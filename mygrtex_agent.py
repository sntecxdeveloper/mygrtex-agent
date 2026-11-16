#!/usr/bin/env python3
"""MygrteX on-premises discovery agent: a Linux VM that you install inside the customer's network. It connects to VMware vCenter, Hyper-V hosts and physical
Linux or Windows servers, reads their configuration, and sends the inventory to MygrteX. Read-only, metadata-only, outbound-only.

Nothing is configured on this VM except where MygrteX is and the agent's token (/etc/mygrtex-agent/config.json and agent.env, written by install.sh). Everything else is
managed in the MygrteX web app and pushed to the agent: which vCenter, Hyper-V hosts and servers to read, their read-only accounts, the approved SSH host keys, the schedule.
The agent asks for its configuration whenever MygrteX says it changed. Passwords are kept in memory only; an SSH key is written to a private temporary directory only while
that target is being read, then deleted.

  mygrtex-agent service      stay running (systemd): check in with MygrteX every minute, apply configuration pushed from the portal, collect when someone presses
                             "Collect now" or on the schedule set there, test targets when asked, then report/upload
  mygrtex-agent status       show whether this VM can reach MygrteX, which configuration revision it has, and the targets it was given (no secrets)
  mygrtex-agent collect --out DIR
                             collect from every target the portal configured and write the inventory files here (nothing leaves this server); review them first

Target types (set up in the portal, Discovery > On-premises agents > the agent > Targets):
  vmware   vCenter 7.0U2+ REST API; the built-in "Read-only" role is enough
  esxi     standalone ESXi hosts (no vCenter) over the vSphere SOAP API on port 443; a local user with the "Read-only" role is enough
  hyperv   Hyper-V hosts over WinRM (needs `pip install pywinrm`); read-only Get-* cmdlets
  windows  physical Windows servers over WinRM; read-only Get-CimInstance queries
  linux    physical Linux servers over SSH with a key; a fixed read-only command set. A host's SSH key is approved in the portal after the agent reports its fingerprint.

The MygrteX token is read from SNTX_AGENT_TOKEN (systemd EnvironmentFile /etc/mygrtex-agent/agent.env, mode 600). Nothing is passed on the command line.

What it guarantees (see README.md): vCenter: GET only (plus its own session login/logout). Hyper-V and Windows: only Get-* cmdlets from an allowlist, each checked before
it runs. Linux: one fixed script of read-only commands. No file contents, no application data, no guest credentials. Outbound HTTPS to the MygrteX URL only.
Connections: from Linux and Windows servers it also reads the list of established TCP connections (addresses, ports, process name; no traffic content) and the listening ports, as dependency
evidence. Turn it off with "policy": {"collect_connections": false}. A snapshot shows only the moment it was taken: collect several times to build a reliable picture.
Utilization: each collection also reads one spot sample of CPU and memory (Linux, Windows, running Hyper-V VMs). MygrteX adds the samples up and uses them to size or retire a VM only once there are
enough (default: 20 samples over 7 days), so collect repeatedly. Turn it off with "policy": {"collect_utilization": false}. VMware needs an imported export (vCenter's REST API has no VM performance history for production use).
Not collected in this version: utilization history, raw device mappings and pass-through devices on VMware, the guest OS of Hyper-V VMs. The platform sizes VMs from
configured CPU and memory and reports what is unknown. Requires Python 3.9+; `pywinrm` only for Hyper-V and Windows targets.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

AGENT_VERSION = "3.1.0"
SCHEMA_VERSION = "2.0"
CONFIG_DIR = Path(os.environ.get("MYGRTEX_AGENT_DIR", "/etc/mygrtex-agent"))
RUN_DIR = Path(os.environ.get("MYGRTEX_AGENT_RUN_DIR", "/run/mygrtex-agent"))      # tmpfs created by systemd (RuntimeDirectory): temporary SSH keys live here, never on disk
SOURCE_OF = {"vmware": "vmware", "esxi": "vmware", "hyperv": "hyperv", "windows": "physical", "linux": "physical"}


def _get(d: Any, *path: str, default: Any = None) -> Any:
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def os_parts(full_name: str, guest_enum: str = "") -> tuple[str, str]:
    """('name', 'version') from the guest's own OS name when it is known, else from vSphere's guest OS identifier."""
    t = (full_name or "").strip()
    if not t and guest_enum:
        g = guest_enum.upper()
        if g.startswith("RHEL_"):
            t = f"Red Hat Enterprise Linux {g.split('_')[1]}"
        elif g.startswith("CENTOS_"):
            t = f"CentOS {g.split('_')[1]}"
        elif g.startswith("ORACLE_LINUX_"):
            t = f"Oracle Linux {g.split('_')[2]}"
        elif g.startswith("UBUNTU"):
            t = "Ubuntu Linux"
        elif g.startswith("DEBIAN_"):
            t = f"Debian {g.split('_')[1]}"
        elif g.startswith("SLES_"):
            t = f"SUSE Linux Enterprise Server {g.split('_')[1]}"
        elif "WIN" in g:
            m = re.search(r"(2003|2008|2012|2016|2019|2022|2025)", g)
            t = f"Microsoft Windows Server {m.group(1)}{' R2' if 'R2' in g else ''}" if m else "Microsoft Windows"
        elif "LINUX" in g:
            t = "Linux"
    t = re.sub(r"\s*\((32|64)-bit\)", "", t).strip()
    if "windows" in t.lower():                                       # "Microsoft Windows Server 2012 R2 Standard": the version is not at the end
        m = re.search(r"\b(2003|2008(?:\s+R2)?|2012(?:\s+R2)?|2016|2019|2022|2025)\b", t)
        return t, (m.group(1) if m else "")
    m = re.search(r"(?:Server\s+)?(\d{4}(?:\s+R2)?|\d+(?:\.\d+)?)\s*$", t)
    return t, (m.group(1) if m else "")


def subnet_of(ip: str, prefix: int | None) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
        if a.version != 4 or a.is_link_local or a.is_loopback or not prefix or prefix >= 32 or prefix < 8:
            return None
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return None


def subnet_resource(cidr: str, location: str) -> dict[str, Any]:
    return {"id": f"cidr:{cidr}", "kind": "subnet", "name": cidr, "location": location, "state": "", "props": {"cidr": cidr}, "relations": []}


# ---------------------------------------------------------------- VMware vSphere (REST, read-only)

def map_vsphere_vm(vm_id: str, summary: dict[str, Any], detail: dict[str, Any], identity: dict[str, Any] | None, tools: dict[str, Any] | None,
                   interfaces: list[dict[str, Any]] | None, location: str = "") -> tuple[list[dict[str, Any]], set[str]]:
    """One vSphere VM to a vm resource plus its disks. Returns (resources, subnet cidrs it sits in)."""
    fn = (identity or {}).get("full_name")
    full = fn.get("default_message", "") if isinstance(fn, dict) else (fn or "")
    name, version = os_parts(str(full or ""), str(detail.get("guest_OS") or ""))
    ips, cidrs = [], set()
    for itf in interfaces or []:
        for a in _get(itf, "ip", "ip_addresses", default=[]) or []:
            ip = a.get("ip_address", "")
            if ip and ":" not in ip and not ip.startswith("169.254."):
                ips.append(ip)
                c = subnet_of(ip, a.get("prefix_length"))
                if c:
                    cidrs.add(c)
    run_state = str((tools or {}).get("run_state") or "").upper()
    props: dict[str, Any] = {"vcpus": _get(detail, "cpu", "count") or summary.get("cpu_count"), "memory_gb": round((_get(detail, "memory", "size_MiB") or summary.get("memory_size_MiB") or 0) / 1024, 2) or None,
                             "os_name": name, "os_version": version, "arch": "x86_64", "firmware": "uefi" if str(_get(detail, "boot", "type", default="")).upper() == "EFI" else "bios" if _get(detail, "boot", "type") else None,
                             "hypervisor_tools": ("running" if run_state == "RUNNING" else "not_running") if tools is not None else None, "ip_addresses": ips or None}
    vm = {"id": vm_id, "kind": "vm", "name": summary.get("name") or vm_id, "location": location, "state": str(summary.get("power_state") or detail.get("power_state") or "").lower().replace("_", ""),
          "props": {k: v for k, v in props.items() if v not in (None, "")}, "relations": [{"type": "in_subnet", "target": f"cidr:{c}"} for c in sorted(cidrs)]}
    out = [vm]
    for key, d in sorted((detail.get("disks") or {}).items()):
        cap = d.get("capacity")
        out.append({"id": f"{vm_id}:disk:{key}", "kind": "disk", "name": f"{vm['name']} {d.get('label') or key}", "location": location, "state": "",
                    "props": {k: v for k, v in {"size_gb": round(cap / 1024**3, 2) if cap else None, "boot": True if str(key) == "2000" or d.get("label", "").endswith(" 1") else None, "attached_to": vm_id,
                                                "tier": _get(d, "backing", "type")}.items() if v is not None}, "relations": [{"type": "attached_to", "target": vm_id}]})
    return out, cidrs


class Vsphere:
    """Read-only vCenter REST client: `fetch(path)` is the only data call (a GET). It is injected so the mapping can be tested without a vCenter."""

    def __init__(self, fetch: Callable[[str], Any]):
        self.fetch = fetch

    def collect(self, include_powered_off: bool = True, progress: Callable[[str], None] = lambda s: None, location: str = "") -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        resources: list[dict[str, Any]] = []
        cidrs: set[str] = set()
        vms = self.fetch("/api/vcenter/vm") or []
        for n, s in enumerate(vms, 1):
            vid = s["vm"]
            if not include_powered_off and str(s.get("power_state")) != "POWERED_ON":
                continue
            progress(f"VM {n}/{len(vms)}")
            detail = self.fetch(f"/api/vcenter/vm/{vid}") or {}
            on = str(s.get("power_state")) == "POWERED_ON"
            identity = tools = interfaces = None
            if on:                                                  # guest details need VMware Tools; absence is data ("not running"), not an error
                try:
                    tools = self.fetch(f"/api/vcenter/vm/{vid}/tools")
                except Exception:
                    tools = None
                if str((tools or {}).get("run_state", "")).upper() == "RUNNING":
                    try:
                        identity = self.fetch(f"/api/vcenter/vm/{vid}/guest/identity")
                        interfaces = self.fetch(f"/api/vcenter/vm/{vid}/guest/networking/interfaces")
                    except Exception:
                        warnings.append(f"{s.get('name')}: guest details unavailable")
            r, c = map_vsphere_vm(vid, s, detail, identity, tools, interfaces, location)
            resources += r
            cidrs |= c
        resources += [subnet_resource(c, location) for c in sorted(cidrs)]
        if not any(r["kind"] == "vm" for r in resources):
            warnings.append("no virtual machines were returned: check the account's permissions")
        warnings.append("utilization history is not collected from vCenter: the platform sizes VMs from their configured CPU and memory")
        warnings.append("subnets are derived from guest IP addresses (VMware Tools must be running); vCenter does not store network address ranges")
        return resources, warnings


def vsphere_fetcher(base: str, user: str, password: str, ca_file: str | None, verify: bool = True) -> tuple[Callable[[str], Any], Callable[[], None]]:
    """(fetch, close). The only non-GET calls are POST /api/session (log in) and DELETE /api/session (log out)."""
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        print("warning: TLS certificate checking is OFF for this vCenter", file=sys.stderr)
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()

    def call(method: str, path: str, headers: dict[str, str]) -> Any:
        req = urllib.request.Request(base.rstrip("/") + path, method=method, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else None

    try:
        sid = call("POST", "/api/session", {"Authorization": f"Basic {basic}"})
    except urllib.error.HTTPError as e:
        raise TargetError("vCenter rejected the account (HTTP %s)" % e.code if e.code in (401, 403) else f"vCenter returned HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise TargetError(f"vCenter is not reachable: {getattr(e, 'reason', e)}")
    hdr = {"vmware-api-session-id": str(sid)}
    return (lambda path: call("GET", path, hdr)), (lambda: call("DELETE", "/api/session", hdr))


class TargetError(Exception):
    """One target failed. The others are still collected; the reason is reported to MygrteX."""


# ---------------------------------------------------------------- Standalone ESXi hosts (vSphere SOAP API at /sdk, read-only)
# A standalone ESXi host has no /api/vcenter REST API: it serves the vSphere Web Services (SOAP) API only. The agent logs in, creates a session-scoped container view of the
# virtual machines, reads their properties and logs out. Nothing is changed on the host. Only the operations in _SOAP_READ_ONLY can be sent (checked before every call).

_SOAP_READ_ONLY = frozenset({"RetrieveServiceContent", "Login", "Logout", "CreateContainerView", "DestroyView", "RetrievePropertiesEx", "ContinueRetrievePropertiesEx"})
_ESXI_PROPS = ["name", "runtime.powerState", "config.hardware.numCPU", "config.hardware.memoryMB", "config.firmware", "config.guestFullName", "config.hardware.device",
               "guest.toolsRunningStatus", "guest.guestFullName", "guest.net"]
_XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"


def _soap_tree(el: Any) -> Any:
    """An XML element as plain data: text for a leaf, else {tag: [children...]} (always lists), with "_type" holding xsi:type."""
    kids = list(el)
    if not kids:
        return el.text or ""
    out: dict[str, Any] = {}
    for k in kids:
        v = _soap_tree(k)
        if isinstance(v, dict) and k.get(_XSI_TYPE):
            v["_type"] = k.get(_XSI_TYPE).split(":")[-1]
        out.setdefault(k.tag.rsplit("}", 1)[-1], []).append(v)
    return out


def _sl(d: Any, tag: str) -> list[Any]:
    return d.get(tag, []) if isinstance(d, dict) else []


def _s1(d: Any, *path: str, default: Any = "") -> Any:
    for p in path:
        k = _sl(d, p)
        if not k:
            return default
        d = k[0]
    return d


def esxi_session(host: str, user: str, password: str, ca_file: str | None, verify: bool = True) -> tuple[Callable[[str, str], Any], Callable[[], None]]:
    """(call, close) for one ESXi host. call(operation, inner_xml) returns the parsed <returnval>; only read-only operations are allowed."""
    import xml.etree.ElementTree as ET
    from xml.sax.saxutils import escape
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        print(f"warning: TLS certificate checking is OFF for ESXi host {host}", file=sys.stderr)
    url = "https://" + (f"[{host}]" if ":" in host else host) + "/sdk"
    state = {"cookie": ""}

    def call(op: str, inner: str) -> Any:
        if op not in _SOAP_READ_ONLY:
            raise ValueError(f"SOAP operation not allowed (read-only operations only): {op}")
        env = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
               f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><{op} xmlns="urn:vim25">{inner}</{op}></soapenv:Body></soapenv:Envelope>')
        headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:vim25/6.7"}
        if state["cookie"]:
            headers["Cookie"] = state["cookie"]
        req = urllib.request.Request(url, data=env.encode(), method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
                raw, cookie = r.read(), r.headers.get("Set-Cookie") or ""
        except urllib.error.HTTPError as e:                                  # a SOAP fault comes as HTTP 500 with the reason in the body
            raw, cookie = e.read(), ""
        except (urllib.error.URLError, OSError) as e:
            raise TargetError(f"ESXi host {host} is not reachable: {getattr(e, 'reason', e)}")
        m = re.search(r"vmware_soap_session=[^;,\s]+", cookie)
        if m:
            state["cookie"] = m.group(0)
        if re.search(rb"<!DOCTYPE|<!ENTITY", raw, re.I):                     # no entity tricks in a response
            raise TargetError(f"ESXi host {host} sent an unexpected response")
        try:
            body = _soap_tree(ET.fromstring(raw))
        except ET.ParseError:
            raise TargetError(f"ESXi host {host} did not return a vSphere API response (is this an ESXi host? port 443)")
        body = _s1(body, "Body", default={})
        fault = _s1(body, "Fault")
        if fault:
            msg = str(_s1(fault, "faultstring"))
            if "InvalidLogin" in raw.decode("utf8", "replace") or "incorrect user name" in msg.lower():
                raise TargetError(f"ESXi host {host} rejected the account")
            raise TargetError(f"ESXi host {host}: {msg or 'request refused'}"[:200])
        return _s1(body, f"{op}Response", "returnval", default="")

    content = call("RetrieveServiceContent", '<_this type="ServiceInstance">ServiceInstance</_this>')
    sm = escape(str(_s1(content, "sessionManager")))
    call("Login", f'<_this type="SessionManager">{sm}</_this><userName>{escape(user)}</userName><password>{escape(password)}</password>')
    call.content = content                                                    # type: ignore[attr-defined]

    def close() -> None:
        try:
            call("Logout", f'<_this type="SessionManager">{sm}</_this>')
        except Exception:
            pass
    return call, close


def _esxi_power(s: str) -> str:
    return {"poweredOn": "POWERED_ON", "poweredOff": "POWERED_OFF", "suspended": "SUSPENDED"}.get(s, s.upper())


def map_esxi_vm(vm_id: str, p: dict[str, Any], location: str = "") -> tuple[list[dict[str, Any]], set[str]]:
    """One ESXi VM (properties by path) to the same shape the vCenter mapping builds, so both sources are assessed identically."""
    power = _esxi_power(str(p.get("runtime.powerState") or ""))
    on = power == "POWERED_ON"
    disks: dict[str, Any] = {}
    for dev in _sl(p.get("config.hardware.device"), "VirtualDevice"):
        if isinstance(dev, dict) and dev.get("_type") == "VirtualDisk":
            cap = _s1(dev, "capacityInBytes") or (int(_s1(dev, "capacityInKB") or 0) * 1024 or "")
            backing = _s1(dev, "backing", default={})
            bt = backing.get("_type", "") if isinstance(backing, dict) else ""
            disks[str(_s1(dev, "key"))] = {"label": str(_s1(dev, "deviceInfo", "label")), "capacity": int(cap) if cap else None,
                                           "backing": {"type": "RAW_DISK" if "RawDisk" in bt else "VMDK_FILE" if bt else None}}
    fw = str(p.get("config.firmware") or "")
    detail: dict[str, Any] = {"cpu": {"count": int(p["config.hardware.numCPU"]) if p.get("config.hardware.numCPU") else None},
                              "memory": {"size_MiB": int(p["config.hardware.memoryMB"]) if p.get("config.hardware.memoryMB") else None},
                              "boot": {"type": "EFI" if fw == "efi" else "BIOS"} if fw else {}, "disks": disks, "guest_OS": ""}
    tools = {"run_state": "RUNNING" if p.get("guest.toolsRunningStatus") == "guestToolsRunning" else "NOT_RUNNING"} if on else None
    full = str(p.get("guest.guestFullName") or p.get("config.guestFullName") or "")
    interfaces = None
    if tools and tools["run_state"] == "RUNNING":
        interfaces = [{"ip": {"ip_addresses": [{"ip_address": str(_s1(a, "ipAddress")), "prefix_length": int(_s1(a, "prefixLength") or 0) or None}
                                               for a in _sl(_s1(nic, "ipConfig", default={}), "ipAddress")]}} for nic in _sl(p.get("guest.net"), "GuestNicInfo")]
    summary = {"name": p.get("name") or vm_id, "power_state": power}
    return map_vsphere_vm(vm_id, summary, detail, {"full_name": full} if full else None, tools, interfaces, location)


def collect_esxi(hosts: list[str], session_for: Callable[[str], tuple[Callable[[str, str], Any], Callable[[], None]]], include_powered_off: bool = True,
                 progress: Callable[[str], None] = lambda s: None) -> tuple[list[dict[str, Any]], list[str]]:
    """Reads every standalone ESXi host. A host that fails is reported and the rest still go; all failing is a target error."""
    from xml.sax.saxutils import escape
    warnings = ["utilization history is not collected from ESXi: the platform sizes VMs from their configured CPU and memory",
                "subnets are derived from guest IP addresses (VMware Tools must be running); an ESXi host does not store network address ranges",
                "standalone ESXi hosts: no cluster, vMotion or HA information, and a VM that moves between hosts is reported once per host that has it registered"]
    res: list[dict[str, Any]] = []
    cidrs: set[str] = set()
    failed: list[str] = []
    for h in hosts:
        try:
            call, close = session_for(h)
        except TargetError as e:
            warnings.append(str(e))
            failed.append(h)
            continue
        try:
            c = getattr(call, "content", None) or {}
            view = call("CreateContainerView", f'<_this type="ViewManager">{escape(str(_s1(c, "viewManager")))}</_this><container type="Folder">{escape(str(_s1(c, "rootFolder")))}</container>'
                                               '<type>VirtualMachine</type><recursive>true</recursive>')
            pc = escape(str(_s1(c, "propertyCollector")))
            spec = ("<specSet><propSet><type>VirtualMachine</type>" + "".join(f"<pathSet>{x}</pathSet>" for x in _ESXI_PROPS) + "</propSet>"
                    f'<objectSet><obj type="ContainerView">{escape(str(view))}</obj><skip>true</skip><selectSet xsi:type="TraversalSpec"><name>traverseView</name>'
                    "<type>ContainerView</type><path>view</path><skip>false</skip></selectSet></objectSet></specSet><options><maxObjects>50</maxObjects></options>")
            page = call("RetrievePropertiesEx", f'<_this type="PropertyCollector">{pc}</_this>{spec}')
            n = 0
            while isinstance(page, dict):
                for o in _sl(page, "objects"):
                    props = {str(_s1(ps, "name")): (_s1(ps, "val", default="")) for ps in _sl(o, "propSet")}
                    n += 1
                    if not include_powered_off and props.get("runtime.powerState") != "poweredOn":
                        continue
                    progress(f"{h}: VM {n}")
                    r, cs = map_esxi_vm(f"{h}/{_s1(o, 'obj')}", props, h)
                    res += r
                    cidrs |= cs
                token = _s1(page, "token")
                page = call("ContinueRetrievePropertiesEx", f'<_this type="PropertyCollector">{pc}</_this><token>{escape(str(token))}</token>') if token else None
            try:
                call("DestroyView", f'<_this type="ContainerView">{escape(str(view))}</_this>')
            except Exception:
                pass
            if n == 0:
                warnings.append(f"{h}: no virtual machines were returned: check the account's permissions")
        except TargetError as e:
            warnings.append(str(e))
            failed.append(h)
        finally:
            close()
    if failed and len(failed) == len(hosts):
        raise TargetError("; ".join(w for w in warnings if w.startswith("ESXi host"))[:300] or "no ESXi host could be read")
    res += [subnet_resource(c, "") for c in sorted(cidrs)]
    return res, warnings


# ---------------------------------------------------------------- Windows over WinRM (Hyper-V and physical): read-only allowlist

_ARG = r"(?:'(?:[^']|'')*'|[A-Za-z0-9_.:\\-]+)"           # a PowerShell single-quoted string (nothing inside is interpreted) or a plain word
_CIM = "Win32_OperatingSystem|Win32_ComputerSystem|Win32_Processor|Win32_DiskDrive|Win32_NetworkAdapterConfiguration|Win32_LogicalDisk|Win32_PerfFormattedData_PerfOS_Processor"
_ALLOWED = re.compile(rf"^(?:Get-(?:VM|VMHardDiskDrive|VHD|VMNetworkAdapter|VMSwitch|ClusterNode|VMHost)(?: -(?:Name|VMName|Path|ComputerName) {_ARG})*"
                      rf"|Get-CimInstance -ClassName (?:{_CIM})|Get-NetTCPConnection -State (?:Established|Listen)) \| ConvertTo-Json -Depth 4 -Compress$")


def check_command(cmd: str) -> str:
    """Refuses anything that is not a single allowlisted Get-* cmdlet piped to ConvertTo-Json."""
    if not _ALLOWED.match(cmd):
        raise ValueError(f"command not allowed (read-only Get-* cmdlets only): {cmd[:80]}")
    return cmd


def winrm_runner(host: str, user: str, password: str, transport: str = "ntlm", https: bool = True, verify: bool = True) -> Callable[[str], Any]:
    """A function that runs one allowlisted command on a Windows host over WinRM and returns the parsed JSON."""
    try:
        import winrm
    except ImportError:
        raise TargetError("Hyper-V and Windows targets need the pywinrm package: pip install pywinrm")
    sess = winrm.Session(f"{'https' if https else 'http'}://{host}:{5986 if https else 5985}/wsman", auth=(user, password), transport=transport, server_cert_validation="validate" if verify else "ignore")

    def ps(cmd: str) -> Any:
        r = sess.run_ps(check_command(cmd))
        if r.status_code != 0:
            raise RuntimeError((r.std_err or b"").decode("utf-8", "replace").strip()[:300] or "PowerShell failed")
        out = (r.std_out or b"").decode("utf-8", "replace").strip()
        return json.loads(out) if out else None
    return ps


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _as_list(x: Any) -> list[Any]:
    return [] if x is None else x if isinstance(x, list) else [x]


def map_hyperv_vm(vm: dict[str, Any], drives: list[dict[str, Any]], vhds: dict[str, dict[str, Any]], nics: list[dict[str, Any]], host: str) -> list[dict[str, Any]]:
    """One Hyper-V VM (as Get-VM returns it) with its virtual disks (Get-VMHardDiskDrive + Get-VHD) and network adapters."""
    vid = str(vm.get("Id") or vm.get("VMId") or vm["Name"])
    state = {2: "poweredon", 3: "poweredoff", 9: "paused", 6: "saved"}.get(vm.get("State"), str(vm.get("State", "")).lower())
    if isinstance(vm.get("State"), str):
        state = {"running": "poweredon", "off": "poweredoff"}.get(vm["State"].lower(), vm["State"].lower())
    mem = vm.get("MemoryAssigned") or vm.get("MemoryStartup") or 0
    ips = [ip for n in nics for ip in _as_list(n.get("IPAddresses")) if ":" not in str(ip)]
    integ = str(vm.get("IntegrationServicesState") or vm.get("Heartbeat") or "")
    out_disks, pass_through = [], False
    for d in drives:
        path = d.get("Path") or ""
        v = vhds.get(path) or {}
        raw = d.get("DiskNumber") is not None and not path           # a pass-through (physical) disk has a disk number and no VHD path
        pass_through = pass_through or raw
        size = v.get("Size")
        out_disks.append({"id": f"{vid}:disk:{path or d.get('DiskNumber')}", "kind": "disk", "name": (path.rsplit("\\", 1)[-1] if path else f"physical disk {d.get('DiskNumber')}"), "location": host, "state": "",
                          "props": {k: x for k, x in {"size_gb": round(size / 1024**3, 2) if size else None, "boot": True if d.get("ControllerNumber") == 0 and d.get("ControllerLocation") == 0 else None, "attached_to": vid,
                                                      "tier": v.get("VhdType") if isinstance(v.get("VhdType"), str) else None, "thin_provisioned": True if str(v.get("VhdType")) in ("Dynamic", "3") else None,
                                                      "raw_device_mapping": True if raw else None, "shared": True if d.get("SupportPersistentReservations") else None}.items() if x is not None},
                          "relations": [{"type": "attached_to", "target": vid}]})
    vmres = {"id": vid, "kind": "vm", "name": vm["Name"], "location": host, "state": state,
             "props": {k: x for k, x in {"vcpus": vm.get("ProcessorCount"), "memory_gb": round(mem / 1024**3, 2) or None, "generation": vm.get("Generation"), "firmware": "uefi" if vm.get("Generation") == 2 else "bios" if vm.get("Generation") == 1 else None,
                                         "arch": "x86_64", "hypervisor_tools": ("running" if integ.upper() in ("UPTODATE", "OK", "OKAPPLICATIONSHEALTHY", "2") else "not_running") if integ else None, "ip_addresses": ips or None,
                                         "host": host, "cluster": host if vm.get("IsClustered") else None, "passthrough_devices": ["physical disk"] if pass_through else None}.items() if x not in (None, "")},
             "relations": []}
    if (smp := hyperv_sample(vm)):
        vmres["utilization"] = {"sample": smp}
    return [vmres, *out_disks]


def collect_hyperv(hosts: list[str], runner_for: Callable[[str], Callable[[str], Any]], include_powered_off: bool = True, progress: Callable[[str], None] = lambda s: None) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = ["utilization history is not collected from Hyper-V: the platform sizes VMs from their configured CPU and memory",
                           "the guest operating system of Hyper-V VMs is not read (it needs guest credentials): it is reported as not collected"]
    res: list[dict[str, Any]] = []
    for h in hosts:
        ps = runner_for(h)
        for n, vm in enumerate(_as_list(ps("Get-VM | ConvertTo-Json -Depth 4 -Compress")), 1):
            if not include_powered_off and vm.get("State") not in (2, "Running"):
                continue
            progress(f"{h}: VM {n}")
            try:
                drives = _as_list(ps(f"Get-VMHardDiskDrive -VMName {_q(vm['Name'])} | ConvertTo-Json -Depth 4 -Compress"))
                vhds = {}
                for d in drives:
                    p = d.get("Path")
                    if p:
                        try:
                            vhds[p] = ps(f"Get-VHD -Path {_q(p)} | ConvertTo-Json -Depth 4 -Compress") or {}
                        except Exception:
                            warnings.append(f"{vm['Name']}: could not read {p.rsplit(chr(92), 1)[-1]}")
                nics = _as_list(ps(f"Get-VMNetworkAdapter -VMName {_q(vm['Name'])} | ConvertTo-Json -Depth 4 -Compress"))
                res += map_hyperv_vm(vm, drives, vhds, nics, h)
            except Exception as e:
                warnings.append(f"{vm.get('Name')}: skipped ({str(e)[:120]})")
    return res, warnings


# ---------------------------------------------------------------- physical servers: Windows (CIM over WinRM) and Linux (SSH)

def map_windows_server(host: str, osr: dict[str, Any], cs: dict[str, Any], cpus: list[dict[str, Any]], disks: list[dict[str, Any]], nics: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    warnings = []
    caption = str(osr.get("Caption") or "")
    name, version = os_parts(caption)
    ips, cidrs = [], set()
    for n in nics:
        if n.get("IPEnabled"):
            addrs, masks = _as_list(n.get("IPAddress")), _as_list(n.get("IPSubnet"))
            for a, m in zip(addrs, masks):
                if ":" in str(a) or str(a).startswith("169.254."):
                    continue
                ips.append(a)
                try:
                    c = subnet_of(a, ipaddress.ip_network(f"0.0.0.0/{m}").prefixlen) if "." in str(m) else subnet_of(a, int(m))
                except ValueError:
                    c = None
                if c:
                    cidrs.add(c)
    virtual = bool(cs.get("HypervisorPresent"))
    if virtual:
        warnings.append(f"{host} reports that it is a virtual machine ({cs.get('Manufacturer')} {cs.get('Model')}): discover it through its hypervisor instead")
    vid = f"windows:{host}"
    srv = {"id": vid, "kind": "vm", "name": cs.get("DNSHostName") or cs.get("Name") or host, "location": host, "state": "poweredon",
           "props": {k: v for k, v in {"vcpus": sum(int(c.get("NumberOfLogicalProcessors") or 0) for c in cpus) or None, "memory_gb": round((cs.get("TotalPhysicalMemory") or 0) / 1024**3, 2) or None,
                                       "os_name": name, "os_version": version, "arch": "x86_64", "physical": None if virtual else True, "manufacturer": cs.get("Manufacturer"), "model": cs.get("Model"),
                                       "cpu_model": (cpus[0].get("Name") or "").strip() if cpus else None, "ip_addresses": ips or None}.items() if v not in (None, "")},
           "relations": [{"type": "in_subnet", "target": f"cidr:{c}"} for c in sorted(cidrs)]}
    out = [srv]
    for d in sorted(disks, key=lambda x: x.get("Index", 0)):
        size = d.get("Size")
        out.append({"id": f"{vid}:disk:{d.get('Index')}", "kind": "disk", "name": f"{srv['name']} disk {d.get('Index')} ({(d.get('Model') or '').strip()})", "location": host, "state": "",
                    "props": {k: v for k, v in {"size_gb": round(size / 1024**3, 2) if size else None, "boot": True if d.get("Index") == 0 else None, "attached_to": vid, "tier": d.get("MediaType") if isinstance(d.get("MediaType"), str) else None}.items() if v is not None},
                    "relations": [{"type": "attached_to", "target": vid}]})
    out += [subnet_resource(c, host) for c in sorted(cidrs)]
    return out, warnings


def collect_windows(hosts: list[str], runner_for: Callable[[str], Callable[[str], Any]], progress: Callable[[str], None] = lambda s: None, conns: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    res: list[dict[str, Any]] = []
    warnings = ["utilization history is not collected from physical servers: the platform sizes them from their CPU and memory",
                "the boot disk is assumed to be disk 0"]
    for h in hosts:
        progress(f"{h}")
        try:
            ps = runner_for(h)
            one = lambda c: (_as_list(ps(f"Get-CimInstance -ClassName {c} | ConvertTo-Json -Depth 4 -Compress")) or [{}])  # noqa: E731
            r, w = map_windows_server(h, one("Win32_OperatingSystem")[0], one("Win32_ComputerSystem")[0], one("Win32_Processor"), one("Win32_DiskDrive"), one("Win32_NetworkAdapterConfiguration"))
            try:
                osr = one("Win32_OperatingSystem")[0]
                if (smp := windows_sample(osr, _as_list(ps("Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor | ConvertTo-Json -Depth 4 -Compress")))) and r and r[0]["kind"] == "vm":
                    r[0]["utilization"] = {"sample": smp}
            except Exception as e:                                           # the sample is optional: whatever goes wrong with it must not cost the inventory
                warnings.append(f"{h}: utilization sample not collected ({type(e).__name__}: {str(e)[:100]})")
            res += r
            warnings += w
            if conns is not None:
                try:
                    lp, cs = windows_connections(_as_list(ps("Get-NetTCPConnection -State Listen | ConvertTo-Json -Depth 4 -Compress")), _as_list(ps("Get-NetTCPConnection -State Established | ConvertTo-Json -Depth 4 -Compress")))
                    conns += cs
                    if lp and r and r[0]["kind"] == "vm":
                        r[0]["props"]["listening_ports"] = lp
                except (RuntimeError, ValueError) as e:
                    warnings.append(f"{h}: connections not collected ({str(e)[:120]})")
        except (TargetError, RuntimeError, ValueError) as e:
            warnings.append(f"{h}: skipped ({str(e)[:160]})")
    return res, warnings


LINUX_SCRIPT = r"""set -u
echo '###os'; cat /etc/os-release 2>/dev/null
echo '###arch'; uname -m
echo '###cpu'; nproc 2>/dev/null; grep -m1 'model name' /proc/cpuinfo 2>/dev/null
echo '###mem'; grep -m1 '^MemTotal' /proc/meminfo
echo '###disks'; lsblk -b -J -o NAME,TYPE,SIZE,ROTA,MOUNTPOINT,MODEL 2>/dev/null
echo '###net'; ip -j addr 2>/dev/null
echo '###dmi'; cat /sys/class/dmi/id/sys_vendor 2>/dev/null; cat /sys/class/dmi/id/product_name 2>/dev/null
echo '###fw'; if [ -d /sys/firmware/efi ]; then echo uefi; else echo bios; fi
echo '###virt'; systemd-detect-virt 2>/dev/null || echo none
echo '###host'; hostname
echo '###util'; head -n1 /proc/stat; sleep 5; head -n1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo
echo '###listen'; ss -H -ltn 2>/dev/null
echo '###conn'; ss -H -tnp state established 2>/dev/null
"""


def parse_sections(text: str) -> dict[str, str]:
    out: dict[str, list[str]] = {}
    cur = ""
    for line in text.splitlines():
        m = re.match(r"^###(\w+)$", line)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


# ---------------------------------------------------------------- spot utilization samples: one reading per collection; MygrteX adds them up over collections and uses them only once there are enough

def _pct(v: float) -> float:
    return round(max(0.0, min(100.0, v)), 1)


def linux_sample(sections: dict[str, str]) -> dict[str, float] | None:
    """CPU busy % over the 5 seconds between two /proc/stat readings, and memory used % from MemAvailable. None when it cannot be read."""
    out: dict[str, float] = {}
    lines = [ln.split() for ln in sections.get("util", "").splitlines() if ln.startswith("cpu ")]
    if len(lines) >= 2:
        try:
            a, b = [[int(x) for x in ln[1:9]] for ln in lines[:2]]
            total, idle = sum(b) - sum(a), (b[3] + b[4]) - (a[3] + a[4])
            if total > 0:
                out["cpu_pct"] = _pct(100.0 * (1 - idle / total))
        except (ValueError, IndexError):
            pass
    mem = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", sections.get("util", ""), re.M))
    if mem.get("MemTotal") and mem.get("MemAvailable") and int(mem["MemTotal"]) > 0:
        out["mem_pct"] = _pct(100.0 * (1 - int(mem["MemAvailable"]) / int(mem["MemTotal"])))
    return out or None


def windows_sample(osr: dict[str, Any], perf: list[dict[str, Any]]) -> dict[str, float] | None:
    """CPU % from the _Total row of the processor performance counters, memory % from the operating system's free and total memory."""
    out: dict[str, float] = {}
    tot = next((r for r in perf if str(r.get("Name")) == "_Total"), None)
    if tot is not None and str(tot.get("PercentProcessorTime", "")).replace(".", "", 1).isdigit():
        out["cpu_pct"] = _pct(float(tot["PercentProcessorTime"]))
    try:
        t, f = float(osr.get("TotalVisibleMemorySize") or 0), float(osr.get("FreePhysicalMemory") or 0)
        if t > 0:
            out["mem_pct"] = _pct(100.0 * (1 - f / t))
    except (TypeError, ValueError):
        pass
    return out or None


def hyperv_sample(vm: dict[str, Any]) -> dict[str, float] | None:
    """What Get-VM reports about a running VM right now: CPUUsage (% of its vCPUs) and MemoryDemand against MemoryAssigned (dynamic memory)."""
    st = vm.get("State")
    if not (st == 2 or str(st).lower() == "running"):
        return None
    out: dict[str, float] = {}
    if isinstance(vm.get("CPUUsage"), (int, float)):
        out["cpu_pct"] = _pct(float(vm["CPUUsage"]))
    d, a = vm.get("MemoryDemand"), vm.get("MemoryAssigned")
    if isinstance(d, (int, float)) and isinstance(a, (int, float)) and a > 0 and d > 0:
        out["mem_pct"] = _pct(100.0 * d / a)
    return out or None


# ---------------------------------------------------------------- observed connections (dependency evidence): endpoints only, never payload

MAX_CONNECTIONS_PER_HOST = 5000


def _endpoint(s: str) -> tuple[str, int] | None:
    """'10.0.1.10:43210', '[::ffff:10.0.1.10]:43210' or '*:80' -> (ip, port); IPv4 only."""
    ip, _, port = s.strip().rpartition(":")
    ip = ip.strip("[]").split("%")[0]
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return (str(a), int(port)) if a.version == 4 and port.isdigit() else None


def _aggregate(rows: list[tuple[str, str, int, str]]) -> list[dict[str, Any]]:
    agg: dict[tuple[str, str, int], dict[str, Any]] = {}
    for src, dst, port, proc in rows:
        a = agg.setdefault((src, dst, port), {"src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": "tcp", "process": "", "count": 0})
        a["count"] += 1
        a["process"] = a["process"] or proc
    return sorted(agg.values(), key=lambda c: -c["count"])[:MAX_CONNECTIONS_PER_HOST]


def linux_listening(text: str) -> set[int]:
    """Ports this server listens on, from `ss -tln` lines (IPv4, IPv6 and wildcard listeners all count)."""
    ports = set()
    for line in text.splitlines():
        c = line.split()
        if len(c) >= 5 and c[0].upper() == "LISTEN":
            c = c[1:]
        if len(c) >= 4:
            port = c[2].rpartition(":")[2]
            if port.isdigit():
                ports.add(int(port))
    return ports


def linux_connections(sections: dict[str, str]) -> tuple[list[int], list[dict[str, Any]]]:
    """(listening ports, outbound connections) from the `ss` sections. A connection whose local port is one this server listens on is inbound (someone else is the client) and is left to that client's own snapshot."""
    listening = linux_listening(sections.get("listen", ""))
    rows: list[tuple[str, str, int, str]] = []
    for line in sections.get("conn", "").splitlines():
        c = line.split()
        if c and c[0].upper() == "ESTAB":
            c = c[1:]
        if len(c) < 4:
            continue
        loc, peer = _endpoint(c[2]), _endpoint(c[3])
        if not loc or not peer or loc[1] in listening or peer[0].startswith("127."):
            continue
        m = re.search(r'users:\(\("([^"]{1,80})"', line)
        rows.append((loc[0], peer[0], peer[1], m.group(1) if m else ""))
    return sorted(listening)[:200], _aggregate(rows)


def windows_connections(listen: list[dict[str, Any]], est: list[dict[str, Any]]) -> tuple[list[int], list[dict[str, Any]]]:
    """Same, from Get-NetTCPConnection rows (LocalAddress, LocalPort, RemoteAddress, RemotePort)."""
    listening = {int(r["LocalPort"]) for r in listen if str(r.get("LocalPort", "")).isdigit()}
    rows = []
    for r in est:
        loc, peer = _endpoint(f"{r.get('LocalAddress', '')}:{r.get('LocalPort', '')}"), _endpoint(f"{r.get('RemoteAddress', '')}:{r.get('RemotePort', '')}")
        if loc and peer and loc[1] not in listening and not peer[0].startswith("127."):
            rows.append((loc[0], peer[0], peer[1], ""))
    return sorted(listening)[:200], _aggregate(rows)


def map_linux_server(host: str, text: str) -> tuple[list[dict[str, Any]], list[str]]:
    s = parse_sections(text)
    warnings: list[str] = []
    osr = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', s.get("os", ""), re.M))
    name = osr.get("PRETTY_NAME") or osr.get("NAME") or ""
    ver = osr.get("VERSION_ID", "").split(".")[0] if osr.get("ID") not in ("ubuntu",) else osr.get("VERSION_ID", "")
    if osr.get("NAME") and osr.get("VERSION_ID"):
        name = f"{osr['NAME']} {osr['VERSION_ID']}"
    cpu = s.get("cpu", "").splitlines()
    vcpus = int(cpu[0]) if cpu and cpu[0].strip().isdigit() else None
    mem = re.search(r"MemTotal:\s+(\d+)\s*kB", s.get("mem", ""))
    dmi = s.get("dmi", "").splitlines()
    virt = (s.get("virt", "none").splitlines() or ["none"])[0].strip()
    physical = virt in ("none", "")
    if not physical:
        warnings.append(f"{host} reports that it is a virtual machine ({virt}): discover it through its hypervisor instead")
    ips, cidrs = [], set()
    try:
        for itf in json.loads(s.get("net") or "[]"):
            if itf.get("ifname") == "lo":
                continue
            for a in itf.get("addr_info", []):
                if a.get("family") == "inet":
                    ips.append(a["local"])
                    c = subnet_of(a["local"], a.get("prefixlen"))
                    if c:
                        cidrs.add(c)
    except ValueError:
        warnings.append(f"{host}: network information could not be read")
    vid = f"linux:{host}"
    arch = s.get("arch", "").strip()
    srv = {"id": vid, "kind": "vm", "name": (s.get("host") or host).strip() or host, "location": host, "state": "poweredon",
           "props": {k: v for k, v in {"vcpus": vcpus, "memory_gb": round(int(mem.group(1)) / 1024**2, 2) if mem else None, "os_name": name, "os_version": ver, "arch": "arm64" if arch in ("aarch64", "arm64") else "x86_64" if arch in ("x86_64", "amd64") else arch,
                                       "firmware": s.get("fw", "").strip() or None, "physical": True if physical else None, "manufacturer": dmi[0].strip() if dmi else None, "model": dmi[1].strip() if len(dmi) > 1 else None,
                                       "cpu_model": (cpu[1].split(":", 1)[1].strip() if len(cpu) > 1 and ":" in cpu[1] else None), "ip_addresses": ips or None,
                                       "listening_ports": linux_connections(s)[0] or None}.items() if v not in (None, "")},
           "relations": [{"type": "in_subnet", "target": f"cidr:{c}"} for c in sorted(cidrs)]}
    if (smp := linux_sample(s)):
        srv["utilization"] = {"sample": smp}
    out = [srv]
    try:
        for d in json.loads(s.get("disks") or "{}").get("blockdevices", []):
            if d.get("type") != "disk" or str(d.get("name", "")).startswith(("loop", "ram", "zram")):
                continue
            mounts = {c.get("mountpoint") for c in _flatten(d)}
            out.append({"id": f"{vid}:disk:{d['name']}", "kind": "disk", "name": f"{srv['name']} {d['name']}", "location": host, "state": "",
                        "props": {k: v for k, v in {"size_gb": round(int(d["size"]) / 1024**3, 2) if d.get("size") else None, "boot": True if mounts & {"/", "/boot", "/boot/efi"} else None, "attached_to": vid,
                                                    "tier": "HDD" if d.get("rota") in (True, "1", 1) else "SSD"}.items() if v is not None},
                        "relations": [{"type": "attached_to", "target": vid}]})
    except (ValueError, KeyError):
        warnings.append(f"{host}: disk information could not be read (lsblk missing?)")
    out += [subnet_resource(c, host) for c in sorted(cidrs)]
    return out, warnings


def _flatten(d: dict[str, Any]) -> list[dict[str, Any]]:
    out = [d]
    for c in d.get("children", []) or []:
        out += _flatten(c)
    return out


def ssh_runner(user: str, key_file: str, port: int, known_hosts: str) -> Callable[[str], str]:
    """Runs the fixed LINUX_SCRIPT on a host over SSH with a key. The host key must already be approved in MygrteX (it arrives in `known_hosts`)."""

    def run(host: str) -> str:
        cmd = ["ssh", "-i", key_file, "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}", "-o", "ConnectTimeout=15", f"{user}@{host}", "sh", "-s"]
        r = subprocess.run(cmd, input=LINUX_SCRIPT, capture_output=True, text=True, timeout=120)
        if r.returncode != 0 and not r.stdout:
            raise TargetError(f"ssh to {host} failed: {r.stderr.strip()[:200]}")
        return r.stdout
    return run


@contextlib.contextmanager
def ssh_material(t: dict[str, Any]) -> Any:
    """The target's private key and approved host keys as files in a private (mode 700) temporary directory, only while that target is being read."""
    if not t.get("key_value"):
        raise TargetError(f"target {t.get('name')}: MygrteX did not send an SSH key")
    d = Path(tempfile.mkdtemp(prefix="ssh-", dir=str(RUN_DIR) if RUN_DIR.is_dir() else None))
    try:
        key = d / "key"
        with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(t["key_value"].rstrip("\n") + "\n")
        kh = d / "known_hosts"
        kh.write_text(t.get("known_hosts", ""))
        kh.chmod(0o600)
        yield str(key), str(kh)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def approved_hosts(known_hosts: str) -> set[str]:
    """Host names that already have an approved key in a known_hosts text ('host', 'host,ip' and '[host]:port' forms)."""
    out: set[str] = set()
    for line in known_hosts.splitlines():
        if line.strip() and not line.startswith("#"):
            for h in line.split()[0].split(","):
                out.add(re.sub(r"^\[(.+)\]:\d+$", r"\1", h))
    return out


def scan_host_keys(host: str, port: int = 22) -> list[dict[str, str]]:
    """The SSH host keys a server offers, with fingerprints, so a person can approve them in MygrteX. Nothing is trusted here."""
    out = subprocess.run(["ssh-keyscan", "-p", str(port), "-t", "ed25519,ecdsa,rsa", host], capture_output=True, text=True, timeout=30).stdout
    keys: list[dict[str, str]] = []
    for line in out.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fp = subprocess.run(["ssh-keygen", "-lf", "-"], input=line + "\n", capture_output=True, text=True).stdout.split()
        keys.append({"line": line.strip(), "type": line.split()[1] if len(line.split()) > 1 else "", "fingerprint": fp[1] if len(fp) > 1 else ""})
    return keys


def collect_linux(hosts: list[str], run: Callable[[str], str], progress: Callable[[str], None] = lambda s: None, conns: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    res: list[dict[str, Any]] = []
    warnings = ["utilization history is not collected from physical servers: the platform sizes them from their CPU and memory"]
    for h in hosts:
        progress(h)
        try:
            text = run(h)
            r, w = map_linux_server(h, text)
            res += r
            warnings += w
            if conns is not None:
                conns += linux_connections(parse_sections(text))[1]
        except (TargetError, subprocess.SubprocessError, OSError) as e:
            warnings.append(f"{h}: skipped ({str(e)[:160]})")
    return res, warnings


# ---------------------------------------------------------------- configuration, targets and the documents

def load_config(path: Path | None = None) -> dict[str, Any]:
    """The only local settings: where MygrteX is (and an optional CA file for a private certificate authority). Everything else comes from MygrteX."""
    p = path or CONFIG_DIR / "config.json"
    try:
        c = json.loads(p.read_text())
    except FileNotFoundError:
        return {"server": "", "ca_file": ""}
    except ValueError as e:
        sys.exit(f"{p} is not valid JSON: {e}")
    return {"server": c.get("server", ""), "ca_file": c.get("ca_file", "")}


def secret(t: dict[str, Any], key: str) -> str:
    """A target's secret as pushed from MygrteX (held in memory; never written to disk, never logged, never sent back)."""
    v = t.get(f"{key}_value")
    if not v:
        raise TargetError(f"target {t.get('name')}: MygrteX did not send a {key}")
    return str(v)


def collect_target(t: dict[str, Any], policy: dict[str, Any], progress: Callable[[str], None] = lambda s: None, conns: list[dict[str, Any]] | None = None) -> tuple[str, list[dict[str, Any]], list[str]]:
    """(source, resources, warnings) for one target. Raises TargetError when the target as a whole cannot be read."""
    typ, inc = t.get("type"), bool(policy.get("include_powered_off", True))
    if typ not in SOURCE_OF:
        raise TargetError(f"unknown target type '{typ}'")
    if typ == "vmware":
        base = t.get("url", "")
        if not base.startswith("https://"):
            raise TargetError("vmware target needs an https:// url")
        fetch, close = vsphere_fetcher(base, t["user"], secret(t, "password"), t.get("ca_file") or None, bool(t.get("verify_tls", True)))
        try:
            res, w = Vsphere(fetch).collect(inc, progress, location=re.sub(r"^https?://", "", base).split("/")[0])
        finally:
            try:
                close()
            except Exception:
                pass
        return "vmware", res, w
    hosts = [h.strip() for h in t.get("hosts", []) if h.strip()]
    if not hosts:
        raise TargetError(f"target {t.get('name')}: no hosts")
    if typ == "esxi":
        pw = secret(t, "password")
        res, w = collect_esxi(hosts, lambda h: esxi_session(h, t["user"], pw, t.get("ca_file") or None, bool(t.get("verify_tls", True))), inc, progress)
        return "vmware", res, w
    if typ in ("hyperv", "windows"):
        pw = secret(t, "password")
        runner = lambda h: winrm_runner(h, t["user"], pw, t.get("transport", "ntlm"), bool(t.get("https", True)), bool(t.get("verify_tls", True)))  # noqa: E731
        res, w = collect_hyperv(hosts, runner, inc, progress) if typ == "hyperv" else collect_windows(hosts, runner, progress, conns)
        return SOURCE_OF[typ], res, w
    with ssh_material(t) as (key_file, known_hosts):
        res, w = collect_linux(hosts, ssh_runner(t["user"], key_file, int(t.get("port", 22)), known_hosts), progress, conns)
    return "physical", res, w


def collect_all(cfg: dict[str, Any], policy: dict[str, Any], progress: Callable[[str], None] = lambda s: None, only: str | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """One inventory document per source (vmware, hyperv, physical), merged across targets. A failing target is reported, the rest still go."""
    by: dict[str, tuple[list[dict[str, Any]], list[str]]] = {}
    conns_by: dict[str, list[dict[str, Any]]] = {}
    errors: list[str] = []
    for t in cfg.get("targets", []):
        if only and t.get("name") != only:
            continue
        try:
            bucket: list[dict[str, Any]] = []
            src, res, w = collect_target(t, policy, lambda s, n=t.get("name"): progress(f"{n}: {s}"), bucket if policy.get("collect_connections", True) else None)
            conns_by.setdefault(src, []).extend(bucket)
            r, ws = by.setdefault(src, ([], []))
            r += res
            ws += [f"[{t.get('name')}] {x}" for x in w]
        except TargetError as e:
            errors.append(f"[{t.get('name')}] {e}")
        except (KeyError, ValueError) as e:
            errors.append(f"[{t.get('name')}] bad target settings ({type(e).__name__}: {e})")
    if policy.get("collect_utilization", True) is False:
        for r, _ in by.values():
            for x in r:
                (x.get("utilization") or {}).pop("sample", None)
    docs = [build_document(src, r, w + errors, {"targets": [t.get("name") for t in cfg.get("targets", []) if SOURCE_OF.get(t.get("type")) == src]}, conns_by.get(src)) for src, (r, w) in by.items()]
    return docs, errors


def test_target(t: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """A dry run of one target: can it be read, and how much? Nothing is uploaded. A physical Linux host whose SSH key has not been approved in MygrteX is not
    contacted for data: its key fingerprints are reported so a person can approve them in the portal."""
    r: dict[str, Any] = {"target_id": t.get("id"), "name": t.get("name"), "ok": False, "message": "", "resources": 0, "host_keys": {}}
    try:
        if t.get("type") == "linux":
            known, port = approved_hosts(t.get("known_hosts", "")), int(t.get("port", 22))
            pending = [h.strip() for h in t.get("hosts", []) if h.strip() and h.strip() not in known]
            for h in pending:
                r["host_keys"][h] = scan_host_keys(h, port)
            if pending:
                r["message"] = "Approve the SSH host key of " + ", ".join(pending) + " in MygrteX (check the fingerprint against the server first)."
                return r
        _src, resources, warnings = collect_target(t, policy)
        r["resources"] = len(resources)
        r["ok"] = bool(resources)
        r["message"] = f"{len(resources)} resource(s) can be read" if resources else ("Nothing could be read: " + "; ".join(warnings)[:250] if warnings else "Nothing was found.")
    except TargetError as e:
        r["message"] = str(e)[:300]
    except (KeyError, ValueError) as e:
        r["message"] = f"bad target settings ({type(e).__name__}: {e})"[:300]
    except Exception as e:  # noqa: BLE001  one failing target must not stop the others
        r["message"] = f"unexpected error: {type(e).__name__}"
    return r


def build_document(source: str, resources: list[dict[str, Any]], warnings: list[str], scope: dict[str, Any], connections: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    seen, out = set(), []
    for r in resources:
        if r["id"] not in seen:
            seen.add(r["id"])
            out.append({**r, "relations": [x for x in r.get("relations", []) if x.get("target")]})
    return {"schema_version": SCHEMA_VERSION, "source": source, "collected_at": datetime.now(timezone.utc).isoformat(), "agent": {"name": "mygrtex-agent", "version": AGENT_VERSION, "host": socket.gethostname()},
            "scope": {**scope, "utilization_days": 0}, "resources": out, "warnings": warnings[:200], **({"connections": connections[:100000]} if connections else {})}


# ---------------------------------------------------------------- talking to MygrteX (outbound HTTPS only)

def _http(method: str, url: str, body: bytes | None, ca_file: str | None, extra: dict[str, str] | None = None) -> Any:
    token = os.environ.get("SNTX_AGENT_TOKEN", "")
    if not token:
        sys.exit("SNTX_AGENT_TOKEN is not set (see /etc/mygrtex-agent/agent.env)")
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        sys.exit("The MygrteX URL must use https://")
    req = urllib.request.Request(url, data=body, method=method, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": f"mygrtex-agent/{AGENT_VERSION}", **(extra or {})})
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=300) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"MygrteX returned HTTP {e.code}: {e.read()[:300].decode('utf-8', 'replace')}")
    except (urllib.error.URLError, OSError) as e:
        raise ConnectionError(str(getattr(e, 'reason', e)))


def upload_all(api: str, docs: list[dict[str, Any]], ca: str | None, job_id: str | None) -> None:
    for i, d in enumerate(docs):
        last = i == len(docs) - 1
        _http("POST", api + "/agent/ingest", json.dumps(d).encode(), ca, {"X-Job-Id": job_id} if job_id and last else None)


def upload_all(api: str, docs: list[dict[str, Any]], ca: str | None, job_id: str | None) -> None:
    for i, d in enumerate(docs):
        last = i == len(docs) - 1
        _http("POST", api + "/agent/ingest", json.dumps(d).encode(), ca, {"X-Job-Id": job_id} if job_id and last else None)


def fetch_config(api: str, ca: str | None) -> dict[str, Any]:
    c = _http("GET", api + "/agent/config", None, ca)
    return {"rev": int(c.get("rev", 0)), "policy": c.get("policy", {}), "targets": list(c.get("targets", []))}


def service_once(api: str, ca: str | None, st: dict[str, Any], say: Callable[[str], None]) -> None:
    """One check-in. `st` holds what this agent knows: the configuration revision, the targets (in memory only) and the schedule."""
    hb = _http("POST", api + "/agent/heartbeat", json.dumps({"version": AGENT_VERSION, "host": socket.gethostname(), "config_rev": st["rev"] or 0}).encode(), ca)
    policy, job = hb["policy"], hb.get("job")
    if hb.get("config_rev") != st["rev"]:                          # the portal changed this agent's targets or settings: pull them
        c = fetch_config(api, ca)
        st["tcfg"], policy, st["rev"] = {"targets": c["targets"]}, c["policy"], c["rev"]
        say(f"{datetime.now():%H:%M:%S} configuration revision {st['rev']} received from MygrteX: {len(c['targets'])} target(s)")
    st["policy"] = policy
    due = bool(policy.get("interval_hours")) and time.time() - st["last"] >= policy["interval_hours"] * 3600
    if job and job.get("action") == "test":
        wanted = job.get("target_id")
        results = [test_target(t, policy) for t in st["tcfg"]["targets"] if not wanted or t.get("id") == wanted]
        _http("POST", f"{api}/agent/jobs/{job['id']}/test-result", json.dumps({"results": results}).encode(), ca)
        say(f"{datetime.now():%H:%M:%S} tested {len(results)} target(s)")
    elif job or due:
        docs, errors = collect_all(st["tcfg"], policy, say)
        if docs:
            upload_all(api, docs, ca, job["id"] if job else None)
            st["last"] = time.time()
            print(f"{datetime.now():%H:%M:%S} uploaded {len(docs)} document(s)" + (f", {len(errors)} target(s) failed" if errors else ""), flush=True)
        elif job:
            _http("POST", f"{api}/agent/jobs/{job['id']}/fail", json.dumps({"error": "; ".join(errors)[:900] or "no targets are configured: add them in MygrteX"}).encode(), ca)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="service", choices=["service", "status", "collect"])
    ap.add_argument("--config", help="path to config.json (default /etc/mygrtex-agent/config.json)")
    ap.add_argument("--out", help="collect: directory for the inventory files")
    ap.add_argument("--interval", type=int, default=60, help="service: seconds between check-ins")
    a = ap.parse_args(argv)
    cfg = load_config(Path(a.config) if a.config else None)
    if not cfg["server"]:
        sys.exit("No MygrteX URL is configured: /etc/mygrtex-agent/config.json should contain {\"server\": \"https://...\"} (install.sh writes it)")
    api, ca = cfg["server"].rstrip("/") + "/api/v1", cfg.get("ca_file") or None
    say = lambda s: print(s, file=sys.stderr)  # noqa: E731
    if a.command == "status":
        hb = _http("POST", api + "/agent/heartbeat", json.dumps({"version": AGENT_VERSION, "host": socket.gethostname(), "config_rev": -1}).encode(), ca)
        c = fetch_config(api, ca)
        print(f"MygrteX: {cfg['server']} (reachable, token accepted)\nAgent version: {AGENT_VERSION}\nConfiguration revision in MygrteX: {c['rev']}\nTargets from the portal: {len(c['targets'])}")
        for t in c["targets"]:
            print(f"  {t.get('name'):24} {t.get('type'):8} {t.get('url') or ','.join(t.get('hosts', []))}")
        if hb.get("job"):
            print("A request is waiting for this agent (the service will pick it up).")
        return
    if a.command == "collect":
        c = fetch_config(api, ca)
        docs, errors = collect_all({"targets": c["targets"]}, c["policy"], say)
        for e in errors:
            say("FAILED: " + e)
        if a.out:
            Path(a.out).mkdir(parents=True, exist_ok=True)
            for d in docs:
                (Path(a.out) / f"inventory-{d['source']}.json").write_text(json.dumps(d, indent=1))
            print(f"wrote {len(docs)} file(s) to {a.out}: this is exactly what the service would upload; nothing was sent")
        else:
            for d in docs:
                print(f"{d['source']}: {len(d['resources'])} resources")
        sys.exit(1 if errors and not docs else 0)
    st: dict[str, Any] = {"rev": None, "tcfg": {"targets": []}, "policy": {}, "last": 0.0}
    while True:                                                    # outbound-only loop: MygrteX never connects in
        try:
            service_once(api, ca, st, say)
        except ConnectionError as e:
            say(f"MygrteX not reachable, will retry: {e}")
        except RuntimeError as e:
            say(str(e))
        time.sleep(max(15, a.interval))


if __name__ == "__main__":
    main()
