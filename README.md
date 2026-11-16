# MygrteX on-premises discovery agent

A small Linux VM that you install **inside your network**. It reads the configuration of your VMware vCenter or standalone ESXi hosts, Hyper-V hosts and physical Windows or Linux servers and
sends the inventory to your MygrteX portal, so the portal can assess the estate for migration to Azure.

- **Read-only and metadata-only.** CPU, memory, disks, networks, operating system name and, optionally, utilization and established connections. No files, no application
  data, no guest passwords.
- **Outbound-only.** The agent connects out to your MygrteX portal over HTTPS. The portal never connects in, so no inbound firewall rule is needed.
- **Configured in the portal, not on the VM.** Which systems to read, their read-only accounts, the approved SSH host keys and the schedule are all set in the MygrteX portal
  and pushed to the agent. The only things stored on the VM are the portal address and the agent's token.
- **One file.** `mygrtex_agent.py` has no dependencies except `pywinrm` (installed only for Hyper-V and Windows targets). Read it before you run it.

This repository contains only the agent and its installer. It holds no secrets: the agent token is created in your MygrteX portal and is never stored here.

## Requirements

- A Linux VM: Ubuntu 22.04 / 24.04, Debian 12, or RHEL / Rocky / Alma 9. 2 vCPU, 4 GB RAM, 20 GB disk. Root access (`sudo`). Python 3.9 or newer (installed by the script if missing).
- Network, **all outbound from the agent VM**:

| To | Port | Purpose |
|---|---|---|
| Your MygrteX portal | 443/TCP (or the port in its address) | HTTPS: check-in every 60 s, receive the configuration set in the portal, receive collect and test requests, upload the inventory |
| github.com | 443/TCP | Installation and upgrades only (download this repository at a version tag) |
| OS package mirrors, pypi.org | 443/TCP (80 for some mirrors) | Installation only: git, Python and, for Hyper-V and Windows, `pywinrm` |
| DNS servers | 53/UDP+TCP | Name resolution |
| NTP servers | 123/UDP | Correct time (TLS certificates are rejected if the clock is wrong) |
| vCenter servers | 443/TCP | Only if you add a VMware target |
| Standalone ESXi hosts | 443/TCP | Only if you add an ESXi target |
| Hyper-V hosts, physical Windows servers | 5986/TCP (WinRM over HTTPS) | Only if you add those targets |
| Physical Linux servers | 22/TCP (or the port you set) | Only if you add those targets (SSH) |

Inbound: none for MygrteX. If outbound HTTPS must use a proxy, add `HTTPS_PROXY=http://proxy:port` (and `NO_PROXY` for the target hosts) to `/etc/mygrtex-agent/agent.env`
and run `sudo systemctl restart mygrtex-agent`.

## Install

In the MygrteX portal open **Discovery > On-premises agents > Create on-prem agent**, fill in the details and press **Next**. The portal shows **one command** with the agent
token inside, and a PDF of the same steps named with the agent version. Paste the command into a terminal on the Linux VM. It installs git if needed, clones this repository at the
version tag (`agent-v<version>`) and runs `install.sh --non-interactive`. The token travels in an environment variable, never on a command line other users could read.

When it finishes, the agent is running and appears as **Online** in the portal within about a minute.

Manual alternative (the portal's command does exactly this):

```bash
git clone --branch agent-v3.1.0 --depth 1 https://github.com/sntecxdeveloper/mygrtex-agent.git
cd mygrtex-agent
sudo MYGRTEX_AGENT_TOKEN='<token from the portal>' ./install.sh --server https://your-mygrtex.example.com --non-interactive
```

`install.sh` creates an unprivileged service user, installs the agent under `/opt/mygrtex-agent`, writes `/etc/mygrtex-agent/config.json` (the portal address) and
`/etc/mygrtex-agent/agent.env` (the token, mode 600), and enables and starts the `mygrtex-agent` service (a hardened systemd unit).

## Configure (in the portal)

Open the agent in the portal and choose **Manage targets > Add target** for each system:

| Target | What the agent connects to | Account |
|---|---|---|
| VMware vCenter | vCenter 7.0U2 or newer, REST API, GET only | the built-in **Read-only** role |
| VMware ESXi (standalone, no vCenter) | vSphere SOAP API on port 443, read-only operations only (login, a VM list, logout) | a local ESXi user with the **Read-only** role |
| Hyper-V hosts | WinRM over HTTPS, `Get-*` cmdlets from an allowlist | a dedicated account in **Hyper-V Administrators** (Hyper-V has no read-only role) |
| Physical Windows servers | WinRM over HTTPS, `Get-CimInstance` of six fixed classes | **Remote Management Users** plus WMI read |
| Physical Linux servers | SSH with a key, one fixed read-only script | an unprivileged user (no sudo), with an unencrypted key |

Passwords and keys are stored in the portal's secret store, sent to the agent over HTTPS only when it asks for its configuration, and kept in the agent's memory. An SSH key is written to a
private temporary directory only while that server is being read, then deleted. For physical Linux servers, press **Test**: the agent reports each server's SSH host key fingerprint and you
approve it in the portal after comparing it with the server (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). The agent never trusts a key by itself.

Then press **Test** (a dry run that uploads nothing) and **Collect now**, or set a schedule.

## On the VM

```bash
sudo mygrtex-agent status                  # can this VM reach the portal? which configuration revision does it have? which targets?
sudo mygrtex-agent collect --out /tmp/inv  # write exactly what would be uploaded, upload nothing: review it first
sudo systemctl status mygrtex-agent
journalctl -u mygrtex-agent -f             # the agent's log
```

There are no commands to add targets or trust hosts on the VM: that is done in the portal.

## Upgrade

Run the installation command again with a newer version tag. The token and the portal address are kept; the targets live in the portal.

## Remove

```bash
sudo systemctl disable --now mygrtex-agent
sudo rm -rf /opt/mygrtex-agent /etc/mygrtex-agent /usr/local/bin/mygrtex-agent /etc/systemd/system/mygrtex-agent.service
sudo userdel mygrtex-agent
```
Then revoke the agent in the portal: its token stops working and its stored credentials are deleted.

## Security notes

- Read-only by design: vCenter GET only (plus its own session login and logout); Hyper-V and Windows only allowlisted `Get-*` cmdlets, each checked before it runs; Linux one fixed script of read-only commands.
- The service runs as an unprivileged user with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, no capabilities and a private runtime directory.
- Not collected: file contents, application data, guest credentials, utilization history from VMware (import it instead), raw device mappings and pass-through devices on VMware, the guest OS of Hyper-V VMs.
  The portal reports each of these as "not collected", never as zero.
- Review `mygrtex_agent.py` (one file) before you trust it.
