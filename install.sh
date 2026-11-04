#!/bin/bash
# Installs the MygrteX on-premises discovery agent on this Linux VM (Ubuntu/Debian or RHEL/Rocky/Alma). Run as root:  sudo ./install.sh
# Normally started by the one-line command that MygrteX shows when you create the agent (it clones this repository at a version tag and runs this script
# with --non-interactive; the agent token arrives in the environment variable MYGRTEX_AGENT_TOKEN, never on a command line that other users could read).
# Needs Python 3.9+ and, unless you pass --no-winrm, internet access (or a local wheel directory: --wheels DIR) to install pywinrm for Hyper-V and Windows targets.
set -euo pipefail

SERVER="" ; WINRM=1 ; WHEELS="" ; NONINTERACTIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2;;
    --no-winrm) WINRM=0; shift;;
    --wheels) WHEELS="$2"; shift 2;;
    --non-interactive) NONINTERACTIVE=1; shift;;
    *) echo "usage: sudo ./install.sh [--server https://mygrtex.example.com] [--non-interactive] [--no-winrm] [--wheels DIR]"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HERE/mygrtex_agent.py" ] && [ -f "$HERE/mygrtex-agent.service" ] || { echo "mygrtex_agent.py and mygrtex-agent.service must be next to install.sh"; exit 1; }

if command -v apt-get >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv openssh-client util-linux sudo
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 openssh-clients util-linux sudo
else
  echo "unsupported distribution: install python3 (3.9+), python3-venv, openssh-client and sudo, then re-run"; exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "Python 3.9 or newer is required"; exit 1; }

id mygrtex-agent >/dev/null 2>&1 || useradd --system --home-dir /opt/mygrtex-agent --shell /usr/sbin/nologin mygrtex-agent
install -d -m 755 -o root -g root /opt/mygrtex-agent
install -d -m 750 -o mygrtex-agent -g mygrtex-agent /etc/mygrtex-agent
install -m 644 -o root -g root "$HERE/mygrtex_agent.py" /opt/mygrtex-agent/mygrtex_agent.py

python3 -m venv /opt/mygrtex-agent/venv
if [ "$WINRM" -eq 1 ]; then
  if [ -n "$WHEELS" ]; then /opt/mygrtex-agent/venv/bin/pip install --no-index --find-links "$WHEELS" pywinrm
  else /opt/mygrtex-agent/venv/bin/pip install --quiet pywinrm; fi
fi

if [ ! -f /etc/mygrtex-agent/config.json ]; then
  if [ -z "$SERVER" ]; then
    [ "$NONINTERACTIVE" -eq 0 ] || { echo "--server is required with --non-interactive"; exit 1; }
    read -r -p "MygrteX URL (https://...): " SERVER
  fi
  case "$SERVER" in https://*) ;; *) echo "the MygrteX URL must start with https://"; exit 1;; esac
  printf '{\n  "server": "%s",\n  "ca_file": ""\n}\n' "$SERVER" > /etc/mygrtex-agent/config.json
  chown mygrtex-agent:mygrtex-agent /etc/mygrtex-agent/config.json; chmod 640 /etc/mygrtex-agent/config.json
fi
if [ ! -f /etc/mygrtex-agent/agent.env ]; then
  TOKEN="${MYGRTEX_AGENT_TOKEN:-}"
  if [ -z "$TOKEN" ]; then
    [ "$NONINTERACTIVE" -eq 0 ] || { echo "set MYGRTEX_AGENT_TOKEN with --non-interactive"; exit 1; }
    read -r -s -p "Agent token (shown once when you registered the agent in MygrteX): " TOKEN; echo
  fi
  case "$TOKEN" in mgx_*) ;; *) echo "that does not look like an agent token (mgx_...)"; exit 1;; esac
  printf 'SNTX_AGENT_TOKEN=%s\n' "$TOKEN" > /etc/mygrtex-agent/agent.env
  chown mygrtex-agent:mygrtex-agent /etc/mygrtex-agent/agent.env; chmod 600 /etc/mygrtex-agent/agent.env
fi

cat > /usr/local/bin/mygrtex-agent <<'WRAP'
#!/bin/bash
# Runs the agent as its own unprivileged user, with the token from agent.env, so files it creates belong to that user.
set -a; [ -r /etc/mygrtex-agent/agent.env ] && . /etc/mygrtex-agent/agent.env; set +a
if [ "$(id -un)" = "mygrtex-agent" ]; then exec /opt/mygrtex-agent/venv/bin/python /opt/mygrtex-agent/mygrtex_agent.py "$@"; fi
exec sudo -u mygrtex-agent -E /opt/mygrtex-agent/venv/bin/python /opt/mygrtex-agent/mygrtex_agent.py "$@"
WRAP
chmod 755 /usr/local/bin/mygrtex-agent

install -m 644 "$HERE/mygrtex-agent.service" /etc/systemd/system/mygrtex-agent.service
systemctl daemon-reload
systemctl enable mygrtex-agent >/dev/null
systemctl restart mygrtex-agent          # starts it (or restarts it after an upgrade): it appears as Online in MygrteX within about a minute

VERSION="$(sed -n 's/^AGENT_VERSION = "\(.*\)"/\1/p' "$HERE/mygrtex_agent.py" | head -1)"
cat <<DONE

MygrteX agent version ${VERSION:-unknown} is installed and running.

Nothing else is configured on this server. In MygrteX open Discovery > On-premises agents, choose this agent and add what it should read
(vCenter, Hyper-V hosts, physical servers). The settings and read-only accounts you enter there are pushed to the agent.

  sudo mygrtex-agent status                  check that this VM reaches MygrteX and see the configuration it received
  sudo mygrtex-agent collect --out /tmp/inv  review exactly what would be uploaded (nothing is sent)
  journalctl -u mygrtex-agent -f             follow the agent's log

Only the MygrteX address (/etc/mygrtex-agent/config.json) and the agent token (/etc/mygrtex-agent/agent.env, mode 600) are stored on this VM.
DONE
