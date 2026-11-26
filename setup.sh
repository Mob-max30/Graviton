#!/usr/bin/env bash
if ! command -v python3 >/dev/null 2>&1 || ! dpkg -s python3-venv python3-pip >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv
fi

if [ ! -x "/opt/venv/bin/pip" ]; then
  rm -rf /opt/venv
  python3 -m venv /opt/venv
fi

/opt/venv/bin/pip install -r requirements.txt && \
/opt/venv/bin/pip install --no-deps -e . && \
export PATH="/opt/venv/bin:$PATH" && \
hash -r && \
eval "$(/opt/venv/bin/gt shell-init)"
