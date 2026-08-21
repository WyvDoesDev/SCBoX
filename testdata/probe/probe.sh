#!/bin/sh
# Benign shell-side sandbox self-test: detection + escape probes that only echo
# what they observe. Run via the package's postinstall hook.

# ---- detection ----
echo "DETECT:sh:hostname=$(hostname)"
echo "DETECT:sh:whoami=$(whoami)"
echo "DETECT:sh:uname=$(uname -s)"
echo "DETECT:sh:home=$HOME"
echo "DETECT:sh:npm_token_set=${NPM_TOKEN:+yes}"
if [ -f /.dockerenv ]; then echo "DETECT:sh:dockerenv=present"; else echo "DETECT:sh:dockerenv=absent"; fi
if [ -f /proc/vz ]; then echo "DETECT:sh:openvz=present"; else echo "DETECT:sh:openvz=absent"; fi

# ---- escape attempts ----
SECRET=$(cat /etc/passwd)
echo "ESCAPE:sh:passwd_len=${#SECRET}"

echo "persisted-by-sh" > /tmp/scbox_escape_probe_sh
BACK=$(cat /tmp/scbox_escape_probe_sh)
echo "ESCAPE:sh:write_readback=${BACK:-(empty)}"

# control flow + command substitution must evaluate for this to print
for i in 1 2 3; do
  COUNT="$i"
done
echo "ESCAPE:sh:loop_ran_to=$COUNT"
echo "ESCAPE:sh:id=$(id)"
