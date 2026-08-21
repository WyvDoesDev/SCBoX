#!/usr/bin/env bash
# SCBoX npm install-gate.
#
# Source this from your ~/.bashrc or ~/.zshrc:
#
#     source /path/to/scbox/scripts/npm-guard.sh
#
# It wraps `npm install` so that any package you're about to add is first
# detonated inside the SCBoX sandbox. If the verdict crosses the threshold, the
# real install is blocked BEFORE npm runs the package's install scripts.
#
# Config (env vars):
#   SCBOX_BIN       path to the scbox binary       (default: scbox, from PATH)
#   SCBOX_FAIL_ON   block at this verdict or worse  (default: suspicious)
#                   one of: low | suspicious | malicious
#
# Override for a single install with:  command npm install <pkg>

SCBOX_BIN="${SCBOX_BIN:-scbox}"
SCBOX_FAIL_ON="${SCBOX_FAIL_ON:-suspicious}"

npm() {
  case "$1" in
    install | i | add | isntall | in | ins)
      local specs=() a
      for a in "${@:2}"; do
        case "$a" in
          -*) ;;                 # flags (e.g. --save-dev) are not packages
          *) specs+=("$a") ;;
        esac
      done

      if [ "${#specs[@]}" -eq 0 ]; then
        # `npm install` with no args → analyze the current project + its tree.
        echo "🔎 SCBoX: scanning project dependencies before install…"
        if ! "$SCBOX_BIN" --fail-on "$SCBOX_FAIL_ON" --trace=false . ; then
          echo "⛔ SCBoX blocked this install. Override with: command npm install" >&2
          return 1
        fi
      else
        local s
        for s in "${specs[@]}"; do
          echo "🔎 SCBoX: scanning '$s' before install…"
          if ! "$SCBOX_BIN" --fail-on "$SCBOX_FAIL_ON" --trace=false "$s" ; then
            echo "⛔ SCBoX blocked '$s'. Override with: command npm install $*" >&2
            return 1
          fi
        done
      fi

      echo "✅ SCBoX: clean - proceeding with npm install"
      command npm "$@"
      ;;
    *)
      command npm "$@"
      ;;
  esac
}
