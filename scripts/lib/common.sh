# common.sh — shared helpers for the MP-QUIC experiment drivers.
# Source AFTER exp_env.sh (so exp_env's SSH_ADDRESS/SERVER_IP win) and AFTER
# SCRIPT_DIR/ROOT_DIR are set:
#
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
#   source "${SCRIPT_DIR}/exp_env.sh"
#   source "${SCRIPT_DIR}/lib/common.sh"
#   parse_env
#
# Not a standalone script — no shebang, no `set` (the sourcing script owns those).

: "${ROOT_DIR:?common.sh requires ROOT_DIR to be set before sourcing}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
# Own the ssh known_hosts under $HOME (was a world-writable /tmp/opencode path).
KNOWN_HOSTS="${KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"

log(){ printf '[*] %s\n' "$*"; }
die(){ printf '[!] %s\n' "$*" >&2; exit 1; }

# parse_env — read ssh_address/ssh_id/ssh_password from .env into
# SSH_ADDRESS / SSH_ID / SSH_PASSWORD. Any already-set value wins (e.g.
# exp_env.sh forces SSH_ADDRESS to the Tailscale IP so a Wi-Fi disconnect
# during a handover test does not kill the control channel).
parse_env(){
    [ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"
    local parsed
    parsed="$(python3 -c "
import re
text = open('$ENV_FILE').read()
v = {m.group(1): m.group(2) for m in re.finditer(r'^(ssh_address|ssh_id|ssh_password)\s*=\s*[\x27\"]([^\x27\"]+)[\x27\"]\s*\$', text, re.M)}
print(v.get('ssh_address',''), v.get('ssh_id',''), v.get('ssh_password',''), sep='\t')
")" || die "failed to parse $ENV_FILE"
    local a i p
    IFS=$'\t' read -r a i p <<<"$parsed"
    SSH_ADDRESS="${SSH_ADDRESS:-$a}"
    SSH_ID="${SSH_ID:-$i}"
    SSH_PASSWORD="${SSH_PASSWORD:-$p}"
    [ -n "$SSH_PASSWORD" ] || die "ssh_password not found in $ENV_FILE"
    [ -n "$SSH_ADDRESS" ] || die "ssh_address not resolved (set it or put it in $ENV_FILE)"
}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$KNOWN_HOSTS")

# ssh_edge <arg>...  — tokenized remote exec. ssh joins the args with spaces and
# the remote shell re-parses them. Use for command + flags where no single arg
# needs its internal spaces preserved (ip link show, killall, env … timeout …).
ssh_edge(){
    sshpass -p "$SSH_PASSWORD" ssh "${SSH_OPTS[@]}" "${SSH_ID}@${SSH_ADDRESS}" "$@"
}

# ssh_edge_sh "<command string>"  — run one pre-composed command string verbatim,
# preserving pipes and quoting. Use for `echo pw | sudo -S …` pipelines; the
# tokenizing ssh_edge() above would mangle the pipe.
ssh_edge_sh(){
    sshpass -p "$SSH_PASSWORD" ssh "${SSH_OPTS[@]}" "${SSH_ID}@${SSH_ADDRESS}" "$1"
}

# scp_edge <remote_path> <local_dest>
scp_edge(){
    sshpass -p "$SSH_PASSWORD" scp "${SSH_OPTS[@]}" "${SSH_ID}@${SSH_ADDRESS}:$1" "$2"
}
