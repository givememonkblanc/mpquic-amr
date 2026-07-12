# exp_env.sh — single source of truth for the CURRENT deployment.
# Source this before any experiment script. Every value can still be
# overridden from the caller's environment.
#
# History: the experiment scripts' baked-in defaults describe the OLD
# deployment (~/client_multi_path_enhanced on the edge, server 192.168.0.80,
# local ./build). The current system is the draft-20 picoquic stack living in
# ~/mpquic on BOTH hosts, built in build_d20/, server on 192.168.0.38.

# ── Server (this ryzen box) ──
export SERVER_IP="${SERVER_IP:-192.168.0.38}"
export PORT="${PORT:-4433}"
export BUILD_DIR="${BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build_d20}"
export SVR_SAVE_FRAMES="${SVR_SAVE_FRAMES:-0}"   # streaming concept: logs only
export SVR_PREVIEW="${SVR_PREVIEW:-0}"

# ── Edge control channel ──
# CRITICAL: .env's ssh_address is the edge's Wi-Fi IP (192.168.0.13). The
# handover scenario disconnects Wi-Fi, which would kill the very ssh session
# that has to issue the reconnect. Control traffic must ride Tailscale, which
# re-routes over the hotspot while Wi-Fi is down.
export SSH_ADDRESS="${SSH_ADDRESS:-100.109.159.8}"

# ── Edge (orin / jetson-desktop) ──
export EDGE_PROJECT_DIR="${EDGE_PROJECT_DIR:-/home/jetson/mpquic}"
export CLIENT_BIN_NAME="${CLIENT_BIN_NAME:-client_uploader}"
export CLIENT_BIN="${CLIENT_BIN:-${EDGE_PROJECT_DIR}/build_d20/${CLIENT_BIN_NAME}}"
export EDGE_WIFI_IFACE="${EDGE_WIFI_IFACE:-wlP1p1s0}"
export EDGE_WIFI_IP="${EDGE_WIFI_IP:-192.168.0.13}"
export EDGE_HOTSPOT_IP="${EDGE_HOTSPOT_IP:-172.20.10.3}"
export EDGE_WIFI_CON_NAME="${EDGE_WIFI_CON_NAME:-solfac 220 5G}"  # nmcli connection name of the Wi-Fi AP
# The client writes ./qlogs_client relative to its cwd; over ssh that is $HOME.
export REMOTE_QLOG_DIR="${REMOTE_QLOG_DIR:-/home/jetson/qlogs_client}"

# The wired iface teardown was for the old testbed; current paths are
# Wi-Fi + USB-tether hotspot only.
export DISABLE_EDGE_WIRED_IFACE="${DISABLE_EDGE_WIRED_IFACE:-0}"
export SKIP_EDGE_ROUTE_SETUP="${SKIP_EDGE_ROUTE_SETUP:-1}"
export TUNE_RP_FILTER="${TUNE_RP_FILTER:-0}"
