#!/usr/bin/env bash
# run_hls.sh — receive the MP-QUIC depth+RGB frame streams and re-stream them as
# two live HLS streams (depth colormap + RGB) instead of saving frames to disk.
# View with: python3 scripts/stream_monitor.py  →  http://<host>:8081/hls
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
source "${SCRIPT_DIR}/exp_env.sh"
source "${SCRIPT_DIR}/lib/common.sh"

PORT="${PORT:-4433}"
CERT="${CERT:-${ROOT_DIR}/certs/cert.pem}"
KEY="${KEY:-${ROOT_DIR}/certs/key.pem}"
BIN="${BIN:-${ROOT_DIR}/build_d20/server_recv}"
HLS_DIR="${HLS_DIR:-${ROOT_DIR}/results/hls}"
SEG_TIME="${SEG_TIME:-1}"        # HLS segment length (s) — smaller = lower latency
LIST_SIZE="${LIST_SIZE:-6}"      # segments kept in the rolling playlist
ENCODER="${ENCODER:-libx264}"    # libx264 (CPU) | h264_nvenc | h264_vaapi …
FPS="${FPS:-5}"                  # assumed input frame rate (OAK-D streams @5fps).
                                 # image2pipe needs this for correct HLS timestamps;
                                 # -f mjpeg -use_wallclock does NOT roll segments.

[ -x "$BIN" ] || die "server_recv not built: $BIN (run: bash scripts/build.sh)"
command -v ffmpeg >/dev/null || die "ffmpeg not found (apt install ffmpeg)"
[ -f "$CERT" ] || die "cert missing: $CERT (run: bash scripts/gen_serts.sh)"

# Fresh HLS output dir (rolling segments accumulate otherwise).
rm -rf "$HLS_DIR"; mkdir -p "$HLS_DIR"

# ffmpeg pipeline: read the mjpeg-over-stdin the server pipes us, encode H.264,
# emit a rolling HLS playlist. wallclock timestamps handle the variable frame
# rate (frames arrive at ~2-5 fps).
ff_cmd() {  # ff_cmd <name>
  local name="$1"
  printf 'ffmpeg -hide_banner -loglevel error -f image2pipe -framerate %s -i - -an -c:v %s -preset veryfast -tune zerolatency -pix_fmt yuv420p -g %d -f hls -hls_time %s -hls_list_size %s -hls_flags delete_segments+append_list+independent_segments+omit_endlist -hls_segment_filename %s/%s_%%05d.ts %s/%s.m3u8' \
    "$FPS" "$ENCODER" "$((SEG_TIME * 10))" "$SEG_TIME" "$LIST_SIZE" "$HLS_DIR" "$name" "$HLS_DIR" "$name"
}

export SVR_SAVE_FRAMES=0                  # replace disk-save with HLS
export SVR_PREVIEW=1
export SVR_PREVIEW_CMD="$(ff_cmd depth)"  # depth colormap-JPEG → HLS
export SVR_PREVIEW_CMD_RGB="$(ff_cmd rgb)" # RGB JPEG → HLS

log "HLS streaming → $HLS_DIR   (depth.m3u8 + rgb.m3u8)"
log "server: :$PORT   encoder=$ENCODER   seg=${SEG_TIME}s   view: http://<host>:8081/hls"
exec "$BIN" --port "$PORT" --cert "$CERT" --key "$KEY" --out "$HLS_DIR"
