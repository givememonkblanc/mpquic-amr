# Validated Local-IP Real-Camera Results

These runs use the now-validated setup:

- Server IP: `192.168.0.80`
- Client: Jetson MP-QUIC client
- Camera mode: **strict real-camera mode** (test-pattern fallback disabled by default)
- Camera device observed in logs: `/dev/video0`
- Multipath requirement: Wi-Fi + iPhone USB hotspot both present

## Latest valid runs

| Scenario | Run ID | Frames received | Handshake ready | Camera opened | PQI switch count | First switch | Last switch |
|---|---|---:|---|---|---:|---|---|
| Handover | `20260617-camera-strict-handover-localip-2` | 271 | Yes | Yes | 7 | `-1 -> 1 (better_usb)` | `0 -> 1 (degrade_failover)` |
| Degradation | `20260617-camera-strict-degrade-localip-2` | 1416 | Yes | Yes | 16 | `-1 -> 1 (better_usb)` | `1 -> 0 (stable_failback)` |

## Notes

- Public-IP-based runs using `165.229.169.131` were invalidated by Jetson `eno1` same-subnet routing conflicts.
- The experiment scripts now default to `SERVER_IP=192.168.0.80` to avoid that conflict.
- The camera path no longer silently falls back to a test pattern; if no real camera opens, the client fails immediately.
- Current `client_uploader` argv contract is: `<server_ip> <primary_local_ip> [port] [backup_local_ip]`. Both paths now use the same `server_ip`; backup goes through Tailscale subnet routing.
