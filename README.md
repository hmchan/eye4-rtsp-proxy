# Eye4 RTSP Proxy

RTSP proxy for Eye4/VStarcam IP cameras. Discovers cameras on the LAN via the proprietary PPPP protocol, decrypts H.264/H.265 video and IMA ADPCM audio, and re-serves them as standard RTSP streams consumable by VLC, ffmpeg, Home Assistant, Scrypted, go2rtc, etc.

These cameras have **no native RTSP server** — this proxy bridges the gap.

## Features

- **Auto-discovery**: Finds cameras on the LAN via UDP broadcast (no manual IP configuration needed)
- **Multi-camera**: Handles multiple cameras simultaneously, each on its own RTSP port
- **Video**: H.264 and H.265/HEVC, 1080p 30fps
- **Audio**: IMA ADPCM decoded to G.711 µ-law (PCMU), plus G.711 a-law passthrough
- **Encryption**: Auto-detects P2P cipher mode and PSK per camera
- **Snapshots**: HTTP endpoint serves JPEG snapshots from cached I-frames (via ffmpeg)
- **Motion detection**: Polls camera alarm status, triggers webhooks (Scrypted-compatible)
- **Auto-reconnect**: State machine handles camera disconnects and network interruptions
- **C accelerator**: Optional shared library for cipher/ADPCM hot paths (~5x speedup)
- **Docker-ready**: Alpine-based image, ~74MB, single command deploy

## Quick Start

```bash
# Install dependencies
pip install pycryptodome pyyaml

# Run (discovers cameras automatically, default credentials admin/888888)
python3 eye4_rtsp_proxy.py

# Connect with VLC
vlc rtsp://localhost:9555/

# Or ffmpeg
ffmpeg -i rtsp://localhost:9555/ -c copy output.mp4
```

## Installation

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `pycryptodome` | Yes | AES decryption support |
| `pyyaml` | Recommended | Config file support (falls back to defaults) |
| `netifaces` | Optional | Better broadcast address detection |
| `ffmpeg` | Optional | Snapshot JPEG conversion (system binary) |

```bash
pip install pycryptodome pyyaml
# Optional
pip install netifaces
```

### Docker

```bash
docker build -t eye4-proxy .
docker run --network host eye4-proxy
```

`--network host` is **required** for UDP broadcast discovery.

### Docker Compose

```yaml
services:
  eye4-proxy:
    build: .
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./eye4_rtsp_proxy.yml:/etc/eye4_rtsp_proxy.yml:ro
```

## Usage

```bash
# Basic (auto-discover, default credentials)
python3 eye4_rtsp_proxy.py

# Explicit credentials
python3 eye4_rtsp_proxy.py -u admin -p mypassword

# Custom RTSP base port
python3 eye4_rtsp_proxy.py --base-port 8554

# Direct camera (skip broadcast)
python3 eye4_rtsp_proxy.py --target-ip 192.168.1.100

# Debug logging
python3 eye4_rtsp_proxy.py -v

# Network diagnostics
python3 eye4_rtsp_proxy.py --diag
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u`, `--username` | `admin` | Camera login username |
| `-p`, `--password` | `888888` | Camera login password |
| `--base-port` | `9555` | Starting RTSP port (increments per camera) |
| `--target-ip` | *(broadcast)* | Send directly to camera IP |
| `--discovery-time` | `3` | Discovery timeout in seconds |
| `--psk` | `vstarcam2019` | P2P encryption pre-shared key |
| `--enc-mode` | `auto` | Encryption: `auto`, `p2p`, or `xor` |
| `--config` | `/etc/eye4_rtsp_proxy.yml` | Config file path |
| `-v`, `--verbose` | off | Debug logging |
| `--diag` | off | Network diagnostics only |
| `--motion-cooldown` | `30` | Seconds to hold motion ON after alarm |

## Configuration

The proxy auto-creates a YAML config file at `/etc/eye4_rtsp_proxy.yml` on first run. CLI arguments override config values.

```yaml
username: admin
password: "888888"
base_port: 9555
discovery_time: 3
psk: vstarcam2019
enc_mode: auto
log_level: info          # debug, info, warning, error
motion_cooldown: 30
motion_poll_interval: 1
snapshot_bind_addr: 0.0.0.0

# Auto-populated on discovery. Override ports or add webhooks here.
cameras:
  VSTABCDEFGHIJKL:
    port: 9555
    motion_webhook: "http://scrypted:10443/endpoint/@scrypted/webhook/turnOnOff/xyz"
  VSTMNOPQRSTUVWX: 9556
```

## Endpoints

For a camera assigned RTSP port 9555:

| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `rtsp://host:9555/` | RTSP/TCP | Live video + audio stream |
| `http://host:10555/snapshot.jpg` | HTTP | JPEG snapshot from cached I-frame |

## Motion Detection

The proxy polls each camera's `alarm_status` via the PPPP command channel. When motion is detected, it calls a webhook URL:

- **Motion start**: `POST {webhook}/turnOn`
- **Motion end**: `POST {webhook}/turnOff` (after cooldown expires)

This is designed for [Scrypted](https://www.scrypted.app/) virtual motion sensors but works with any HTTP endpoint.

Configure per-camera in the YAML config under `cameras.<UID>.motion_webhook`.

## C Accelerator

An optional C shared library accelerates the P2P cipher, ADPCM decoder, and byte-swap operations:

```bash
gcc -O2 -shared -fPIC -o eye4_accel.so eye4_accel.c
```

Place `eye4_accel.so` next to the Python script. The proxy auto-loads it if present and falls back to pure Python otherwise. The Docker image builds this automatically.

## Compatible Cameras

Tested with VStarcam cameras using the **Eye4** mobile app (Android: `vstc.vscam.client`). Known working UID prefixes:

| Prefix | PSK | Notes |
|--------|-----|-------|
| VSTJ, VSTK, VSTL, VSTM, VSTN, VSTP | `vstarcam2019` | Most common |
| VSTG, VSTH, ELSC | `vstarcam2018` | Older models |
| VSTC, VSTB | *(none)* | Legacy, no P2P cipher |
| VC0 | `vstarcam2019` | Variant prefix |

The proxy auto-detects the correct PSK. If auto-detection fails, specify manually with `--psk`.

## Protocol Documentation

See [PROTOCOL.md](PROTOCOL.md) for a comprehensive technical reference covering the PPPP protocol internals, packet formats, cipher algorithms, and proxy architecture.

## Architecture

Single-file async Python 3 application (~3500 lines). Key components:

- **PPPPUnifiedProtocol** — asyncio UDP handler for the PPPP session lifecycle
- **CameraSession** — Per-camera orchestrator with auto-reconnect state machine
- **RTSPServer** — RTSP 1.0 server with RTP/TCP interleaved transport
- **VideoReassembly / AudioReassembly** — Frame reconstruction from DRW packets
- **MotionHandler** — Alarm polling and webhook integration

```
Camera (UDP) ──→ PPPPUnifiedProtocol ──→ VideoReassembly ──→ RTSPServer ──→ RTSP Clients
                                     ──→ AudioReassembly ──→
```

## Troubleshooting

**No cameras found**: Run `--diag` to test network connectivity. Ensure the proxy host is on the same subnet as the cameras. Try `--target-ip <camera_ip>`.

**Video doesn't start**: Check credentials (`-u`/`-p`). Try `--enc-mode p2p --psk vstarcam2019` explicitly.

**Audio missing**: Audio is requested separately from the camera. Verify with `ffprobe rtsp://host:port/` — you should see both an H264 video track and a PCMU audio track. For Home Assistant, ensure go2rtc WebRTC is working (HLS fallback has no audio).

**Connection drops**: The proxy auto-reconnects. If drops are frequent, ensure the camera firmware is up to date and the network path is stable.

## License

MIT
