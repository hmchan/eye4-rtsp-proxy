# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file Python 3 RTSP proxy for Eye4/VStarcam IP cameras. Discovers cameras on LAN via the proprietary PPPP protocol over UDP, establishes P2P sessions, decrypts H.264/H.265 video + IMA ADPCM audio, and re-serves as standard RTSP streams.

## Running

```bash
# Run proxy (discovers cameras, serves RTSP)
python3 eye4_rtsp_proxy.py

# With explicit credentials
python3 eye4_rtsp_proxy.py -u admin -p 888888 --base-port 9555

# Debug mode
python3 eye4_rtsp_proxy.py -v

# Network diagnostics only
python3 eye4_rtsp_proxy.py --diag

# Direct camera (skip broadcast discovery)
python3 eye4_rtsp_proxy.py --target-ip 192.168.1.50
```

Config file: `/etc/eye4_rtsp_proxy.yml` (YAML, auto-created on first run). CLI args override config values.

## Dependencies

```bash
pip install pycryptodome pyyaml   # pycryptodome required, pyyaml optional
```

`netifaces` is optional (broadcast address detection fallback exists).

## Running Tests

```bash
# Verification tests (imports from eye4_rtsp_proxy.py, uses eye4.pcap)
python3 test_verify.py

# Decryption analysis against pcap (requires scapy)
python3 test_decrypt.py
```

Both test files use `eye4.pcap` (real 3-camera capture) as ground truth. No test framework — they're standalone scripts with assertions.

## Architecture

`eye4_rtsp_proxy.py` is a ~3400-line monolithic async script. Key sections in order:

| Lines | Module | Purpose |
|-------|--------|---------|
| 1-115 | Config | YAML config loading, optional imports |
| 150-160 | XOR Layer | 4-byte XOR obfuscation for control packets (key: `0x15DB4322`) |
| 163-241 | P2P Cipher | Stateful stream cipher for DRW data (table-based, PSK-derived) |
| 243-277 | AES Decrypt | Optional AES-128-ECB video decryption (UID+password derived key) |
| 278-450 | Audio Codecs | IMA ADPCM decoder, PCM→G.711 μ-law encoder |
| 455-540 | Packet Builders | Construct/parse PPPP packets (discovery, punch, DRW, ACK, CGI) |
| 551-1375 | **PPPPUnifiedProtocol** | Core async UDP handler — discovery, connection, encryption auto-detect, DRW relay |
| 1376-1596 | Frame Reassembly | VideoReassembly + AudioReassembly — buffer STREAMHEAD-delimited frames |
| 1598-1847 | **CameraSession** | Per-camera lifecycle: PPPP protocol + RTSP server + auto-reconnect state machine |
| 1848-2511 | **RTSP Server** | Minimal RTSP 1.0 server + per-client handler, RTP/TCP interleaved, SDP generation |
| 2512-2937 | Discovery & Main | Broadcast discovery, multi-camera orchestration, CLI parsing |

### Key Classes

- **PPPPUnifiedProtocol** — asyncio DatagramProtocol. Handles one camera's UDP session. Manages encryption state, DRW packet reassembly, ACK generation, and command sending.
- **CameraSession** — Owns a PPPPUnifiedProtocol + RTSPServer pair. State machine: STOPPED → CONNECTING → CONNECTED ↔ STALE(5s) → OFFLINE(15s) → RECONNECTING.
- **RTSPServer** — Accepts TCP clients, generates SDP, sends RTP-interleaved H.264/H.265 video + G.711 µ-law audio. Caches last I-frame for instant playback.
- **VideoReassembly / AudioReassembly** — Accumulate DRW payloads, detect STREAMHEAD boundaries (`0x55AA15A8`), emit complete frames.

### Protocol Stack

```
UDP:32108 (discovery) / dynamic (DRW)
  → XOR obfuscation (control packets only)
    → PPPP messages (LAN_SEARCH=0xE0, DRW=0xD0, DRW_ACK=0xD1, etc.)
      → P2P_Proprietary cipher (DRW payloads, PSK: "vstarcam2019")
        → DRW framing: F1 D0 [size16BE] D1 [channel] [idx16BE] [payload]
          → Channel 0: CGI commands (HTTP-style)
          → Channel 1: STREAMHEAD + H.265 NALUs
          → Channel 2: STREAMHEAD + IMA ADPCM audio
```

### Critical Protocol Details

- **DRW_ACK inner magic is `0xD1`** (same as DRW), not `0xD2`. Wrong byte kills video streaming.
- Camera tracks sessions by UDP source port — must create fresh socket to restart.
- Video start CGI uses `streamid=10` (HEVC main stream); `streamid=0` does NOT work.
- Audio must be requested separately from video (`/audiostream.cgi`).
- STREAMHEAD byte 4 = frame type (0x10=I, 0x11=P, 0x06=audio), byte 5 = codec.

## Deployment

Deployed as Docker container:
- Image: `hmchan/eye4-proxy:latest` (Alpine-based, ~74MB)
- Config: `/etc/eye4_rtsp_proxy.yml` bind-mounted read-only
- `network_mode: host` required for UDP broadcast discovery
- See `Dockerfile` and `README.md` for build/run details
