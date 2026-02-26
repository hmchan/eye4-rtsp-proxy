# Eye4 / VStarcam PPPP Protocol & RTSP Proxy — Technical Reference

This document describes the proprietary PPPP (Peer-to-Peer Protocol for P2P cameras) used by Eye4/VStarcam IP cameras and the RTSP proxy server that bridges them to standard video clients.

---

## Table of Contents

### Part 1: Protocol
1. [Overview](#1-overview)
2. [Packet Framing](#2-packet-framing)
3. [Discovery](#3-discovery)
4. [Connection Handshake](#4-connection-handshake)
5. [P2P_Proprietary Cipher](#5-p2p_proprietary-cipher)
6. [Encryption Auto-Detection](#6-encryption-auto-detection)
7. [DRW Data Channel](#7-drw-data-channel)
8. [CGI Commands](#8-cgi-commands)
9. [STREAMHEAD](#9-streamhead)
10. [Video Framing](#10-video-framing)
11. [Audio Framing](#11-audio-framing)
12. [Critical Behaviors](#12-critical-behaviors)

### Part 2: Proxy Server
1. [Architecture](#13-architecture)
2. [RTSP Server](#14-rtsp-server)
3. [Snapshot HTTP Server](#15-snapshot-http-server)
4. [Frame Reassembly](#16-frame-reassembly)
5. [Motion Detection](#17-motion-detection)
6. [Multi-Camera](#18-multi-camera)
7. [State Machine](#19-state-machine)
8. [C Accelerator](#20-c-accelerator)
9. [Configuration](#21-configuration)
10. [Deployment](#22-deployment)

---

# Part 1: Protocol

## 1. Overview

Eye4/VStarcam cameras use a proprietary UDP-based protocol called **PPPP** (Peer-to-Peer Protocol for P2P cameras) for all communication. The cameras have no native RTSP server — video and audio are tunneled through PPPP's DRW data channel, with commands sent as HTTP-style CGI strings.

**Transport**: UDP, default port **32108** for discovery and initial handshake. After the handshake, the camera may switch DRW data to a different ephemeral port.

**Protocol layers** (outermost to innermost):

```
UDP:32108 (discovery) / dynamic (DRW data)
  → XOR obfuscation layer (control packets only)
    OR P2P_Proprietary cipher (DRW packets)
      → PPPP messages (LAN_SEARCH, LAN_NOTIFY, DRW, DRW_ACK, etc.)
        → DRW framing: F1 D0 [size16BE] D1 [ch] [idx16BE] [payload]
          → Channel 0: CGI commands (HTTP-style text)
          → Channel 1: STREAMHEAD + H.264/H.265 NAL units
          → Channel 2: STREAMHEAD + IMA ADPCM audio frames
```

Known camera prefixes and their UID formats: `VSTJ`, `VSTK`, `VSTL`, `VSTM`, `VSTN`, `VSTP`, `VSTG`, `VSTH`, `VSTC`, `VSTB`, `VC0`.

## 2. Packet Framing

Every PPPP packet starts with magic byte `0xF1` (after decryption/deobfuscation) followed by a message type byte.

### XOR Obfuscation Layer

Control/handshake packets use a 4-byte repeating XOR key applied to the entire packet:

```
XOR Key: 0x15 0xDB 0x43 0x22
```

The XOR is applied byte-by-byte, cycling through the key. The operation is its own inverse (encrypt = decrypt).

**Applies to**: LAN_SEARCH, LAN_NOTIFY, PUNCH_RSP, PUNCH_TO, PUNCH_PKT, and other control messages.

**Does NOT apply to**: DRW and DRW_ACK packets, which use the P2P_Proprietary cipher (see [Section 5](#5-p2p_proprietary-cipher)) or XOR-only mode depending on the camera model.

### Message Types

After XOR decoding (for control packets) or P2P decryption (for DRW packets), byte 1 identifies the message type:

| Type | Hex  | Name        | Direction      | Purpose                                    |
|------|------|-------------|----------------|--------------------------------------------|
| E0   | 0xE0 | LAN_SEARCH  | Client → Bcast | Discovery broadcast                        |
| 91   | 0x91 | LAN_NOTIFY  | Camera → Client | Discovery response with UID                |
| 92   | 0x92 | PUNCH_RSP   | Camera → Client | Handshake response                         |
| 30   | 0x30 | PUNCH_TO    | Camera → Client | NAT punch / port announcement              |
| 31   | 0x31 | PUNCH_PKT   | Client → Camera | Handshake acknowledgement                  |
| D0   | 0xD0 | DRW         | Bidirectional   | Data channel (video/audio/commands)        |
| D1   | 0xD1 | DRW_ACK     | Bidirectional   | Data channel acknowledgement               |
| 20   | 0x20 | CLOSE       | Camera → Client | Session close notification                 |

### General Packet Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Magic (0xF1) |  Message Type |       Payload Size (BE)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload ...                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Note: Control packets (LAN_SEARCH, PUNCH_PKT, etc.) may have a payload size of zero.

### Fast Type Detection

On the wire, the first two bytes of any packet are XOR-obfuscated. The proxy performs a fast 2-byte XOR to determine the message type without decoding the full packet:

```
xor_magic = data[0] ^ 0x15   // Must equal 0xF1
xor_type  = data[1] ^ 0xDB   // Message type
```

For P2P_Proprietary-encrypted DRW packets, XOR decoding yields type `0x00` (DRW) or `0x01` (DRW_ACK) — these are artifacts used solely for detection. True XOR-only DRW packets decode to `0xD0`/`0xD1`.

## 3. Discovery

### LAN_SEARCH (0xE0)

Broadcast by the client to UDP port **32108** on all network broadcast addresses. The packet is minimal — just the 4-byte header with no payload:

```
Raw (XOR-encoded): F5 3B 43 22
Decoded:           F1 E0 00 00
```

The client sends LAN_SEARCH 5 times at 1-second intervals to all detected broadcast addresses plus `255.255.255.255`. If a `--target-ip` is specified, a unicast LAN_SEARCH is also sent directly to that IP.

### LAN_NOTIFY (0x91)

Cameras respond with LAN_NOTIFY containing their 20-byte UID:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xF1         |  0x91         |       Payload Size (BE)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     UID (20 bytes)                             |
|                                                               |
|                                                               |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**UID format**: The 20-byte field may be ASCII (e.g., `VSTJ847204DZPJF\x00...`) or binary. The proxy checks for printable ASCII first; if not ASCII, it falls back to hex encoding for the stable identifier string.

**Handshake trigger**: The client echoes the raw LAN_NOTIFY packet back to the camera. This prompts the camera to initiate the PUNCH handshake sequence.

## 4. Connection Handshake

After discovering a camera via LAN_NOTIFY, the following handshake establishes a session:

```
Client                          Camera
  |                               |
  |--- LAN_SEARCH (broadcast) --->|
  |<-- LAN_NOTIFY (UID) ---------|
  |--- LAN_NOTIFY echo --------->|   (echo raw bytes back)
  |<-- PUNCH_RSP ----------------|   (may come from different port)
  |--- PUNCH_PKT --------------->|   (acknowledge)
  |<-- PUNCH_TO -----------------|   (announces DRW port)
  |--- PUNCH_PKT --------------->|   (acknowledge)
  |                               |
  |=== Session Established ======|
  |                               |
  |--- DRW (login CGI) --------->|   (command channel)
  |<-- DRW (status response) ----|
  |--- DRW (livestream CGI) ---->|   (start video)
  |--- DRW (audiostream CGI) --->|   (start audio)
  |<-- DRW (video data) ---------|   (channel 1, continuous)
  |<-- DRW (audio data) ---------|   (channel 2, continuous)
```

### PUNCH_RSP (0x92)

Sent by the camera after receiving the LAN_NOTIFY echo. May arrive from a different port than the discovery port. The client responds with PUNCH_PKT.

### PUNCH_TO (0x30)

Sent by the camera to announce the port it will use for DRW data. The client **must** respond with PUNCH_PKT to complete the handshake. If PUNCH_TO arrives for the active camera, the session is marked as connected and the DRW port is updated.

### PUNCH_PKT (0x31)

Sent by the client to acknowledge PUNCH_RSP and PUNCH_TO. This is a minimal control packet (header only, no payload). Multiple PUNCH_PKTs are sent to all known camera ports to ensure receipt.

### Port Tracking

The camera may use different UDP ports for different purposes:
- **Discovery port**: The source port of the initial LAN_NOTIFY response
- **DRW port**: May differ from the discovery port; locked to the first port from which DRW data is received

The proxy tracks all ports and sends keepalives to each.

## 5. P2P_Proprietary Cipher

DRW data packets are encrypted with a stateful stream cipher based on a 256-byte permutation table and a 4-byte key derived from a pre-shared key (PSK).

### PE Table

The cipher uses a fixed 256-byte permutation/entropy table (`P2P_PE_TABLE`):

```
7C 9C E8 4A 13 DE DC B2 2F 21 23 E4 30 7B 3D 8C
BC 0B 27 0C 3C F7 9A E7 08 71 96 00 97 85 EF C1
1F C4 DB A1 C2 EB D9 01 FA BA 3B 05 B8 15 87 83
28 72 D1 8B 5A D6 DA 93 58 FE AA CC 6E 1B F0 A3
88 AB 43 C0 0D B5 45 38 4F 50 22 66 20 7F 07 5B
14 98 1D 9B A7 2A B9 A8 CB F1 FC 49 47 06 3E B1
0E 04 3A 94 5E EE 54 11 34 DD 4D F9 EC C7 C9 E3
78 1A 6F 70 6B A4 BD A9 5D D5 F8 E5 BB 26 AF 42
37 D8 E1 02 0A AE 5F 1C C5 73 09 4E 69 24 90 6D
12 B3 19 AD 74 8A 29 40 F5 2D BE A5 59 E0 F4 79
D2 4B CE 89 82 48 84 25 C6 91 2B A2 FB 8F E9 A6
B0 9E 3F 65 F6 03 31 2E AC 0F 95 2C 5C ED 39 B7
33 6C 56 7E B4 A0 FD 7A 81 53 51 86 8D 9F 77 FF
6A 80 DF E2 BF 10 D7 75 64 57 76 F3 55 CD D0 C8
18 E6 36 41 62 CF 99 F2 32 4C 67 60 61 92 CA D3
EA 63 7D 16 B6 8E D4 68 35 C3 52 9D 46 44 1E 17
```

### PSK Derivation

The 4-byte cipher key `key4` is derived from the PSK string:

```
k0 = sum(all PSK bytes) & 0xFF
k1 = (-k0) & 0xFF            // two's complement
k2 = sum(each PSK byte // 3) & 0xFF
k3 = XOR of all PSK bytes
```

### Known PSKs

| PSK String       | key4 (hex)   | Camera Prefixes               |
|-------------------|-------------|-------------------------------|
| `vstarcam2019`   | `2D D3 61 07` | VSTJ, VSTK, VSTL, VSTM, VSTN, VSTP, VC0 |
| `vstarcam2018`   | `1C E4 58 16` | VSTG, VSTH, ELSC             |
| *(empty string)* | `00 00 00 00` | VSTC, VSTB                   |

### Per-Byte Algorithm

The cipher builds 4 lookup tables (one per key byte), where:

```
tables[k][prev] = PE_TABLE[(key4[k] + prev) & 0xFF]
```

**Decrypt**: For each byte at position `i` with ciphertext byte `c`:
```
plaintext[i] = c XOR tables[prev & 3][prev]
prev = c                    // feedback uses CIPHERTEXT
```

**Encrypt**: For each byte at position `i` with plaintext byte `p`:
```
c = p XOR tables[prev & 3][prev]
ciphertext[i] = c
prev = c                    // feedback uses CIPHERTEXT
```

Both directions start with `prev = 0`.

### Merged Table Optimization

For performance, the 4 x 256 tables are collapsed into a single 256-byte merged table:

```
merged[i] = PE_TABLE[(key4[i & 3] + i) & 0xFF]
```

The decrypt loop becomes:
```
out[i] = in[i] ^ merged[prev]
prev = in[i]
```

This merged table is used by both the C accelerator and the Python fast path.

## 6. Encryption Auto-Detection

When the encryption mode is not explicitly configured, the proxy auto-detects by trial:

1. For each known PSK (in order: `vstarcam2019`, `vstarcam2018`, empty):
   a. Re-establish the PPPP session (echo LAN_NOTIFY, wait for PUNCH)
   b. Build a login DRW packet encrypted with the trial PSK
   c. Send it to the camera and wait up to 2 seconds for any DRW/DRW_ACK response
   d. Try decrypting the response — if it produces a valid PPPP header (`0xF1` magic + `0xD0`/`0xD1` type), the PSK is confirmed

2. After P2P modes, try **XOR-only** mode (simple XOR with no P2P cipher) as a final fallback

3. If no mode succeeds, log an error with suggestions for manual `--psk` or `--enc-mode` flags

The detection distinguishes P2P-encrypted packets from XOR-only packets by examining the message type after a 2-byte XOR decode:
- Type `0x00` / `0x01` → P2P-encrypted DRW/DRW_ACK
- Type `0xD0` / `0xD1` → XOR-only DRW/DRW_ACK

## 7. DRW Data Channel

### DRW Packet Format (0xD0)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xF1 (magic) |  0xD0 (DRW)   |    Inner Payload Size (BE)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xD1 (inner) |    Channel    |      Packet Index (BE)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Data ...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Inner magic**: Always `0xD1` — this is the same value as DRW_ACK's outer type, which is counterintuitive but confirmed from packet captures.
- **Channel**: Identifies the data stream (see below)
- **Packet Index**: 16-bit big-endian sequence number, per-channel, wraps at 65535

### Channels

| Channel | ID | Content |
|---------|----|---------|
| Command | 0  | CGI command text (login, video start, status queries) |
| Video   | 1  | STREAMHEAD + H.264/H.265 NAL unit data |
| Audio   | 2  | STREAMHEAD + IMA ADPCM audio frame data |
| Control | 5  | Keepalive / miscellaneous |

### DRW_ACK Packet Format (0xD1)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xF1 (magic) |  0xD1 (ACK)   |    Inner Payload Size (BE)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xD1 (inner) |    Channel    |      ACK Count (BE)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Acked Index (BE)         |     [more indices ...]        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Inner magic**: `0xD1` (**CRITICAL**: same as DRW inner magic — using `0xD2` kills video streaming)
- **ACK Count**: Number of packet indices being acknowledged (usually 1)
- **Acked Index**: 16-bit BE index of the acknowledged DRW packet

ACKs must be sent immediately for every received DRW packet, even retransmissions.

### Index Tracking and Deduplication

- Each channel maintains a set of seen indices for deduplication
- ACKs are sent for all received packets (including duplicates), but only new indices are processed
- **Wraparound handling**: When the high-water index is > 49152 and a new index is < 16384, the dedup set is cleared (16-bit wraparound at ~65535)
- Safety pruning: if the dedup set exceeds 16384 entries, old entries are removed

### Encryption of DRW Packets

DRW/DRW_ACK packets are encrypted as a whole (header + inner payload) using either:
- **P2P_Proprietary cipher**: Full packet encrypted with the P2P stream cipher (most cameras)
- **XOR-only**: Full packet XOR-obfuscated with the 4-byte key (VSTC/VSTB/VC0 in some firmware)

The encryption mode is determined per-session (see [Section 6](#6-encryption-auto-detection)).

## 8. CGI Commands

Commands are sent to the camera via DRW on channel 0 (CH_CMD). Each command is an HTTP-style CGI string wrapped in a binary envelope.

### CGI Envelope

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0x01         |  0x0A         |  0x00         |  0x00         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               CGI Text Length (LE 32-bit)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     CGI Text (ASCII) ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Preamble**: Fixed 4 bytes `01 0A 00 00`
- **Length**: 32-bit little-endian length of the CGI text that follows
- Multiple CGI commands can be packed into a single DRW payload by concatenating multiple envelopes

### CGI Strings

All CGI strings follow HTTP GET format with authentication parameters:

**Login / Status Query**:
```
GET /get_status.cgi?loginuse=admin&loginpas=888888&user=admin&pwd=888888&
```

**Start Video Stream**:
```
GET /livestream.cgi?streamid=10&substream=1&loginuse=admin&loginpas=888888&user=admin&pwd=888888&
```

**Start Audio Stream** (must be requested separately from video):
```
GET /audiostream.cgi?streamid=10&loginuse=admin&loginpas=888888&user=admin&pwd=888888&
```

**Set Alarm Server**:
```
GET /set_factory_param.cgi?alarm_server=http://host:port&loginuse=admin&loginpas=888888&user=admin&pwd=888888&
```

### CGI Responses

Camera responses arrive on channel 0 with the same `01 0A` preamble (or as raw continuation text). Responses contain key=value pairs like:
```
result=0
deviceid=VSTJ847204DZPJF
realdeviceid=VC0235454WXHW
sys_ver=48.88.180.11
alarm_status=0
```

## 9. STREAMHEAD

Both video and audio data are prefixed with a 32-byte header called **STREAMHEAD**, identified by the magic bytes `55 AA 15 A8` (little-endian `0xA815AA55`).

### STREAMHEAD Layout (32 bytes)

```
Offset  Size  Field             Description
──────  ────  ────────────────  ─────────────────────────────────────
 0      4     Magic             55 AA 15 A8 (LE: 0xA815AA55)
 4      1     Frame Type        0x10=I-frame, 0x11=P-frame, 0x06=audio
 5      1     Codec/Stream      Video: codec ID; Audio: see table below
 6      2     Milliseconds      Timestamp millisecond part (LE 16-bit)
 8      4     Seconds           Timestamp seconds part (LE 32-bit)
12      4     (Reserved)
16      4     Frame Data Length  Payload size after header (LE 32-bit)
20      12    (Reserved/flags)
```

Full timestamp = `seconds * 1000 + milliseconds`.

### Frame Type Byte (offset 4)

| Value | Meaning |
|-------|---------|
| 0x10  | I-frame (keyframe) — video |
| 0x11  | P-frame — video |
| 0x06  | Audio frame |

### Audio Codec Byte (offset 5)

| Value | Codec |
|-------|-------|
| 0x00  | Raw PCM 16-bit signed LE |
| 0x01  | IMA ADPCM |
| 0x02  | G.711 a-law (PCMA) |
| 0x03  | G.711 u-law (PCMU) |

## 10. Video Framing

### Codec Detection

Video data (channel 1) consists of concatenated NAL units with standard start codes (`00 00 00 01` or `00 00 01`). The proxy detects the codec from NAL header bytes:

**H.264**: NAL type = `byte[0] & 0x1F`
- Type 7 = SPS → locks codec to H.264
- Type 8 = PPS

**H.265/HEVC**: NAL header is 2 bytes, type = `(byte[0] >> 1) & 0x3F`
- Additional validation: `byte[0] & 0x81 == 0` (forbidden=0, layer_id MSB=0) and `byte[1] & 0x07 == 1` (temporal_id_plus1=1)
- Type 32 = VPS → locks codec to H.265
- Type 33 = SPS
- Type 34 = PPS

Once the codec is locked (first VPS for HEVC or first SPS for H.264), it cannot switch. This prevents false HEVC detection when an H.264 NAL byte coincidentally matches the HEVC type check.

### AES-ECB Layer (Optional)

Some cameras additionally encrypt video with AES-128-ECB. The key is derived from the camera UID and password:

```python
key = MD5(uid + password)   # 16 bytes
```

Decryption is applied only to the 16-byte-aligned portion of the frame data; any trailing bytes (< 16) are passed through unmodified. This layer is applied *after* P2P_Proprietary decryption, between STREAMHEAD parsing and NAL extraction.

In practice, the tested cameras (VSTJ/VC0 prefix) do **not** use AES encryption — video arrives as raw NALs after P2P decryption.

### Video Data Flow

```
DRW channel 1 → VideoReassembly buffer
  → scan for STREAMHEAD magic (55 AA 15 A8)
    → extract frame type + length from header
      → accumulate payload bytes until length satisfied
        → emit complete frame → extract SPS/PPS/VPS
          → push to RTSP server frame queue
```

## 11. Audio Framing

### Wire Format

Audio data arrives on DRW channel 2, prefixed by a STREAMHEAD. The codec is identified by STREAMHEAD byte 5 (see [Section 9](#9-streamhead)).

### IMA ADPCM

The most common audio codec on these cameras. Key characteristics:

- **4 bits per sample**, 2 samples per byte
- **HIGH nibble first**: Each byte encodes `(byte >> 4) & 0x0F` then `byte & 0x0F` — this is non-standard (most IMA ADPCM implementations use low nibble first)
- **Per-frame state reset**: The camera resets ADPCM predictor to 0 and step index to 0 at each frame boundary. There are no block headers — the reset is implicit. Carrying state across frames causes severe decoder divergence (DC drift)
- **Frame size**: 512 bytes of ADPCM = 1024 PCM samples = 128ms at 8kHz
- **Sample rate**: 8000 Hz, mono

### ADPCM Decode Algorithm

Standard IMA ADPCM with the high-nibble-first modification:

```
for each byte in frame:
    for nibble in (high_nibble, low_nibble):
        step = step_table[index]
        diff = step >> 3
        if nibble & 1: diff += step >> 2
        if nibble & 2: diff += step >> 1
        if nibble & 4: diff += step
        if nibble & 8: predicted -= diff
        else:          predicted += diff
        clamp predicted to [-32768, 32767]
        index += index_table[nibble]
        clamp index to [0, 88]
        emit predicted as 16-bit sample
```

### Audio Output Pipeline

```
IMA ADPCM (512 bytes)
  → decode to PCM 16-bit signed LE (1024 samples)
    → byte-swap LE → BE (network byte order)
      → RTP L16/8000/1 (payload type 97)
```

For G.711 a-law or u-law, the data passes through unchanged to RTP with the appropriate static payload type (8 for PCMA, 0 for PCMU).

## 12. Critical Behaviors

These protocol details were discovered through extensive debugging and are essential for correct operation:

### DRW_ACK Inner Magic Must Be 0xD1

The inner magic byte of DRW_ACK packets **must** be `0xD1` — the same value as DRW's inner magic. Using `0xD2` (which might seem logical for "ACK") causes the camera to stop streaming video entirely.

### Camera Tracks Sessions by UDP Source Port

The camera associates a session with the client's UDP source port. To restart a session (e.g., after connection loss), a **new UDP socket** must be created. Reusing the old socket with the same source port will not work — the camera ignores the connection attempt.

### streamid=10 Required

The video start CGI must use `streamid=10` for the main stream. `streamid=0` does **not** trigger video on these cameras (VStarcam VSTJ/VC0 firmware).

### Audio Must Be Requested Separately

Video (`/livestream.cgi`) and audio (`/audiostream.cgi`) must be requested as separate CGI commands. The camera treats them as independent streams. The native Eye4 app calls `PPPPStartAudio()` separately.

### Audio DRW Index Reset

When audio is re-requested, the camera restarts DRW indices from 0. The proxy must clear the audio channel's dedup set and reset `AudioReassembly` to avoid dropping all new packets as duplicates of old indices.

### Camera CLOSE (0x20) Debounce

The camera may send a CLOSE (0x20) packet from subsidiary ports while DRW data is still flowing on the main port. The proxy ignores CLOSE if DRW data was received within the last 5 seconds.

### Keepalive

The proxy sends PUNCH_PKT to all known camera ports (discovery, current, DRW) every 2 seconds to keep the session alive.

### Video Keepalive

If no DRW data is received for 2+ seconds, the proxy re-requests video and audio on the existing session. After 10+ seconds with no data despite 2+ re-requests, it triggers a full reconnect (new UDP socket).

---

# Part 2: Proxy Server

## 13. Architecture

The proxy is a single-file (~3400 lines) async Python 3 application (`eye4_rtsp_proxy.py`). It uses `asyncio` for all I/O — no threads.

### Class Overview

| Class | Purpose |
|-------|---------|
| **PPPPUnifiedProtocol** | `asyncio.DatagramProtocol` subclass. Handles one camera's full UDP lifecycle: discovery, handshake, encryption detection, DRW send/receive, ACK generation, CGI commands, keepalive. |
| **CameraSession** | Per-camera orchestrator. Owns a `PPPPUnifiedProtocol` + `RTSPServer` pair. Manages the connection state machine and auto-reconnect loop. |
| **RTSPServer** | Minimal RTSP 1.0 server. Accepts TCP clients, generates SDP, pushes RTP-interleaved video + audio. Caches the last I-frame for instant client start. |
| **RTSPClient** | Per-connection RTSP handler. Processes OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN. Manages interleaved RTP channels. |
| **VideoReassembly** | Accumulates DRW video payloads, scans for STREAMHEAD boundaries, emits complete video frames. |
| **AudioReassembly** | Accumulates DRW audio payloads with a reorder buffer, scans for STREAMHEAD, decodes ADPCM, emits PCM frames. |
| **CameraInfo** | Data class for discovered camera info (IP, port, UID). |
| **MotionHandler** | Per-camera motion state manager. Polls alarm_status, triggers webhook calls with cooldown. |

### Data Flow

```
Camera UDP ──→ PPPPUnifiedProtocol
                 ├── decrypt DRW
                 ├── send ACK
                 ├── dispatch by channel
                 │    ├── CH_CMD(0): parse CGI response
                 │    ├── CH_VIDEO(1): → VideoReassembly
                 │    │                    └── emit frame → RTSPServer.push_video_frame()
                 │    └── CH_AUDIO(2): → AudioReassembly
                 │                         └── decode ADPCM → RTSPServer.push_audio_frame()
                 └── keepalive

RTSPServer
  ├── TCP listener → RTSPClient handlers
  ├── frame queue → _frame_sender task → RTP packetize → send to clients
  ├── audio queue → _audio_sender task → RTP packetize → send to clients
  └── snapshot HTTP server (port + 1000)
```

## 14. RTSP Server

### Supported Methods

| Method   | Behavior |
|----------|----------|
| OPTIONS  | Returns `Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN` |
| DESCRIBE | Returns SDP with video + audio media descriptions |
| SETUP    | Configures RTP/TCP interleaved transport (UDP returns 461) |
| PLAY     | Starts streaming; triggers audio re-request to camera |
| TEARDOWN | Stops streaming, closes connection |

### SDP Generation

The SDP is dynamically generated based on detected codec and parameter sets:

**H.264**:
```
v=0
o=- <timestamp> 1 IN IP4 <server_ip>
s=Eye4 Camera
t=0 0
m=video 0 RTP/AVP 96
c=IN IP4 0.0.0.0
a=rtpmap:96 H264/90000
a=fmtp:96 packetization-mode=1;profile-level-id=<from SPS>;sprop-parameter-sets=<SPS_b64>,<PPS_b64>
a=control:streamid=0
m=audio 0 RTP/AVP 97
c=IN IP4 0.0.0.0
a=rtpmap:97 L16/8000/1
a=control:streamid=1
```

**H.265/HEVC**:
```
a=rtpmap:96 H265/90000
a=fmtp:96 sprop-vps=<VPS_b64>; sprop-sps=<SPS_b64>; sprop-pps=<PPS_b64>
```

Audio SDP varies by detected codec:
- ADPCM → decoded to L16, dynamic PT 97: `a=rtpmap:97 L16/8000/1`
- G.711 a-law: static PT 8, `a=rtpmap:8 PCMA/8000`
- G.711 u-law: static PT 0, `a=rtpmap:0 PCMU/8000`

### RTP Packetization

All RTP is sent via **TCP interleaved** mode (RTSP over TCP with `$` framing). UDP transport is not supported — the server returns 461 Unsupported Transport.

**Interleaved framing**:
```
0x24 | channel (1 byte) | length (2 bytes BE) | RTP packet
```

Default channel assignments:
- Video RTP: channel 0, RTCP: channel 1
- Audio RTP: channel 2, RTCP: channel 3

(Clients may override via SETUP Transport header.)

**H.264 FU-A** (RFC 6184): NALs > 1400 bytes are fragmented. Each fragment has a 2-byte FU header (FU indicator + FU header with S/E bits).

**HEVC FU** (RFC 7798): NALs > 1400 bytes are fragmented. Each fragment has a 3-byte FU header (2-byte FU indicator preserving F/LayerId/TID + 1-byte FU header with S/E bits and NAL type).

NALs ≤ 1400 bytes are sent as single NAL unit packets.

### I-Frame Caching

The server always caches the most recent I-frame, even when no clients are connected. When a new client sends PLAY:
1. `got_iframe` is set to false
2. The client receives either the next live I-frame or the cached I-frame (whichever comes first)
3. P-frames are only sent after the client has received an I-frame

This ensures instant video start without waiting for the camera's next keyframe interval.

### Batched RTP Writes

For each video frame, all NAL units are packetized into RTP packets, then written to each client in a single batch with one `drain()` call per client. This reduces event-loop overhead from dozens of yields per frame to one.

## 15. Snapshot HTTP Server

Each camera's RTSP server also runs a simple HTTP server on **RTSP port + 1000** (e.g., port 10555 if RTSP is on 9555).

**Endpoint**: `GET /snapshot.jpg`

**Process**:
1. Retrieve the cached I-frame + SPS + PPS from the RTSP server
2. Build a raw H.264 byte stream: `[start_code][SPS][start_code][PPS][I-frame data]`
3. Pipe through `ffmpeg -f h264 -i pipe:0 -frames:v 1 -f image2 -c:v mjpeg -q:v 5 pipe:1`
4. Return the JPEG with `Content-Type: image/jpeg`

Returns 503 if no I-frame is cached, 500 if ffmpeg conversion fails.

The bind address for the snapshot server is configurable via `snapshot_bind_addr` (default `0.0.0.0`).

## 16. Frame Reassembly

### VideoReassembly

Accumulates DRW video payloads (channel 1) into a single buffer and scans for STREAMHEAD boundaries:

1. Append incoming DRW payload to buffer
2. Search for STREAMHEAD magic (`55 AA 15 A8`) using `bytearray.find()` (C-speed)
3. Parse 32-byte header: extract frame type, timestamp, and frame data length
4. Accumulate bytes until `frame_data_length` is satisfied
5. Emit complete frame via callback
6. Buffer compaction: when read offset exceeds 64KB, delete consumed bytes

Video DRW packets are fed in index order (as received after dedup). No reorder buffer is used for video — UDP packet reordering is rare for video due to high throughput.

### AudioReassembly

Audio uses the same STREAMHEAD-based reassembly but adds a **reorder buffer** (window size = 8) to handle out-of-order UDP delivery:

1. Incoming packets are checked against `_next_expected_idx`
2. **In-order**: Fed directly to reassembly, then consecutive buffered followers are flushed
3. **Future**: Stored in reorder buffer (dict: index → data)
4. **Past/duplicate**: Discarded
5. **Gap**: If reorder buffer reaches window size, the proxy skips to the lowest buffered index. Any partial audio frame is discarded to avoid corrupt audio.

Orphan data (bytes before a STREAMHEAD, or data with no STREAMHEAD found) is discarded rather than decoded, to prevent audible clicks/ticks.

## 17. Motion Detection

Motion detection works by polling the camera's `alarm_status` field via the DRW command channel.

### Polling

- The proxy sends `GET /get_status.cgi?...` every `motion_poll_interval` seconds (default: 1s)
- The camera response includes `alarm_status=N` where N changes from 0 to non-zero on motion

### Webhook Integration

When `alarm_status` changes from 0 to non-zero:
1. `MotionHandler` sends HTTP POST to `{motion_webhook}/turnOn`
2. A cooldown timer starts (default: 30 seconds)
3. If another alarm event occurs during cooldown, the timer resets
4. When cooldown expires without new events, sends POST to `{motion_webhook}/turnOff`

The webhook URL is designed for Scrypted virtual motion sensor integration but works with any HTTP endpoint that accepts POST to `turnOn`/`turnOff` paths.

### Configuration

Motion detection is configured per-camera in the YAML config:

```yaml
cameras:
  VSTJ847204DZPJF:
    port: 9555
    motion_webhook: "http://scrypted:10443/endpoint/@scrypted/webhook/turnOnOff/xyz"
```

## 18. Multi-Camera

### Discovery Loop

1. **Initial discovery**: Broadcast LAN_SEARCH, wait `discovery_time` seconds (default 3)
2. **Session creation**: For each discovered camera, assign an RTSP port and start a `CameraSession`
3. **Periodic re-discovery**: Every 30 seconds, re-broadcast and start sessions for any new cameras

### Port Assignment

RTSP ports are auto-assigned starting from `base_port` (default 9555):
- First camera: 9555
- Second camera: 9556
- Third camera: 9557

Assigned ports are saved to the config file and reused on restart. Per-camera config can override the port.

Each camera also gets:
- Snapshot HTTP server: RTSP port + 1000 (e.g., 10555)

### Session Independence

Each `CameraSession` has its own:
- UDP socket (PPPPUnifiedProtocol instance)
- RTSP TCP server
- Reconnect loop
- Motion detection handler (if configured)

Sessions operate independently — one camera going offline does not affect others.

## 19. State Machine

Each `CameraSession` follows this state machine:

```
                        ┌──────────┐
                        │ STOPPED  │
                        └────┬─────┘
                             │ start()
                        ┌────▼─────┐
                        │CONNECTING│
                        └────┬─────┘
                             │ connected
            data resumes     │
          ┌─────────────┌────▼─────┐
          │             │CONNECTED │◄────────────┐
          │             └────┬─────┘             │
          │                  │ no data 5s        │ data resumes
          │             ┌────▼─────┐             │
          └─────────────│  STALE   │─────────────┘
                        └────┬─────┘
                             │ no data 15s
                        ┌────▼─────┐
                        │ OFFLINE  │
                        └────┬─────┘
                             │ teardown protocol
                        ┌────▼────────┐
                        │RECONNECTING │──── camera found ──→ CONNECTED
                        └─────────────┘
                             │ camera not found
                             └──── retry in ~10s ──→ RECONNECTING
```

**Timing**:
- **CONNECTED → STALE**: No DRW data for 5 seconds. Re-requests video stream.
- **STALE → OFFLINE**: No DRW data for 15 seconds. Tears down protocol.
- **STALE → CONNECTED**: Data resumes within 15 seconds.
- **RECONNECTING**: Probes every 10 seconds (5s reconnect loop sleep + 5s backoff on failure). Creates fresh discovery probe, checks if camera responds, creates new session if found.
- **Reconnect loop**: Checks every 5 seconds.

## 20. C Accelerator

Performance-critical functions are implemented in C (`eye4_accel.c`) and loaded at runtime via `ctypes`.

### Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `p2p_decrypt` | `(table, in, out, len)` | P2P_Proprietary stream cipher decrypt |
| `p2p_encrypt` | `(table, in, out, len)` | P2P_Proprietary stream cipher encrypt |
| `decode_adpcm` | `(data, len, out)` | IMA ADPCM → PCM 16-bit (high nibble first, per-frame reset) |
| `byteswap16` | `(in, out, len)` | Pairwise byte swap for LE↔BE conversion |

### Compilation

```bash
gcc -O2 -shared -fPIC -o eye4_accel.so eye4_accel.c
```

### Loading

The proxy searches for `eye4_accel.so` in three directories:
1. Same directory as `eye4_rtsp_proxy.py`
2. `/app` (Docker container path)
3. Current working directory

If found, function prototypes are registered via `ctypes`. If not found (or loading fails), the proxy falls back to pure Python implementations with no functional difference.

A reusable `ctypes` char buffer is maintained to avoid per-call allocation overhead.

## 21. Configuration

### Config File

Path: `/etc/eye4_rtsp_proxy.yml` (default, override with `--config`)

Format: YAML. Auto-created on first camera discovery.

### Settings Table

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `username` | string | `admin` | Camera login username |
| `password` | string | `888888` | Camera login password |
| `base_port` | int | `9555` | Starting RTSP port (auto-increments per camera) |
| `discovery_time` | int | `3` | Seconds to wait for camera discovery broadcasts |
| `verbose` | bool | `false` | Enable debug-level logging |
| `log_level` | string | `info` | Log level: debug, info, warning, error |
| `psk` | string | `vstarcam2019` | P2P pre-shared key for encryption |
| `enc_mode` | string | `auto` | Encryption mode: `auto`, `p2p`, or `xor` |
| `alarm_server_port` | int | `0` | HTTP port for camera alarm listener (0 = disabled) |
| `alarm_server_addr` | string | `""` | IP:port cameras should send alarms to |
| `motion_cooldown` | int | `30` | Seconds to keep motion ON after last alarm event |
| `motion_poll_interval` | int | `1` | Seconds between alarm_status polls |
| `snapshot_bind_addr` | string | `0.0.0.0` | Bind address for snapshot HTTP server |
| `cameras` | dict | `{}` | Camera UID → port mapping (auto-populated) |

### Camera-Specific Config

Each camera UID in the `cameras` dict can be an integer (port only) or a dict:

```yaml
cameras:
  VSTJ847204DZPJF:
    port: 9555
    motion_webhook: "http://scrypted:10443/endpoint/@scrypted/webhook/turnOnOff/xyz"
  VSTJ847204ABCDE: 9556   # port only, no motion webhook
```

### CLI Arguments

| Flag | Config Key | Description |
|------|-----------|-------------|
| `-u`, `--username` | `username` | Camera username |
| `-p`, `--password` | `password` | Camera password |
| `--base-port` | `base_port` | RTSP base port |
| `--discovery-time` | `discovery_time` | Discovery timeout (seconds) |
| `-v`, `--verbose` | `verbose` | Debug logging |
| `--target-ip` | *(none)* | Skip broadcast, send directly to IP |
| `--diag` | *(none)* | Run network diagnostics only |
| `--psk` | `psk` | P2P encryption PSK |
| `--enc-mode` | `enc_mode` | `xor`, `p2p`, or `auto` |
| `--alarm-port` | `alarm_server_port` | Camera alarm HTTP listener port |
| `--alarm-addr` | `alarm_server_addr` | Alarm listener address |
| `--motion-cooldown` | `motion_cooldown` | Motion cooldown seconds |
| `--config` | *(none)* | Config file path (default: `/etc/eye4_rtsp_proxy.yml`) |

### Precedence

CLI arguments override config file values. Config file values override built-in defaults.

## 22. Deployment

### Dockerfile

Multi-stage Alpine-based build:

```dockerfile
# Stage 1: Compile C accelerator
FROM python:3.12-alpine AS builder
RUN apk add --no-cache gcc musl-dev
COPY eye4_accel.c /build/
RUN gcc -O2 -shared -fPIC -o /build/eye4_accel.so /build/eye4_accel.c

# Stage 2: Runtime
FROM python:3.12-alpine
RUN apk add --no-cache ffmpeg && pip install --no-cache-dir pycryptodome pyyaml
COPY --from=builder /build/eye4_accel.so /app/
COPY eye4_rtsp_proxy.py /app/
WORKDIR /app
CMD ["python3", "eye4_rtsp_proxy.py"]
```

Image size: ~74MB.

### Docker Compose

```yaml
services:
  eye4-proxy:
    image: hmchan/eye4-proxy:latest
    network_mode: host           # Required for UDP broadcast discovery
    restart: unless-stopped
    volumes:
      - /etc/eye4_rtsp_proxy.yml:/etc/eye4_rtsp_proxy.yml:ro
```

**`network_mode: host` is required** — the proxy uses UDP broadcast for camera discovery and receives responses on ephemeral ports. Bridge networking would block these broadcasts.

### Build and Deploy

```bash
# Build image
docker build -t hmchan/eye4-proxy:latest .

# Run directly
docker run --network host -v /etc/eye4_rtsp_proxy.yml:/etc/eye4_rtsp_proxy.yml:ro hmchan/eye4-proxy:latest

# With Docker Compose
docker compose up -d
```

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `pycryptodome` | Yes | AES-ECB video decryption (if cameras use it) |
| `pyyaml` | Optional | Config file parsing (falls back to defaults without it) |
| `netifaces` | Optional | Network interface enumeration (falls back to IP guessing) |
| `ffmpeg` | Optional | Snapshot JPEG conversion (binary, not Python package) |
