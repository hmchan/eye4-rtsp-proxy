#!/usr/bin/env python3
"""
Eye4 Camera RTSP Proxy

Discovers Eye4/VStarcam cameras (VC0 prefix) on the LAN via the PPPP protocol,
establishes a P2P session, receives and decrypts H.264 video, and re-serves it
as a standard RTSP stream consumable by VLC, ffmpeg, etc.

Usage:
    python3 eye4_rtsp_proxy.py --username admin --password 888888
    # Then connect with: vlc rtsp://localhost:8554/

Dependencies: pycryptodome (pip install pycryptodome)
"""

import argparse
import asyncio
import hashlib
import logging
import random
import re
import socket
import struct
import time
import urllib.request
import urllib.parse
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    from Crypto.Cipher import AES
    HAS_AES = True
except ImportError:
    HAS_AES = False

# C accelerator for hot-path functions (p2p cipher, ADPCM decode, byte-swap)
import ctypes
import ctypes.util
import os as _os
import array as _array

_accel = None
try:
    _so_dirs = [
        _os.path.dirname(_os.path.abspath(__file__)),
        "/app",
        ".",
    ]
    for _d in _so_dirs:
        _so_path = _os.path.join(_d, "eye4_accel.so")
        if _os.path.isfile(_so_path):
            _accel = ctypes.CDLL(_so_path)
            break
    if _accel is not None:
        _accel.p2p_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _accel.p2p_decrypt.restype = None
        _accel.p2p_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _accel.p2p_encrypt.restype = None
        _accel.decode_adpcm.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int16)]
        _accel.decode_adpcm.restype = None
        _accel.byteswap16.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _accel.byteswap16.restype = None
except Exception:
    _accel = None

HAS_ACCEL = _accel is not None

log = logging.getLogger("eye4")

# =============================================================================
# Config File Support (YAML)
# =============================================================================

DEFAULT_CONFIG_PATH = "/etc/eye4_rtsp_proxy.yml"

DEFAULT_CONFIG = {
    "username": "admin",
    "password": "888888",
    "base_port": 9555,
    "discovery_time": 3,
    "verbose": False,
    "log_level": "info",
    "psk": "vstarcam2019",
    "enc_mode": "auto",
    "alarm_server_port": 0,
    "alarm_server_addr": "",
    "motion_cooldown": 30,
    "motion_poll_interval": 1,
    "bind_addr": "127.0.0.1",
    "cameras": {},
}


def load_config(path: str) -> dict:
    """Load config from YAML file, returning defaults if file doesn't exist."""
    config = dict(DEFAULT_CONFIG)
    config["cameras"] = dict(DEFAULT_CONFIG["cameras"])
    if not HAS_YAML:
        log.warning("PyYAML not installed — using defaults (pip install pyyaml)")
        return config
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            for key in DEFAULT_CONFIG:
                if key in data:
                    config[key] = data[key]
            if not isinstance(config["cameras"], dict):
                config["cameras"] = {}
            log.info("Loaded config from %s (%d camera mappings)", path, len(config["cameras"]))
        else:
            log.warning("Config file %s has invalid format, using defaults", path)
    except FileNotFoundError:
        log.info("Config file %s not found, will create on first discovery", path)
    except Exception as e:
        log.warning("Error reading config %s: %s — using defaults", path, e)
    return config


def save_config(path: str, config: dict):
    """Write config to YAML file."""
    if not HAS_YAML:
        log.warning("PyYAML not installed — cannot save config")
        return
    try:
        data = {}
        for key in DEFAULT_CONFIG:
            if key in config:
                data[key] = config[key]
        with open(path, "w") as f:
            f.write("# Eye4 Camera RTSP Proxy Configuration\n")
            f.write("# Auto-generated — edit as needed\n\n")
            # Write scalar settings first
            for key in ["username", "password", "base_port", "discovery_time", "verbose", "log_level", "psk", "enc_mode",
                        "alarm_server_port", "alarm_server_addr", "motion_cooldown", "motion_poll_interval",
                        "bind_addr"]:
                if key in data:
                    yaml.dump({key: data[key]}, f, default_flow_style=False)
            # Write camera mappings
            f.write("\n# Camera UID → RTSP port mappings (auto-populated on discovery)\n")
            yaml.dump({"cameras": data.get("cameras", {})}, f, default_flow_style=False)
        log.info("Saved config to %s", path)
    except PermissionError:
        log.warning("Permission denied writing %s — try running as root or change --config path", path)
    except Exception as e:
        log.warning("Error saving config to %s: %s", path, e)


def _get_camera_port(cam_cfg) -> Optional[int]:
    """Extract port from a camera config value (int or dict with 'port' key)."""
    if isinstance(cam_cfg, int):
        return cam_cfg
    if isinstance(cam_cfg, dict):
        return cam_cfg.get("port")
    return None


def assign_port(config: dict, camera_uid: str, base_port: int) -> int:
    """Assign an RTSP port for a camera UID. Returns existing or next available port."""
    cameras = config.get("cameras", {})
    if camera_uid in cameras:
        existing = _get_camera_port(cameras[camera_uid])
        if existing is not None:
            return existing
    used_ports = {_get_camera_port(v) for v in cameras.values()} - {None}
    port = base_port
    while port in used_ports:
        port += 1
    # Preserve dict config if it exists (has motion_webhook etc), otherwise store int
    if isinstance(cameras.get(camera_uid), dict):
        cameras[camera_uid]["port"] = port
    else:
        cameras[camera_uid] = port
    config["cameras"] = cameras
    return port


def uid_from_bytes(uid_bytes: bytes) -> str:
    """Convert raw UID bytes from LAN_NOTIFY to a stable identifier string.
    The 20-byte binary DID is not ASCII — use hex, but check for ASCII first
    in case some cameras send plain text UIDs."""
    # Check if bytes are printable ASCII (some cameras do send plain text)
    try:
        text = uid_bytes.split(b'\x00', 1)[0].decode('ascii')
        if text and all(0x20 <= ord(c) < 0x7F for c in text):
            return text
    except (UnicodeDecodeError, ValueError):
        pass
    # Binary DID — use hex (last 12 bytes vary per camera, first 8 are prefix)
    return uid_bytes.hex()


# =============================================================================
# Module 1: XOR Obfuscation Layer (for control/handshake packets only)
# =============================================================================

XOR_KEY = bytes([0x15, 0xDB, 0x43, 0x22])


def xor_obfuscate(data: bytes) -> bytes:
    """Apply/remove the 4-byte repeating XOR obfuscation on PPPP control packets."""
    n = len(data)
    if n == 0:
        return data
    # Use int.from_bytes/to_bytes for bulk XOR (processes 8 bytes at a time via Python bigint)
    key = XOR_KEY * (n // 4 + 1)
    return (int.from_bytes(data, 'big') ^ int.from_bytes(key[:n], 'big')).to_bytes(n, 'big')


# =============================================================================
# Module 2: P2P_Proprietary Encryption (for DRW data packets)
# =============================================================================

P2P_PE_TABLE = bytes([
    0x7C, 0x9C, 0xE8, 0x4A, 0x13, 0xDE, 0xDC, 0xB2, 0x2F, 0x21, 0x23, 0xE4, 0x30, 0x7B, 0x3D, 0x8C,
    0xBC, 0x0B, 0x27, 0x0C, 0x3C, 0xF7, 0x9A, 0xE7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xEF, 0xC1,
    0x1F, 0xC4, 0xDB, 0xA1, 0xC2, 0xEB, 0xD9, 0x01, 0xFA, 0xBA, 0x3B, 0x05, 0xB8, 0x15, 0x87, 0x83,
    0x28, 0x72, 0xD1, 0x8B, 0x5A, 0xD6, 0xDA, 0x93, 0x58, 0xFE, 0xAA, 0xCC, 0x6E, 0x1B, 0xF0, 0xA3,
    0x88, 0xAB, 0x43, 0xC0, 0x0D, 0xB5, 0x45, 0x38, 0x4F, 0x50, 0x22, 0x66, 0x20, 0x7F, 0x07, 0x5B,
    0x14, 0x98, 0x1D, 0x9B, 0xA7, 0x2A, 0xB9, 0xA8, 0xCB, 0xF1, 0xFC, 0x49, 0x47, 0x06, 0x3E, 0xB1,
    0x0E, 0x04, 0x3A, 0x94, 0x5E, 0xEE, 0x54, 0x11, 0x34, 0xDD, 0x4D, 0xF9, 0xEC, 0xC7, 0xC9, 0xE3,
    0x78, 0x1A, 0x6F, 0x70, 0x6B, 0xA4, 0xBD, 0xA9, 0x5D, 0xD5, 0xF8, 0xE5, 0xBB, 0x26, 0xAF, 0x42,
    0x37, 0xD8, 0xE1, 0x02, 0x0A, 0xAE, 0x5F, 0x1C, 0xC5, 0x73, 0x09, 0x4E, 0x69, 0x24, 0x90, 0x6D,
    0x12, 0xB3, 0x19, 0xAD, 0x74, 0x8A, 0x29, 0x40, 0xF5, 0x2D, 0xBE, 0xA5, 0x59, 0xE0, 0xF4, 0x79,
    0xD2, 0x4B, 0xCE, 0x89, 0x82, 0x48, 0x84, 0x25, 0xC6, 0x91, 0x2B, 0xA2, 0xFB, 0x8F, 0xE9, 0xA6,
    0xB0, 0x9E, 0x3F, 0x65, 0xF6, 0x03, 0x31, 0x2E, 0xAC, 0x0F, 0x95, 0x2C, 0x5C, 0xED, 0x39, 0xB7,
    0x33, 0x6C, 0x56, 0x7E, 0xB4, 0xA0, 0xFD, 0x7A, 0x81, 0x53, 0x51, 0x86, 0x8D, 0x9F, 0x77, 0xFF,
    0x6A, 0x80, 0xDF, 0xE2, 0xBF, 0x10, 0xD7, 0x75, 0x64, 0x57, 0x76, 0xF3, 0x55, 0xCD, 0xD0, 0xC8,
    0x18, 0xE6, 0x36, 0x41, 0x62, 0xCF, 0x99, 0xF2, 0x32, 0x4C, 0x67, 0x60, 0x61, 0x92, 0xCA, 0xD3,
    0xEA, 0x63, 0x7D, 0x16, 0xB6, 0x8E, 0xD4, 0x68, 0x35, 0xC3, 0x52, 0x9D, 0x46, 0x44, 0x1E, 0x17,
])

# Known PSK strings for different camera prefixes
KNOWN_PSKS = [
    "vstarcam2019",    # vstj, vstk, vstl, vstm, vstn, vstp (and VC0 per pcap)
    "vstarcam2018",    # vstg, vsth, elsc
    "",                # No PSK (vstc, vstb)
]


def p2p_derive_key(psk: bytes) -> bytes:
    """Derive 4-byte cipher key from PSK string."""
    k0 = sum(psk) & 0xFF
    k1 = (-k0) & 0xFF
    k2 = sum(b // 3 for b in psk) & 0xFF
    k3 = 0
    for b in psk:
        k3 ^= b
    return bytes([k0, k1, k2, k3])


def _build_p2p_tables(key4):
    """Pre-compute 4 x 256 XOR-value tables for P2P cipher acceleration."""
    tables = []
    for k in range(4):
        t = bytes(P2P_PE_TABLE[(key4[k] + prev) & 0xFF] for prev in range(256))
        tables.append(t)
    return tables


def _build_merged_table(key4):
    """Pre-compute merged 256-byte table: merged[i] = tables[i & 3][i].
    Used by both C accelerator and as a Python fast-path."""
    return bytes(P2P_PE_TABLE[(key4[i & 3] + i) & 0xFF] for i in range(256))

_p2p_table_cache = {}
_p2p_merged_cache = {}
_p2p_buf = None  # Reusable ctypes buffer to avoid per-call allocation
_p2p_buf_size = 0

def _get_p2p_buf(n: int):
    """Get a reusable ctypes char buffer of at least n bytes."""
    global _p2p_buf, _p2p_buf_size
    if n > _p2p_buf_size:
        _p2p_buf_size = max(n, 2048)
        _p2p_buf = ctypes.create_string_buffer(_p2p_buf_size)
    return _p2p_buf

def p2p_proprietary_decrypt(key4: bytes, data: bytes) -> bytes:
    """Decrypt data using P2P_Proprietary stateful XOR table cipher."""
    k = bytes(key4)
    if _accel is not None:
        if k not in _p2p_merged_cache:
            _p2p_merged_cache[k] = _build_merged_table(key4)
        merged = _p2p_merged_cache[k]
        n = len(data)
        buf = _get_p2p_buf(n)
        _accel.p2p_decrypt(merged, data, buf, n)
        return buf.raw[:n]
    # Python fallback
    if k not in _p2p_table_cache:
        _p2p_table_cache[k] = _build_p2p_tables(key4)
    tables = _p2p_table_cache[k]
    out = bytearray(len(data))
    prev = 0
    for i, c in enumerate(data):
        out[i] = c ^ tables[prev & 3][prev]
        prev = c
    return bytes(out)


def p2p_proprietary_encrypt(key4: bytes, data: bytes) -> bytes:
    """Encrypt data using P2P_Proprietary stateful XOR table cipher."""
    k = bytes(key4)
    if _accel is not None:
        if k not in _p2p_merged_cache:
            _p2p_merged_cache[k] = _build_merged_table(key4)
        merged = _p2p_merged_cache[k]
        n = len(data)
        buf = _get_p2p_buf(n)
        _accel.p2p_encrypt(merged, data, buf, n)
        return buf.raw[:n]
    # Python fallback
    if k not in _p2p_table_cache:
        _p2p_table_cache[k] = _build_p2p_tables(key4)
    tables = _p2p_table_cache[k]
    out = bytearray(len(data))
    prev = 0
    for i, p in enumerate(data):
        c = p ^ tables[prev & 3][prev]
        out[i] = c
        prev = c
    return bytes(out)


# =============================================================================
# Module 3: AES Video Decryption
# =============================================================================

def derive_video_key(uid: str, password: str) -> bytes:
    """Derive AES-128 key from camera UID and password via MD5."""
    return hashlib.md5((uid + password).encode("ascii", errors="replace")).digest()


def aes_decrypt_ecb(key: bytes, data: bytes) -> bytes:
    """Decrypt data with AES-128-ECB (no padding removal)."""
    if not HAS_AES:
        raise RuntimeError("pycryptodome required: pip install pycryptodome")
    cipher = AES.new(key, AES.MODE_ECB)
    aligned = len(data) & ~15
    if aligned == 0:
        return data
    return cipher.decrypt(data[:aligned]) + data[aligned:]


# =============================================================================
# Module 4: CS2 Init String Decoder
# =============================================================================

INIT_STRING_LUT = bytes([
    0x49, 0x59, 0x43, 0x3D, 0xB5, 0xBF, 0x6D, 0xA3,
    0x47, 0x53, 0x4F, 0x61, 0x65, 0xE3, 0x71, 0xE9,
    0x67, 0x7F, 0x02, 0x03, 0x0B, 0xAD, 0xB3, 0x89,
    0x2B, 0x2F, 0x35, 0xC1, 0x6B, 0x8B, 0x95, 0x97,
    0x11, 0xE5, 0xA7, 0x0D, 0xEF, 0xF1, 0x05, 0x07,
    0x83, 0xFB, 0x9D, 0x3B, 0xC5, 0xC7, 0x13, 0x17,
    0x1D, 0x1F, 0x25, 0x29, 0xD3, 0xDF,
])


def decode_init_string(init_str: str) -> tuple[str, Optional[str]]:
    """Decode a CS2 PPCS init string. Returns (servers, PSK or None)."""
    parts = init_str.split(":", 1)
    encoded = parts[0]
    psk = parts[1] if len(parts) > 1 else None

    n = len(encoded) // 2
    output = bytearray(n)
    for i in range(n):
        running_xor = 0x39
        for j in range(i):
            running_xor ^= output[j]
        hi = ord(encoded[2 * i]) - ord("A")
        lo = ord(encoded[2 * i + 1]) - ord("A")
        byte_val = (hi << 4) | lo
        output[i] = (running_xor ^ INIT_STRING_LUT[i % len(INIT_STRING_LUT)] ^ byte_val) & 0xFF

    return output.decode("ascii", errors="replace"), psk


INIT_STRINGS = {
    "VSTC": "EBGBEMBMKGJMGAJPEIGIFKEGHBMCHMNFGKEGBFCBBMJELILDCJADCIOLHHLLJBKEAMMBLCDGONMDBJCJJPNFJP",
    "VSTB": "EBGBEMBMKGJMGAJPEIGIFKEGHBMCHMNFGKEGBFCBBMJELILDCJADCIOLHHLLJBKEAMMBLCDGONMDBJCJJPNFJP",
    "VC0":  "EBGBEMBMKGJMGAJPEIGIFKEGHBMCHMNFGKEGBFCBBMJELILDCJADCIOLHHLLJBKEAMMBLCDGONMDBJCJJPNFJP",
    "VSTA": "EFGFFBBOKAIEGHJAEDHJFEEOHMNGDCNJCDFKAKHLEBJHKEKMCAFCDLLLHAOCJPPMBHMNOMCJKGJEBGGHJHIOMFBDNPKNFEGCEGCBGCALMFOHBCGMFK",
}


# =============================================================================
# Module 5: PPPP Protocol Constants and Packet Building
# =============================================================================

PPPP_MAGIC = 0xF1
PPPP_PORT = 32108

# Control message types (decoded with simple XOR)
MSG_LAN_SEARCH = 0xE0
MSG_LAN_NOTIFY = 0x91
MSG_PUNCH_RSP = 0x92
MSG_PUNCH_TO = 0x30
MSG_PUNCH_PKT = 0x31

# DRW message types (decoded with P2P_Proprietary — standard PPPP)
MSG_DRW = 0xD0
MSG_DRW_ACK = 0xD1

# DRW inner magic
DRW_INNER_MAGIC = 0xD1
DRW_ACK_INNER_MAGIC = 0xD1  # Same as DRW inner magic (confirmed from pcap)

# Standard PPPP channels
CH_CMD = 0       # Command/control channel
CH_VIDEO = 1     # Video stream
CH_AUDIO = 2     # Audio stream

# After simple XOR, P2P_Proprietary-encrypted DRW packets appear as these types
# (artifact of XOR decoding P2P-encrypted data — used for detection only)
SIMPLE_XOR_DRW_TYPE = 0x00
SIMPLE_XOR_DRW_ACK_TYPE = 0x01

# Encryption mode for DRW packets
ENC_P2P = "p2p"          # P2P_Proprietary cipher (vstarcam2019, vstarcam2018)
ENC_XOR_ONLY = "xor"     # Simple XOR only, no P2P_Proprietary (VC0, VSTC, VSTB)

# Video frame header
STREAMHEAD_MAGIC = 0xA815AA55  # little-endian: 55 AA 15 A8
STREAMHEAD_SIZE = 32
# Frame types from STREAMHEAD byte 4
FRAME_I = 0x10   # I-frame (keyframe)
FRAME_P = 0x11   # P-frame

# Audio codec identifiers (auto-detected from stream data)
AUDIO_PCM_L16 = "pcm"    # Raw PCM 16-bit signed LE, 8kHz mono
AUDIO_PCMA = "pcma"       # G.711 a-law
AUDIO_PCMU = "pcmu"       # G.711 u-law
AUDIO_ADPCM = "adpcm"    # IMA ADPCM (decoded to PCM L16 before RTP)
AUDIO_SAMPLE_RATE = 8000

# STREAMHEAD audio codec byte (offset 5 in STREAMHEAD)
AUDIO_CODEC_PCM = 0x00
AUDIO_CODEC_ADPCM = 0x01
AUDIO_CODEC_G711A = 0x02
AUDIO_CODEC_G711U = 0x03

# IMA ADPCM step size table (RFC 3551 / IMA standard)
_ADPCM_STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31,
    34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
    157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544,
    598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707,
    1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871,
    5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635,
    13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
]

# IMA ADPCM index adjustment table
_ADPCM_INDEX_TABLE = [
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8,
]


def decode_ima_adpcm(data: bytes, predicted: int = 0, index: int = 0) -> tuple:
    """Decode IMA ADPCM data to PCM 16-bit signed little-endian.
    Camera sends raw ADPCM nibbles with no block header.
    Each input byte contains two 4-bit ADPCM samples (high nibble first).
    Returns (pcm_bytes, final_predicted, final_index)."""
    if _accel is not None and predicted == 0 and index == 0:
        n_samples = len(data) * 2
        out_buf = (ctypes.c_int16 * n_samples)()
        _accel.decode_adpcm(data, len(data), out_buf)
        return (bytes(out_buf), 0, 0)
    # Python fallback
    samples = _array.array('h')
    step_table = _ADPCM_STEP_TABLE
    index_table = _ADPCM_INDEX_TABLE
    for byte in data:
        for nibble in ((byte >> 4) & 0x0F, byte & 0x0F):
            step = step_table[index]
            diff = step >> 3
            if nibble & 1:
                diff += step >> 2
            if nibble & 2:
                diff += step >> 1
            if nibble & 4:
                diff += step
            if nibble & 8:
                predicted -= diff
            else:
                predicted += diff
            if predicted > 32767:
                predicted = 32767
            elif predicted < -32768:
                predicted = -32768
            index += index_table[nibble]
            if index < 0:
                index = 0
            elif index > 88:
                index = 88
            samples.append(predicted)
    return (samples.tobytes(), predicted, index)

# PCM 16-bit signed → G.711 mu-law conversion table (ITU-T G.711)
# Pre-computed for all 65536 possible 16-bit values for maximum speed.
def _build_pcm_to_ulaw_table() -> bytes:
    """Build 65536-entry lookup: signed 16-bit PCM index → mu-law byte."""
    BIAS = 0x84
    CLIP = 32635
    table = bytearray(65536)
    for i in range(65536):
        sample = i - 65536 if i >= 32768 else i  # unsigned index → signed
        sign = 0 if sample >= 0 else 0x80
        sample = min(abs(sample), CLIP) + BIAS
        # Find segment (exponent)
        exp = 7
        for e in range(7, -1, -1):
            if sample & (1 << (e + 7)):
                exp = e
                break
        mantissa = (sample >> (exp + 3)) & 0x0F
        ulaw_byte = ~(sign | (exp << 4) | mantissa) & 0xFF
        table[i] = ulaw_byte
    return bytes(table)

_PCM_TO_ULAW = _build_pcm_to_ulaw_table()


def pcm16le_to_ulaw(pcm_data: bytes) -> bytes:
    """Convert PCM 16-bit LE to G.711 mu-law. Returns half the bytes."""
    table = _PCM_TO_ULAW
    out = bytearray(len(pcm_data) // 2)
    for i in range(0, len(pcm_data) - 1, 2):
        # Convert LE 16-bit signed to unsigned 16-bit table index
        idx = pcm_data[i] | (pcm_data[i + 1] << 8)
        out[i >> 1] = table[idx]
    return bytes(out)


# CGI command preamble (before length + CGI text)
CGI_PREAMBLE = bytes([0x01, 0x0A, 0x00, 0x00])


def build_control_packet(msg_type: int, payload: bytes = b"") -> bytes:
    """Build a control/handshake packet with simple XOR."""
    header = bytes([PPPP_MAGIC, msg_type, 0x00, 0x00])
    return xor_obfuscate(header + payload)


def build_lan_search() -> bytes:
    return build_control_packet(MSG_LAN_SEARCH)


def build_punch_to() -> bytes:
    return build_control_packet(MSG_PUNCH_TO)


def build_punch_pkt() -> bytes:
    return build_control_packet(MSG_PUNCH_PKT)


def build_alive() -> bytes:
    return build_control_packet(MSG_LAN_SEARCH)  # Keep-alive = unicast LAN_SEARCH


def build_drw_packet(channel: int, index: int, payload: bytes,
                     p2p_key: bytes, enc_mode: str = ENC_P2P) -> bytes:
    """
    Build a DRW data packet in standard PPPP format.

    Standard format: F1 D0 [size16BE] D1 [channel] [index16BE] [payload]
    enc_mode: ENC_P2P (P2P_Proprietary cipher) or ENC_XOR_ONLY (simple XOR)
    """
    inner = struct.pack(">BBH", DRW_INNER_MAGIC, channel, index & 0xFFFF) + payload
    size = len(inner)
    header = struct.pack(">BBH", PPPP_MAGIC, MSG_DRW, size)
    plaintext = header + inner
    if enc_mode == ENC_XOR_ONLY:
        return xor_obfuscate(plaintext)
    return p2p_proprietary_encrypt(p2p_key, plaintext)


def build_drw_ack(channel: int, acked_index: int,
                  p2p_key: bytes, enc_mode: str = ENC_P2P) -> bytes:
    """Build a DRW_ACK packet for a received packet index."""
    # Pre-allocate single buffer: F1 D1 [size16BE] D1 [channel] [count16BE] [idx16BE]
    buf = bytearray(10)
    buf[0] = PPPP_MAGIC
    buf[1] = MSG_DRW_ACK
    struct.pack_into('>H', buf, 2, 6)  # inner size = 6 bytes
    buf[4] = DRW_ACK_INNER_MAGIC
    buf[5] = channel
    struct.pack_into('>H', buf, 6, 1)  # count = 1
    struct.pack_into('>H', buf, 8, acked_index)
    if enc_mode == ENC_XOR_ONLY:
        return xor_obfuscate(bytes(buf))
    return p2p_proprietary_encrypt(p2p_key, bytes(buf))


def build_drw_ack_batch(channel: int, indices: list[int],
                        p2p_key: bytes, enc_mode: str = ENC_P2P) -> bytes:
    """Build a batched DRW_ACK packet for multiple indices at once.
    The Eye4 app sends batched ACKs with count=N and N index entries."""
    count = len(indices)
    inner_size = 4 + count * 2  # D1 + channel + count16 + N*idx16
    buf = bytearray(4 + inner_size)
    buf[0] = PPPP_MAGIC
    buf[1] = MSG_DRW_ACK
    struct.pack_into('>H', buf, 2, inner_size)
    buf[4] = DRW_ACK_INNER_MAGIC
    buf[5] = channel
    struct.pack_into('>H', buf, 6, count)
    for i, idx in enumerate(indices):
        struct.pack_into('>H', buf, 8 + i * 2, idx)
    if enc_mode == ENC_XOR_ONLY:
        return xor_obfuscate(bytes(buf))
    return p2p_proprietary_encrypt(p2p_key, bytes(buf))


def build_cgi_command(cgi_text: str) -> bytes:
    """Wrap a CGI command string in the binary envelope expected by the camera."""
    cgi_bytes = cgi_text.encode("ascii")
    return CGI_PREAMBLE + struct.pack("<I", len(cgi_bytes)) + cgi_bytes


def parse_drw_packet(plaintext: bytes) -> Optional[dict]:
    """
    Parse a decrypted (plaintext) DRW packet.
    Returns dict with 'channel', 'index', 'payload' or None if invalid.
    """
    if len(plaintext) < 8:
        return None
    magic, msg_type, size = struct.unpack(">BBH", plaintext[:4])
    if magic != PPPP_MAGIC or msg_type != MSG_DRW:
        return None
    if plaintext[4] != DRW_INNER_MAGIC:
        return None
    channel = plaintext[5]
    index = struct.unpack(">H", plaintext[6:8])[0]
    payload = plaintext[8:]
    return {"channel": channel, "index": index, "payload": payload}


def parse_drw_ack(plaintext: bytes) -> Optional[dict]:
    """Parse a decrypted DRW_ACK packet."""
    if len(plaintext) < 8:
        return None
    magic, msg_type, size = struct.unpack(">BBH", plaintext[:4])
    if magic != PPPP_MAGIC or msg_type != MSG_DRW_ACK:
        return None
    # Inner: D2 channel count16 [acked_indices...]
    channel = plaintext[5]
    return {"channel": channel, "raw": plaintext}


# =============================================================================
# Module 6: PPPP Session — Discovery, Connection, Commands
# =============================================================================

class CameraInfo:
    """Discovered camera information."""

    def __init__(self, ip: str, port: int, uid_bytes: bytes):
        self.ip = ip
        self.port = port  # Current port (updated by PUNCH_TO)
        self.discovery_port = port  # Original port from LAN_NOTIFY
        self.uid_bytes = uid_bytes
        self.uid_hex = uid_bytes.hex()
        self.uid = uid_from_bytes(uid_bytes)  # Printable UID like "VSTABCDEFGHIJKL"

    def __repr__(self):
        return f"Camera({self.ip}:{self.port} uid={self.uid})"


class PPPPUnifiedProtocol(asyncio.DatagramProtocol):
    """
    Unified UDP protocol handler for the entire PPPP lifecycle.

    CRITICAL PROTOCOL INSIGHT:
    - Control packets (LAN_SEARCH, LAN_NOTIFY, PUNCH_RSP, PUNCH_TO, PUNCH_PKT)
      use simple 4-byte repeating XOR.
    - DRW data packets use P2P_Proprietary stream cipher and standard PPPP format:
      F1 D0 [size16BE] D1 [channel] [index16BE] [payload]
    """

    def __init__(self, username: str, password: str,
                 video_callback=None, audio_callback=None,
                 p2p_key: bytes = None,
                 psk_list: Optional[list[str]] = None,
                 enc_mode: Optional[str] = None,
                 alarm_server_addr: Optional[str] = None):
        self.username = username
        self.password = password
        self.video_callback = video_callback
        self.audio_callback = audio_callback
        self.p2p_key = p2p_key  # 4-byte P2P_Proprietary key (None = auto-detect)
        self.enc_mode = enc_mode  # ENC_P2P, ENC_XOR_ONLY, or None = auto-detect
        self.psk_list = psk_list or KNOWN_PSKS  # PSKs to try for auto-detection
        self.alarm_server_addr = alarm_server_addr
        self.alarm_callback = None  # Called with (alarm_status: int) on change
        self.alarm_poll_interval: float = 1.0
        self._last_alarm_status: Optional[int] = None
        self._alarm_poll_task: Optional[asyncio.Task] = None

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.cameras: dict[str, CameraInfo] = {}
        self.discovery_done = asyncio.Event()

        self._active_camera: Optional[CameraInfo] = None
        self._connected = asyncio.Event()
        self._logged_in = asyncio.Event()
        self._got_any_drw = asyncio.Event()  # Set when ANY DRW/ACK received
        self._drw_port: Optional[int] = None  # Locked port for DRW communication
        self._seen_drw_indices: dict[int, set[int]] = {}  # channel -> set of seen indices
        self._drw_high_water: dict[int, int] = {}  # channel -> highest seen index
        self._cmd_index = 0
        self._video_reassembly: Optional[VideoReassembly] = None
        self._audio_reassembly: Optional["AudioReassembly"] = None
        self._last_audio_drw_time: float = 0
        self._drw_bytes_received = 0
        self._drw_packets_received = 0
        self._running = False
        self._alive_task: Optional[asyncio.Task] = None
        self._punch_rsp_data: dict[str, bytes] = {}
        self._raw_drw_buffer: list[bytes] = []  # Buffer raw DRW for PSK detection
        self._raw_drw_enc_modes: list[str] = []  # Track which enc mode each buffered pkt uses
        self._lan_notify_raw: dict[str, tuple[bytes, tuple]] = {}  # ip -> (raw, addr)

        # Batched ACK state — camera expects multi-index ACK packets
        self._pending_acks: dict[int, list[int]] = {}  # channel -> [indices]
        self._ack_addr: Optional[tuple] = None  # address to send ACKs to
        self._ack_flush_task: Optional[asyncio.Task] = None

        self.aes_key: Optional[bytes] = None

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        if sock:
            local = sock.getsockname()
            log.info("PPPP socket bound to %s:%d", local[0], local[1])

    def _flush_acks_for_channel(self, channel: int, addr: tuple):
        """Send a batched ACK for all pending indices on a channel."""
        indices = self._pending_acks.pop(channel, [])
        if not indices or not self.transport or self.transport.is_closing():
            return
        ack = build_drw_ack_batch(channel, indices, self.p2p_key, self.enc_mode)
        self.transport.sendto(ack, addr)

    def _flush_all_acks_timer(self):
        """Flush all pending ACKs across all channels (called by timer)."""
        self._ack_flush_task = None  # Allow new timer to be scheduled
        if not self._ack_addr:
            return
        for channel in list(self._pending_acks.keys()):
            self._flush_acks_for_channel(channel, self._ack_addr)

    def datagram_received(self, data: bytes, addr: tuple):
        if len(data) < 4:
            return

        ip, port = addr

        # Step 1: Fast type check — only XOR first 2 bytes instead of full packet
        xor_magic = data[0] ^ 0x15  # XOR_KEY[0]
        if xor_magic != PPPP_MAGIC:
            if self._active_camera and ip == self._active_camera.ip:
                log.warning("Non-PPPP packet from %s:%d (%d bytes) raw[0:4]=%s",
                            ip, port, len(data), data[:4].hex())
            return

        xor_type = data[1] ^ 0xDB   # XOR_KEY[1]

        # Step 2: Dispatch — DRW packets (vast majority) skip full XOR decode
        if xor_type == SIMPLE_XOR_DRW_TYPE:
            # P2P_Proprietary-encrypted DRW (appears as type 0x00 after simple XOR)
            self._handle_drw_encrypted(data, addr, ENC_P2P)
        elif xor_type == SIMPLE_XOR_DRW_ACK_TYPE:
            # P2P_Proprietary-encrypted DRW_ACK (appears as type 0x01 after simple XOR)
            self._handle_drw_ack_encrypted(data, addr, ENC_P2P)
        elif xor_type == MSG_DRW:
            # XOR-only DRW (type 0xD0 after simple XOR = no P2P_Proprietary)
            self._handle_drw_encrypted(data, addr, ENC_XOR_ONLY)
        elif xor_type == MSG_DRW_ACK:
            # XOR-only DRW_ACK (type 0xD1 after simple XOR = no P2P_Proprietary)
            self._handle_drw_ack_encrypted(data, addr, ENC_XOR_ONLY)
        elif xor_type == MSG_LAN_NOTIFY:
            xor_decoded = xor_obfuscate(data)
            self._handle_lan_notify(xor_decoded, data, addr)
        elif xor_type == MSG_PUNCH_RSP:
            xor_decoded = xor_obfuscate(data)
            self._handle_punch_rsp(xor_decoded, ip, port)
        elif xor_type == MSG_PUNCH_TO:
            self._handle_punch_to(ip, port)
        elif xor_type == MSG_PUNCH_PKT:
            self._handle_punch_pkt(ip, port)
        elif xor_type == MSG_LAN_SEARCH:
            pass  # Ignore our own broadcasts
        elif xor_type == 0x20:
            if self._active_camera and ip == self._active_camera.ip:
                # Only treat CLOSE as meaningful if it's from the active DRW port
                if self._drw_port and port != self._drw_port:
                    log.debug("CLOSE (0x20) from %s:%d — not DRW port (%d), ignoring",
                              ip, port, self._drw_port)
                else:
                    now = asyncio.get_event_loop().time()
                    last_drw = getattr(self, '_last_drw_time', 0)
                    drw_age = now - last_drw if last_drw > 0 else float('inf')
                    if drw_age < 15.0:
                        log.debug("CLOSE (0x20) from %s:%d — DRW active %.1fs ago, ignoring",
                                  ip, port, drw_age)
                    else:
                        log.warning("CLOSE (0x20) from %s:%d — DRW stale (%.1fs), scheduling reconnect",
                                    ip, port, drw_age)
                        asyncio.ensure_future(self._handle_session_close())
            else:
                log.debug("CLOSE (0x20) from %s:%d (not active camera)", ip, port)
        else:
            log.info("Unknown msg xor_type=0x%02X from %s:%d (%d bytes): %s",
                     xor_type, ip, port, len(data), data[:16].hex())

    def error_received(self, exc):
        log.error("UDP error: %s", exc)

    def connection_lost(self, exc):
        log.debug("UDP socket closed: %s", exc)

    # --- Control packet handlers ---

    def _handle_lan_notify(self, decoded: bytes, raw: bytes, addr: tuple):
        ip, port = addr
        if len(decoded) < 24:
            return
        uid_bytes = decoded[4:24]
        if ip not in self.cameras:
            cam = CameraInfo(ip, port, uid_bytes)
            self.cameras[ip] = cam
            log.info("Discovered camera: %s", cam)
        else:
            # Don't update discovery_port - keep the first one
            self.cameras[ip].port = port
        # Save raw LAN_NOTIFY for re-establishing sessions later
        self._lan_notify_raw[ip] = (raw, addr)
        # Echo LAN_NOTIFY back (triggers PUNCH_RSP from camera)
        self.transport.sendto(raw, addr)

    def _handle_punch_rsp(self, decoded: bytes, ip: str, port: int):
        log.debug("PUNCH_RSP from %s:%d", ip, port)
        if ip not in self._punch_rsp_data:
            self._punch_rsp_data[ip] = decoded[2:]
        # Respond with PUNCH_PKT to acknowledge
        if self.transport and not self.transport.is_closing():
            self.transport.sendto(build_punch_pkt(), (ip, port))
        if self._active_camera and ip == self._active_camera.ip:
            self._active_camera.port = port
            self._connected.set()

    def _handle_punch_to(self, ip: str, port: int):
        # Always respond with PUNCH_PKT — this is required to complete handshake!
        if self.transport and not self.transport.is_closing():
            self.transport.sendto(build_punch_pkt(), (ip, port))
        if self._active_camera and ip == self._active_camera.ip:
            self._active_camera.port = port
            if not self._connected.is_set():
                log.info("PUNCH_TO from target %s:%d — connection established!", ip, port)
                self._connected.set()
            else:
                log.debug("PUNCH_TO from %s:%d (already connected)", ip, port)
        else:
            log.debug("PUNCH_TO from %s:%d (not target camera)", ip, port)

    def _handle_punch_pkt(self, ip: str, port: int):
        log.info("PUNCH_PKT from %s:%d — session confirmed!", ip, port)
        if self._active_camera and ip == self._active_camera.ip:
            self._active_camera.port = port
            self._connected.set()

    # --- DRW packet handlers (P2P_Proprietary encrypted) ---

    def _handle_drw_encrypted(self, raw_data: bytes, addr: tuple, pkt_enc_mode: str):
        """Decrypt a DRW packet and process it."""
        if not self.enc_mode:
            # Enc mode not determined yet — buffer for auto-detection
            self._raw_drw_buffer.append(raw_data)
            self._raw_drw_enc_modes.append(pkt_enc_mode)
            self._got_any_drw.set()
            log.info("Buffered raw DRW (%s) from %s:%d (%d bytes) for enc detection",
                     pkt_enc_mode, addr[0], addr[1], len(raw_data))
            return

        # Track DRW port — update to the port that sends us data
        if self._active_camera and addr[0] == self._active_camera.ip:
            if not self._drw_port:
                self._drw_port = addr[1]
                log.info("DRW port locked to %s:%d", addr[0], self._drw_port)
            elif self._drw_port != addr[1]:
                log.debug("DRW data also from port %d (locked=%d)", addr[1], self._drw_port)
                # Update to the new port — camera may have switched
                self._drw_port = addr[1]

        plaintext = self._decrypt_drw(raw_data, pkt_enc_mode)
        parsed = parse_drw_packet(plaintext)

        if not parsed:
            log.debug("Failed to parse DRW from %s:%d (%d bytes), first8=%s",
                      addr[0], addr[1], len(raw_data), plaintext[:8].hex())
            return

        channel = parsed["channel"]
        index = parsed["index"]
        payload = parsed["payload"]

        # Track time of last DRW received (for reconnect debounce)
        self._last_drw_time = asyncio.get_event_loop().time()
        if channel == 1:
            self._last_video_drw_time = self._last_drw_time

        # Queue ACK for batched sending (camera expects multi-index ACKs)
        self._ack_addr = addr
        if channel not in self._pending_acks:
            self._pending_acks[channel] = []
        self._pending_acks[channel].append(index)
        # Flush when we have enough indices or for command channel (ACK immediately)
        if channel == 0 or len(self._pending_acks[channel]) >= 16:
            self._flush_acks_for_channel(channel, addr)
        else:
            # Schedule a flush timer if one isn't already pending
            if self._ack_flush_task is None:
                self._ack_flush_task = asyncio.get_event_loop().call_later(
                    0.05, self._flush_all_acks_timer)

        # Track seen indices — skip retransmissions for processing
        # Uses a sliding window to handle 16-bit index wraparound (0-65535)
        if channel not in self._seen_drw_indices:
            self._seen_drw_indices[channel] = set()
            self._drw_high_water[channel] = -1
        seen = self._seen_drw_indices[channel]
        if index in seen:
            return  # Already processed this index
        # Detect wraparound: if high_water is near max and index is near 0,
        # or if the set has grown too large, prune old entries
        hw = self._drw_high_water[channel]
        if hw >= 0 and index < 16384 and hw > 49152:
            # Index wrapped around 65535 → 0; clear the set
            seen.clear()
            log.debug("DRW ch=%d index wrapped (%d → %d), cleared dedup set", channel, hw, index)
        elif len(seen) > 16384:
            # Safety: prune entries far below current index to bound memory
            cutoff = (index - 8192) & 0xFFFF
            if cutoff < index:
                seen.difference_update(range(cutoff))
            else:
                # cutoff wrapped: remove 0..cutoff and keep cutoff..65535
                seen.difference_update(range(cutoff))
        seen.add(index)
        self._drw_high_water[channel] = index

        self._drw_packets_received += 1
        self._drw_bytes_received += len(payload)

        if self._drw_packets_received <= 10:
            log.info("DRW #%d from %s:%d ch=%d idx=%d (%d bytes) first16=%s",
                     self._drw_packets_received, addr[0], addr[1],
                     channel, index, len(payload),
                     payload[:16].hex() if payload else "empty")

        if self._drw_packets_received % 100 == 0:
            log.info("DRW stats: %d unique packets, %d bytes total",
                     self._drw_packets_received, self._drw_bytes_received)

        # Process by channel
        if channel == CH_CMD:
            self._handle_cmd_response(payload)
        elif channel == CH_VIDEO:
            self._handle_video_data(index, payload)
        elif channel == CH_AUDIO:
            self._handle_audio_data(index, payload)
        else:
            log.debug("DRW ch=%d idx=%d (%d bytes)", channel, index, len(payload))

    def _decrypt_drw(self, raw_data: bytes, pkt_enc_mode: str) -> bytes:
        """Decrypt a DRW packet based on the determined encryption mode."""
        if self.enc_mode == ENC_XOR_ONLY or pkt_enc_mode == ENC_XOR_ONLY:
            return xor_obfuscate(raw_data)
        return p2p_proprietary_decrypt(self.p2p_key, raw_data)

    def _handle_drw_ack_encrypted(self, raw_data: bytes, addr: tuple, pkt_enc_mode: str):
        """Process a DRW_ACK packet."""
        if not self.enc_mode:
            self._raw_drw_buffer.append(raw_data)
            self._raw_drw_enc_modes.append(pkt_enc_mode)
            self._got_any_drw.set()
            log.info("Buffered raw DRW_ACK (%s) from %s:%d for enc detection",
                     pkt_enc_mode, addr[0], addr[1])
            return

        # Lock DRW port to the port that responds
        if self._active_camera and addr[0] == self._active_camera.ip:
            if not self._drw_port:
                self._drw_port = addr[1]
                log.info("DRW port locked to %s:%d (from ACK)", addr[0], self._drw_port)

        plaintext = self._decrypt_drw(raw_data, pkt_enc_mode)
        parsed = parse_drw_ack(plaintext)
        if parsed:
            log.info("DRW_ACK from %s:%d ch=%d", addr[0], addr[1], parsed["channel"])
        else:
            log.info("DRW_ACK from %s:%d (unparsed, %d bytes)",
                      addr[0], addr[1], len(raw_data))

    def _handle_cmd_response(self, payload: bytes):
        """Process a command channel response from the camera."""
        # Response format: 01 0A XX XX [more data...] where XX XX is a response sub-type
        # Or continuation data without preamble
        text = None
        if len(payload) >= 8 and payload[:2] == b'\x01\x0a':
            # Preamble present — skip 4 bytes preamble, extract text after it
            text = payload[4:].decode("ascii", errors="replace")
        else:
            # Continuation or raw text
            text = payload.decode("ascii", errors="replace")
        # Log at DEBUG for alarm poll responses to reduce noise
        is_alarm_poll = text and ("alarm_status=" in text or "support_motion" in text)
        log.log(logging.DEBUG if is_alarm_poll else logging.INFO,
                "CMD response (%d bytes): first16=%s", len(payload), payload[:16].hex())

        if text:
            # Clean up for display
            display = text.replace('\x00', '').strip()[:300]
            # Suppress noisy alarm poll responses (every 3s per camera)
            if "alarm_status=" in text or "support_motion" in text:
                log.debug("CMD response: %s", display)
            else:
                log.info("CMD response: %s", display)
            if "result=" in text or "deviceid=" in text:
                if not self._logged_in.is_set():
                    self._logged_in.set()
                    log.info("Camera responded — login successful!")
            # Detect alarm_status changes for motion detection
            if "alarm_status=" in text:
                m = re.search(r'alarm_status=(\d+)', text)
                if m:
                    status = int(m.group(1))
                    if status != self._last_alarm_status:
                        prev = self._last_alarm_status
                        self._last_alarm_status = status
                        if prev is not None:  # Skip initial reading
                            log.info("alarm_status changed: %d → %d", prev, status)
                            if self.alarm_callback:
                                self.alarm_callback(status)

    def _handle_video_data(self, index: int, payload: bytes):
        if not payload or not self._video_reassembly:
            return
        self._video_reassembly.feed(index, payload)

    def _handle_audio_data(self, index: int, payload: bytes):
        if not payload:
            return
        self._last_audio_drw_time = asyncio.get_event_loop().time()
        if not hasattr(self, '_audio_drw_count'):
            self._audio_drw_count = 0
        self._audio_drw_count += 1
        if not self._audio_reassembly:
            self._audio_reassembly = AudioReassembly(self._on_audio_frame)
            log.info("First audio DRW: ch=2 idx=%d %d bytes first16=%s",
                     index, len(payload), payload[:16].hex())
        elif self._audio_drw_count <= 5 or self._audio_drw_count % 50 == 0:
            log.info("Audio DRW #%d: idx=%d %d bytes",
                     self._audio_drw_count, index, len(payload))
        self._audio_reassembly.feed(index, payload)

    def _on_audio_frame(self, data: bytes, codec: str):
        if self.audio_callback:
            self.audio_callback(data, codec)

    def _on_video_frame(self, frame_type: int, timestamp: int, data: bytes):
        # Video data is NOT AES-encrypted after P2P_Proprietary decryption
        # (confirmed from pcap: STREAMHEAD + raw H.264 NALs)
        n = self._video_reassembly._frames_received if self._video_reassembly else 0
        if n <= 3 or n % 100 == 0:
            log.info("Video frame #%d: type=%d size=%d first32=%s",
                     n, frame_type, len(data),
                     data[:32].hex() if data else "empty")
            if n <= 3:
                if data[:4] == b'\x00\x00\x00\x01':
                    nal_type = data[4] & 0x1F
                    log.info("  H.264 NAL type=%d (4-byte start code)", nal_type)
                elif data[:3] == b'\x00\x00\x01':
                    nal_type = data[3] & 0x1F
                    log.info("  H.264 NAL type=%d (3-byte start code)", nal_type)
        if self.video_callback:
            self.video_callback(frame_type, timestamp, data)

    # --- Session management ---

    async def connect_to_camera(self, camera: CameraInfo):
        """Establish a PPPP session with the specified camera."""
        self._active_camera = camera
        self._running = True
        self._video_reassembly = VideoReassembly(self._on_video_frame)

        log.info("Connecting to %s (discovery port %d)...", camera, camera.discovery_port)

        # Re-establish session: echo LAN_NOTIFY again to get fresh PUNCH_TO
        if camera.ip in self._lan_notify_raw:
            raw, orig_addr = self._lan_notify_raw[camera.ip]
            log.info("Re-sending LAN_NOTIFY echo to %s:%d", orig_addr[0], orig_addr[1])
            self.transport.sendto(raw, orig_addr)

        # Also send LAN_SEARCH directly to refresh
        self.transport.sendto(build_lan_search(), (camera.ip, PPPP_PORT))
        self._session_start = asyncio.get_event_loop().time()

        # Wait for fresh PUNCH_TO to confirm session
        self._connected.clear()
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=3.0)
            log.info("Session established with %s:%d",
                     camera.ip, camera.discovery_port)
        except asyncio.TimeoutError:
            log.warning("No PUNCH_TO after re-handshake, proceeding anyway...")
            self._connected.set()

        # Send PUNCH_PKT to all known camera ports to keep them alive
        for port in set([camera.discovery_port, camera.port]):
            for _ in range(3):
                self.transport.sendto(build_punch_pkt(), (camera.ip, port))
                await asyncio.sleep(0.02)

        # Start keepalive
        self._alive_task = asyncio.create_task(self._keepalive_loop())

        # Encryption auto-detection: if enc_mode not set, try each mode
        if not self.enc_mode:
            await self._auto_detect_psk(camera)

        if not self.enc_mode:
            log.error("Could not determine encryption mode! Camera may not respond.")
            log.info("Try: --psk vstarcam2019, --psk vstarcam2018, --enc-mode xor")
            return

        # Send login command
        log.info("Sending login command...")
        await self._send_login()

        try:
            await asyncio.wait_for(self._logged_in.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            log.warning("No login response, trying video stream anyway...")
            self._logged_in.set()

        # Small delay to let camera process login
        await asyncio.sleep(0.3)

        # Request video stream
        log.info("Requesting video stream...")
        await self._send_start_video()

        # Request audio stream (separate from video on these cameras)
        await asyncio.sleep(0.3)
        await self._send_start_audio()

        # Redirect alarm notifications to our local HTTP listener
        if self.alarm_server_addr:
            await asyncio.sleep(0.3)
            await self._send_set_alarm_server(self.alarm_server_addr)

        # Start video keepalive — periodically re-request video to keep stream flowing
        self._video_keepalive_task = asyncio.create_task(self._video_keepalive_loop())

        # Start alarm status polling if callback is set
        if self.alarm_callback:
            self._alarm_poll_task = asyncio.create_task(self._alarm_poll_loop())

    async def _alarm_poll_loop(self):
        """Periodically poll get_status.cgi to detect alarm_status changes."""
        try:
            while self._running:
                await asyncio.sleep(self.alarm_poll_interval)
                if self.enc_mode and self.transport and not self.transport.is_closing():
                    cgi = (f"GET /get_status.cgi?"
                           f"loginuse={self.username}&loginpas={self.password}"
                           f"&user={self.username}&pwd={self.password}&")
                    await self._send_cmd(cgi)
        except asyncio.CancelledError:
            pass

    async def _auto_detect_psk(self, camera: CameraInfo):
        """
        Try each known encryption mode by sending a login DRW and checking for response.

        Order of attempts:
        1. XOR-only (no P2P_Proprietary) — most likely for VC0/VSTC/VSTB
        2. P2P_Proprietary with vstarcam2019
        3. P2P_Proprietary with vstarcam2018
        4. P2P_Proprietary with empty PSK
        """
        cgi = (f"GET /get_status.cgi?"
               f"loginuse={self.username}&loginpas={self.password}"
               f"&user={self.username}&pwd={self.password}&")
        payload = build_cgi_command(cgi)

        # Build list of (enc_mode, psk_str, key4) to try
        # Try P2P modes first (most common), then XOR-only
        attempts = []
        for psk_str in self.psk_list:
            if psk_str:
                key4 = p2p_derive_key(psk_str.encode("ascii"))
            else:
                key4 = bytes([0, 0, 0, 0])
            attempts.append((ENC_P2P, psk_str, key4))
        attempts.append((ENC_XOR_ONLY, "(none)", None))  # XOR-only last

        for enc_mode, psk_label, trial_key in attempts:
            # Use the discovery port (original LAN_NOTIFY port) for DRW
            addr = (camera.ip, camera.discovery_port)
            log.info("Trying enc=%s PSK=%r (key=%s) on %s:%d...",
                     enc_mode, psk_label,
                     trial_key.hex() if trial_key else "n/a",
                     addr[0], addr[1])

            # Re-establish session: echo LAN_NOTIFY to get fresh session
            if camera.ip in self._lan_notify_raw:
                raw, orig_addr = self._lan_notify_raw[camera.ip]
                self.transport.sendto(raw, orig_addr)
            self.transport.sendto(build_lan_search(), (camera.ip, PPPP_PORT))

            # Wait for camera to respond with PUNCH_TO
            self._connected.clear()
            end_t = asyncio.get_event_loop().time() + 1.5
            while asyncio.get_event_loop().time() < end_t:
                await asyncio.sleep(0.05)
                if self._connected.is_set():
                    break

            # Send PUNCH_PKT to keep session alive
            addr = (camera.ip, camera.discovery_port)  # Use fresh discovery port
            for _ in range(3):
                self.transport.sendto(build_punch_pkt(), addr)
                await asyncio.sleep(0.02)

            # Clear buffers
            self._raw_drw_buffer.clear()
            self._raw_drw_enc_modes.clear()
            self._got_any_drw.clear()

            # Build and send login DRW with this encryption mode
            pkt = build_drw_packet(CH_CMD, self._cmd_index, payload,
                                   trial_key or b'\x00\x00\x00\x00', enc_mode)
            self._cmd_index = (self._cmd_index + 1) & 0xFFFF
            log.info("  Sending DRW (%d bytes) to %s:%d, first16=%s",
                     len(pkt), addr[0], addr[1], pkt[:16].hex())
            self.transport.sendto(pkt, addr)

            # Wait briefly for any DRW/ACK response
            try:
                await asyncio.wait_for(self._got_any_drw.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                log.info("  No DRW response with enc=%s PSK=%r", enc_mode, psk_label)
                continue

            # We got a response! Check if it decrypts correctly.
            found = False
            for buf_raw, buf_enc in zip(self._raw_drw_buffer, self._raw_drw_enc_modes):
                if buf_enc == ENC_XOR_ONLY:
                    # XOR-only packet — just XOR decode
                    plaintext = xor_obfuscate(buf_raw)
                else:
                    # P2P-encrypted packet — try with trial key
                    if trial_key:
                        plaintext = p2p_proprietary_decrypt(trial_key, buf_raw)
                    else:
                        continue

                if len(plaintext) >= 4 and plaintext[0] == PPPP_MAGIC:
                    if plaintext[1] in (MSG_DRW, MSG_DRW_ACK):
                        log.info("  enc=%s PSK=%r WORKS! (type=0x%02X)",
                                 enc_mode, psk_label, plaintext[1])
                        self.enc_mode = enc_mode
                        self.p2p_key = trial_key or b'\x00\x00\x00\x00'
                        found = True
                        break

            if found:
                # Lock the DRW port to the port we detected on
                log.info("  DRW port locked to %s:%d after auto-detect",
                         camera.ip, addr[1])
                self._drw_port = addr[1]
                # Process all buffered packets with the detected mode
                for buf_raw, buf_enc in zip(self._raw_drw_buffer, self._raw_drw_enc_modes):
                    self._process_buffered_drw(buf_raw, buf_enc, addr)
                self._raw_drw_buffer.clear()
                self._raw_drw_enc_modes.clear()
                return

            log.info("  enc=%s PSK=%r: got response but parse failed", enc_mode, psk_label)
            # Log what we received for debugging
            for buf_raw, buf_enc in zip(self._raw_drw_buffer, self._raw_drw_enc_modes):
                if buf_enc == ENC_XOR_ONLY:
                    decoded = xor_obfuscate(buf_raw)
                else:
                    decoded = p2p_proprietary_decrypt(trial_key, buf_raw) if trial_key else buf_raw
                log.info("    response (%s): first16=%s", buf_enc, decoded[:16].hex())

        log.warning("All encryption mode attempts failed!")
        log.info("Possible causes:")
        log.info("  - Camera uses an unknown PSK")
        log.info("  - Camera requires different handshake sequence")
        log.info("Try: --psk vstarcam2019, --psk vstarcam2018, or --enc-mode xor")

    def _process_buffered_drw(self, raw_data: bytes, pkt_enc_mode: str, addr: tuple):
        """Decrypt and process a buffered DRW packet."""
        if not self.enc_mode:
            return
        plaintext = self._decrypt_drw(raw_data, pkt_enc_mode)
        parsed = parse_drw_packet(plaintext)
        if parsed:
            channel = parsed["channel"]
            index = parsed["index"]
            payload = parsed["payload"]
            self._drw_packets_received += 1
            self._drw_bytes_received += len(payload)
            if channel == CH_CMD:
                self._handle_cmd_response(payload)
            elif channel == CH_VIDEO:
                self._handle_video_data(index, payload)

    async def stop(self):
        self._running = False
        if self._alive_task:
            self._alive_task.cancel()
            try:
                await self._alive_task
            except asyncio.CancelledError:
                pass
        if hasattr(self, '_video_keepalive_task') and self._video_keepalive_task:
            self._video_keepalive_task.cancel()
            try:
                await self._video_keepalive_task
            except asyncio.CancelledError:
                pass
        if self._alarm_poll_task:
            self._alarm_poll_task.cancel()
            try:
                await self._alarm_poll_task
            except asyncio.CancelledError:
                pass
        if self.transport:
            self.transport.close()

    async def _handle_session_close(self):
        """Handle camera session close — create a fresh UDP socket and reconnect.
        The camera tracks sessions by source port, so we need a new socket."""
        if not self._running or not self._active_camera:
            return
        # Debounce: only reconnect once per 15 seconds
        now = asyncio.get_event_loop().time()
        if hasattr(self, '_last_reconnect') and now - self._last_reconnect < 15:
            return
        self._last_reconnect = now

        cam = self._active_camera
        log.info("Creating fresh session with %s (new UDP socket)...", cam.ip)

        # Reset all session state
        self._drw_port = None
        self._seen_drw_indices.clear()
        self._drw_high_water.clear()
        self._cmd_index = 0
        self._drw_packets_received = 0
        self._drw_bytes_received = 0
        self._last_video_drw_time = 0
        self._video_rerequests = 0
        self._pending_acks.clear()
        if self._ack_flush_task:
            self._ack_flush_task.cancel()
            self._ack_flush_task = None
        self._got_any_drw.clear()

        # Close old transport and create new one
        old_transport = self.transport
        loop = asyncio.get_event_loop()
        new_transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=("0.0.0.0", 0),
            allow_broadcast=True,
        )
        sock = new_transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            log.info("New socket bound to port %d", sock.getsockname()[1])

        # Close old transport (self.transport was already updated by connection_made)
        if old_transport and old_transport != self.transport:
            old_transport.close()

        # Fresh discovery on this camera only
        self.transport.sendto(build_lan_search(), (cam.ip, PPPP_PORT))

        # Wait for LAN_NOTIFY + PUNCH
        self._connected.clear()
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("Reconnect: no response on new socket, retrying...")
            return

        # Send PUNCH_PKT to complete handshake
        for port in set([cam.discovery_port, cam.port]):
            for _ in range(3):
                self.transport.sendto(build_punch_pkt(), (cam.ip, port))
                await asyncio.sleep(0.02)

        # Login and request video + audio
        log.info("Fresh session established! Sending login + video + audio request...")
        await self._send_login()
        await asyncio.sleep(0.3)
        await self._send_start_video()
        await asyncio.sleep(0.3)
        await self._send_start_audio()

    async def _keepalive_loop(self):
        while self._running:
            await asyncio.sleep(2)  # Check every 2s
            if not (self._active_camera and self.transport and not self.transport.is_closing()):
                continue

            cam = self._active_camera
            now = asyncio.get_event_loop().time()

            # Send keepalive to ALL known ports for this camera
            ports = set()
            if cam.discovery_port:
                ports.add(cam.discovery_port)
            if cam.port:
                ports.add(cam.port)
            if self._drw_port:
                ports.add(self._drw_port)
            for port in ports:
                self.transport.sendto(build_punch_pkt(), (cam.ip, port))

    async def _video_keepalive_loop(self):
        """Periodically re-request video stream to keep it flowing.
        Camera sends ~3 frames per livestream.cgi request, so we re-request
        frequently to maintain near-continuous video.
        Does NOT trigger full reconnects — that's CameraSession's job."""
        self._video_rerequests = 0
        while self._running:
            await asyncio.sleep(1)  # Check every 1 second
            if not (self._active_camera and self.enc_mode):
                continue
            now = asyncio.get_event_loop().time()
            last_video = getattr(self, '_last_video_drw_time', 0)
            # If video stopped for 1+ second, re-request (camera needs periodic requests)
            if last_video > 0 and now - last_video > 1:
                gap = now - last_video
                self._video_rerequests += 1
                if self._video_rerequests <= 30:
                    # Re-request video quietly (this is normal operation, not an error)
                    log.debug("Video keepalive: re-requesting video (gap=%.1fs, attempt=%d)",
                              gap, self._video_rerequests)
                    await self._send_start_video()
                elif self._video_rerequests % 10 == 0:
                    # Log occasionally after many attempts
                    log.info("Video keepalive: re-requesting video+audio (gap=%.1fs, attempt=%d)",
                             gap, self._video_rerequests)
                    await self._send_start_video()
                    await self._send_start_audio()
                else:
                    await self._send_start_video()
            elif last_video > 0 and now - last_video <= 1:
                # Video stream is active, reset counter
                if self._video_rerequests > 0:
                    self._video_rerequests = 0
            # Check if audio went stale (separate from video)
            last_audio = getattr(self, '_last_audio_drw_time', 0)
            if last_audio > 0 and now - last_audio > 3:
                last_drw = getattr(self, '_last_drw_time', 0)
                if last_drw > 0 and now - last_drw < 3:
                    log.info("Audio keepalive: re-requesting audio (audio gap=%.1fs)",
                             now - last_audio)
                    await self._send_start_audio()
            # No video yet — re-request. The "video stale" branch above only
            # fires once last_video > 0, so without this an audio-only DRW
            # stream silently keeps the session "healthy" forever.
            if last_video == 0 and hasattr(self, '_session_start'):
                if now - self._session_start > 5:
                    log.info("Video keepalive: no video yet, re-requesting...")
                    self._session_start = now  # Reset to avoid spam
                    await self._send_start_video()
                    await self._send_start_audio()

    async def _send_login(self):
        # Send get_status first (matches pcap behavior — camera returns device info)
        cgi = (f"GET /get_status.cgi?"
               f"loginuse={self.username}&loginpas={self.password}"
               f"&user={self.username}&pwd={self.password}&")
        await self._send_cmd(cgi)

    async def _send_start_video(self):
        # streamid=10 = main stream (H.264, 1080p)
        cgi = (f"GET /livestream.cgi?"
               f"streamid=10&substream=1"
               f"&loginuse={self.username}&loginpas={self.password}"
               f"&user={self.username}&pwd={self.password}&")
        await self._send_cmd(cgi)

    async def _send_start_audio(self):
        """Request audio stream from camera.
        The Eye4 app calls PPPPStartAudio() natively, which sends
        audiostream.cgi to start audio on channel 2."""
        # Clear audio channel dedup set — camera restarts DRW indices from 0
        # on each audio request, so old indices would be rejected as retransmissions.
        if CH_AUDIO in self._seen_drw_indices:
            self._seen_drw_indices[CH_AUDIO].clear()
        self._drw_high_water[CH_AUDIO] = -1
        # Reset AudioReassembly so reorder buffer starts fresh (otherwise
        # _next_expected_idx would be high and new index-0 packets get dropped)
        self._audio_reassembly = None
        cgi = (f"GET /audiostream.cgi?"
               f"streamid=10"
               f"&loginuse={self.username}&loginpas={self.password}"
               f"&user={self.username}&pwd={self.password}&")
        log.info("Requesting audio stream...")
        await self._send_cmd(cgi)

    async def _send_set_alarm_server(self, alarm_server_addr: str):
        """Redirect camera alarm notifications to our local HTTP listener."""
        cgi = (f"GET /set_factory_param.cgi?alarm_server={alarm_server_addr}"
               f"&loginuse={self.username}&loginpas={self.password}"
               f"&user={self.username}&pwd={self.password}&")
        log.info("Setting alarm_server → %s", alarm_server_addr)
        await self._send_cmd(cgi)

    async def _send_start_video_combined(self):
        """Send multiple CGI commands packed into a single DRW payload.
        The pcap shows the app does this — packs get_record + get_status +
        get_params + livestream into one DRW packet."""
        cgis = [
            (f"GET /get_status.cgi?"
             f"loginuse={self.username}&loginpas={self.password}"
             f"&user={self.username}&pwd={self.password}&"),
            (f"GET /livestream.cgi?"
             f"streamid=10&substream=1"
             f"&loginuse={self.username}&loginpas={self.password}"
             f"&user={self.username}&pwd={self.password}&"),
            (f"GET /audiostream.cgi?"
             f"streamid=10"
             f"&loginuse={self.username}&loginpas={self.password}"
             f"&user={self.username}&pwd={self.password}&"),
        ]
        # Pack all CGI commands into one payload
        combined = b""
        for cgi in cgis:
            combined += build_cgi_command(cgi)

        if not self.enc_mode:
            log.error("Cannot send DRW: encryption mode not set!")
            return

        pkt = build_drw_packet(CH_CMD, self._cmd_index, combined,
                               self.p2p_key, self.enc_mode)
        self._cmd_index = (self._cmd_index + 1) & 0xFFFF

        addr = self._get_drw_addr()
        if addr and self.transport and not self.transport.is_closing():
            log.info("Sending combined CGI DRW (%d bytes, %d commands) to %s:%d",
                     len(combined), len(cgis), addr[0], addr[1])
            self.transport.sendto(pkt, addr)

    def _get_drw_addr(self) -> Optional[tuple[str, int]]:
        """Get the address to send DRW packets to.
        Priority: locked DRW port > discovery port > latest punch port."""
        if not self._active_camera:
            return None
        port = self._drw_port or self._active_camera.discovery_port or self._active_camera.port
        return (self._active_camera.ip, port)

    async def _send_cmd(self, cgi_text: str):
        """Send a CGI command to the camera via DRW on the command channel."""
        if not self.enc_mode:
            log.error("Cannot send DRW: encryption mode not set!")
            return

        payload = build_cgi_command(cgi_text)
        pkt = build_drw_packet(CH_CMD, self._cmd_index, payload,
                               self.p2p_key, self.enc_mode)
        self._cmd_index = (self._cmd_index + 1) & 0xFFFF

        addr = self._get_drw_addr()
        if addr and self.transport and not self.transport.is_closing():
            lvl = logging.DEBUG if "get_status.cgi" in cgi_text else logging.INFO
            log.log(lvl, "Sending DRW CMD (%s) to %s:%d idx=%d cgi=%s",
                    self.enc_mode, addr[0], addr[1],
                    self._cmd_index - 1, cgi_text[:60])
            self.transport.sendto(pkt, addr)

    # --- PSK auto-detection ---

    def try_decrypt_with_psk(self, raw_data: bytes, psk_str: str,
                             enc_mode: str = ENC_P2P) -> Optional[dict]:
        """Try decrypting a raw DRW packet with a given PSK. Returns parsed dict or None."""
        if enc_mode == ENC_XOR_ONLY:
            plaintext = xor_obfuscate(raw_data)
        else:
            if psk_str:
                key4 = p2p_derive_key(psk_str.encode("ascii"))
            else:
                key4 = bytes([0, 0, 0, 0])
            plaintext = p2p_proprietary_decrypt(key4, raw_data)
        return parse_drw_packet(plaintext)


# =============================================================================
# Module 7: Video Frame Reassembly
# =============================================================================

class VideoReassembly:
    """
    Reassemble DRW video fragments into complete video frames.
    Looks for STREAMHEAD markers (55 AA 15 A8) to identify frame boundaries.
    """

    def __init__(self, frame_callback):
        self.frame_callback = frame_callback
        self._buffer = bytearray()
        self._off = 0  # current read offset into _buffer
        self._current_frame_type = FRAME_P
        self._current_timestamp = 0
        self._current_frame_len = 0
        self._current_frame_data = bytearray()
        self._in_frame = False
        self._frames_received = 0

    def _compact(self):
        """Compact buffer when offset gets large to avoid unbounded growth."""
        if self._off > 65536:
            del self._buffer[:self._off]
            self._off = 0

    def feed(self, index: int, data: bytes):
        self._buffer.extend(data)
        self._parse_buffer()

    def _parse_buffer(self):
        buf = self._buffer
        while True:
            avail = len(buf) - self._off
            if not self._in_frame:
                # Use bytearray.find() with start offset — runs in C, no copy
                idx = buf.find(b"\x55\xAA\x15\xA8", self._off)
                if idx < 0:
                    if avail > 3:
                        self._off = len(buf) - 3
                    self._compact()
                    return

                self._off = idx
                avail = len(buf) - self._off

                if avail < STREAMHEAD_SIZE:
                    return

                magic = struct.unpack_from("<I", buf, self._off)[0]
                if magic != STREAMHEAD_MAGIC:
                    self._off += 4
                    continue

                self._current_frame_type = buf[self._off + 4]
                millitime = struct.unpack_from("<H", buf, self._off + 6)[0]
                sectime = struct.unpack_from("<I", buf, self._off + 8)[0]
                self._current_timestamp = sectime * 1000 + millitime
                self._current_frame_len = struct.unpack_from("<I", buf, self._off + 16)[0]

                log.debug("STREAMHEAD: type=%d len=%d ts=%d",
                          self._current_frame_type, self._current_frame_len,
                          self._current_timestamp)

                self._off += STREAMHEAD_SIZE
                self._current_frame_data = bytearray()
                self._in_frame = True

            if self._in_frame:
                remaining = self._current_frame_len - len(self._current_frame_data)
                if remaining <= 0:
                    self._emit_frame()
                    continue
                avail = len(buf) - self._off
                take = min(remaining, avail)
                if take == 0:
                    self._compact()
                    return
                self._current_frame_data.extend(
                    buf[self._off:self._off + take])
                self._off += take
                if len(self._current_frame_data) >= self._current_frame_len:
                    self._emit_frame()

    def _emit_frame(self):
        self._in_frame = False
        self._frames_received += 1
        data = bytes(self._current_frame_data[:self._current_frame_len])
        self._current_frame_data = bytearray()
        if not data:
            return
        log.debug("Frame #%d: type=%d size=%d",
                  self._frames_received, self._current_frame_type, len(data))
        self.frame_callback(self._current_frame_type, self._current_timestamp, data)


# =============================================================================
# Module 7a: Audio Frame Reassembly
# =============================================================================

class AudioReassembly:
    """
    Reassemble DRW audio fragments into audio frames.
    Reads codec type from STREAMHEAD byte 5 and decodes ADPCM if needed.

    Includes a small reorder buffer to handle out-of-order UDP packets.
    DRW packets are held until their index is the next expected one, or
    a timeout forces flushing to avoid stalls.
    """

    # Reorder buffer: hold up to this many out-of-order packets before flushing
    REORDER_WINDOW = 8

    def __init__(self, frame_callback):
        self.frame_callback = frame_callback  # callback(pcm_data: bytes, codec: str)
        self._buffer = bytearray()
        self._in_frame = False
        self._current_frame_len = 0
        self._current_frame_data = bytearray()
        self._frames_received = 0
        self.detected_codec: Optional[str] = None
        self._wire_codec_byte: Optional[int] = None
        # Reorder buffer: index → data
        self._reorder_buf: dict[int, bytes] = {}
        self._next_expected_idx: Optional[int] = None
        self._gap_count = 0  # count of detected gaps (for logging)

    def feed(self, index: int, data: bytes):
        """Feed a DRW audio packet. Packets are reordered by index before
        being appended to the reassembly buffer."""
        if self._next_expected_idx is None:
            # First packet — start sequence from here
            self._next_expected_idx = index

        if index == self._next_expected_idx:
            # In-order: feed directly, then flush any buffered followers
            self._feed_ordered(data)
            self._next_expected_idx = (self._next_expected_idx + 1) & 0xFFFF
            self._flush_reorder_buf()
        elif ((index - self._next_expected_idx) & 0xFFFF) < 0x8000:
            # Future packet (within forward half of 16-bit range): buffer it
            self._reorder_buf[index] = data
            if len(self._reorder_buf) >= self.REORDER_WINDOW:
                # Too many buffered — skip ahead (gap detected)
                self._handle_gap()
        else:
            # Old/duplicate packet — ignore
            pass

    def _flush_reorder_buf(self):
        """Flush consecutive packets from the reorder buffer."""
        while self._next_expected_idx in self._reorder_buf:
            data = self._reorder_buf.pop(self._next_expected_idx)
            self._feed_ordered(data)
            self._next_expected_idx = (self._next_expected_idx + 1) & 0xFFFF

    def _handle_gap(self):
        """Called when reorder buffer is full — lost packet(s) detected.
        Skip to the lowest buffered index and flush, resetting ADPCM state."""
        if not self._reorder_buf:
            return
        self._gap_count += 1
        # Find the lowest buffered index
        min_idx = min(self._reorder_buf.keys(),
                      key=lambda i: (i - self._next_expected_idx) & 0xFFFF)
        gap_size = (min_idx - self._next_expected_idx) & 0xFFFF
        if self._gap_count <= 10 or self._gap_count % 100 == 0:
            log.info("Audio DRW gap #%d: lost %d packet(s) (idx %d→%d)",
                     self._gap_count, gap_size, self._next_expected_idx, min_idx)
        # If we were mid-frame, discard partial data to avoid corrupt audio
        if self._in_frame:
            self._in_frame = False
            self._current_frame_data = bytearray()
            self._buffer.clear()
        self._next_expected_idx = min_idx
        self._flush_reorder_buf()

    def _feed_ordered(self, data: bytes):
        """Feed data that is in the correct sequence order."""
        self._buffer.extend(data)
        self._parse_buffer()

    def _parse_buffer(self):
        while len(self._buffer) > 0:
            if not self._in_frame:
                idx = self._buffer.find(b"\x55\xAA\x15\xA8")
                if idx == 0 and len(self._buffer) >= STREAMHEAD_SIZE:
                    # Read codec byte from STREAMHEAD offset 5
                    codec_byte = self._buffer[5]
                    if self._wire_codec_byte is None:
                        self._wire_codec_byte = codec_byte
                        codec_name = {
                            AUDIO_CODEC_PCM: "PCM",
                            AUDIO_CODEC_ADPCM: "IMA ADPCM",
                            AUDIO_CODEC_G711A: "G.711 a-law",
                            AUDIO_CODEC_G711U: "G.711 u-law",
                        }.get(codec_byte, f"unknown(0x{codec_byte:02X})")
                        log.info("Audio STREAMHEAD codec byte=0x%02X → %s",
                                 codec_byte, codec_name)
                    self._current_frame_len = struct.unpack_from("<I", self._buffer, 16)[0]
                    self._buffer = self._buffer[STREAMHEAD_SIZE:]
                    self._current_frame_data = bytearray()
                    self._in_frame = True
                    continue
                elif idx > 0:
                    # Data before STREAMHEAD — discard it (orphan data from
                    # partial frames or corruption). Don't decode as audio —
                    # it would produce clicks/ticks.
                    log.debug("Audio: discarding %d orphan bytes before STREAMHEAD", idx)
                    self._buffer = self._buffer[idx:]
                    continue
                elif idx < 0:
                    # No STREAMHEAD found — keep last 3 bytes (potential partial magic)
                    # Don't emit this data as audio.
                    if len(self._buffer) > 3:
                        log.debug("Audio: discarding %d bytes (no STREAMHEAD found)",
                                  len(self._buffer) - 3)
                        self._buffer = self._buffer[-3:]
                    return
                else:
                    return

            if self._in_frame:
                remaining = self._current_frame_len - len(self._current_frame_data)
                if remaining <= 0:
                    self._emit_frame()
                    continue
                available = min(remaining, len(self._buffer))
                if available == 0:
                    return
                self._current_frame_data.extend(self._buffer[:available])
                self._buffer = self._buffer[available:]
                if len(self._current_frame_data) >= self._current_frame_len:
                    self._emit_frame()

    def _emit_frame(self):
        self._in_frame = False
        data = bytes(self._current_frame_data[:self._current_frame_len])
        self._current_frame_data = bytearray()
        if data:
            self._frames_received += 1
            self._emit_decoded(data)

    def _emit_decoded(self, data: bytes):
        """Decode audio if needed (ADPCM → PCM) and emit."""
        if not data:
            return
        codec_byte = self._wire_codec_byte
        if codec_byte == AUDIO_CODEC_ADPCM:
            # Camera resets ADPCM state (predictor=0, index=0) at each frame
            # boundary — do NOT carry state across frames or the decoder diverges.
            pcm_le, _, _ = decode_ima_adpcm(data, 0, 0)
            # Convert to G.711 µ-law for universal compatibility.
            # L16 (dynamic PT 97) is not detected by ffmpeg over RTSP/TCP,
            # but PCMU (static PT 0) is universally supported.
            ulaw = pcm16le_to_ulaw(pcm_le)
            self.detected_codec = AUDIO_PCMU
            self.frame_callback(ulaw, AUDIO_PCMU)
        elif codec_byte == AUDIO_CODEC_G711A:
            self.detected_codec = AUDIO_PCMA
            self.frame_callback(data, AUDIO_PCMA)
        elif codec_byte == AUDIO_CODEC_G711U:
            self.detected_codec = AUDIO_PCMU
            self.frame_callback(data, AUDIO_PCMU)
        elif codec_byte == AUDIO_CODEC_PCM:
            # Raw PCM → convert to PCMU for universal compatibility
            ulaw = pcm16le_to_ulaw(data)
            self.detected_codec = AUDIO_PCMU
            self.frame_callback(ulaw, AUDIO_PCMU)
        else:
            # Unknown codec — try to convert as PCM → PCMU (best effort)
            ulaw = pcm16le_to_ulaw(data)
            self.detected_codec = AUDIO_PCMU
            self.frame_callback(ulaw, AUDIO_PCMU)



# =============================================================================
# Module 7b: Camera Session (per-camera lifecycle + auto-reconnect)
# =============================================================================

# Session states
STATE_CONNECTING = "CONNECTING"
STATE_CONNECTED = "CONNECTED"
STATE_STALE = "STALE"
STATE_OFFLINE = "OFFLINE"
STATE_RECONNECTING = "RECONNECTING"
STATE_STOPPED = "STOPPED"


class CameraSession:
    """Manages a single camera: PPPP protocol + RTSP server + reconnection."""

    def __init__(self, camera: CameraInfo, rtsp_port: int,
                 username: str, password: str,
                 p2p_key: Optional[bytes] = None,
                 psk_list: Optional[list[str]] = None,
                 enc_mode: Optional[str] = None,
                 alarm_server_addr: Optional[str] = None,
                 motion_webhook: Optional[str] = None,
                 motion_cooldown: float = 30.0,
                 motion_poll_interval: float = 1.0,
                 bind_addr: str = "127.0.0.1"):
        self.camera = camera
        self.rtsp_port = rtsp_port
        self.username = username
        self.password = password
        self.p2p_key = p2p_key
        self.psk_list = psk_list
        self.enc_mode = enc_mode
        self.alarm_server_addr = alarm_server_addr
        self.motion_webhook = motion_webhook
        self.motion_cooldown = motion_cooldown
        self.motion_poll_interval = motion_poll_interval
        self.bind_addr = bind_addr
        self.motion_handler: Optional[MotionHandler] = None

        self.protocol: Optional[PPPPUnifiedProtocol] = None
        self.rtsp: Optional["RTSPServer"] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.state = STATE_STOPPED
        self._running = False
        self._reconnect_task: Optional[asyncio.Task] = None
        self._last_drw_time: float = 0
        self._last_audio_drw_time: float = 0

    async def start(self):
        """Create protocol, RTSP server, connect to camera."""
        self._running = True
        self.state = STATE_CONNECTING
        log.info("[%s] Starting session on RTSP port %d", self.camera.uid, self.rtsp_port)

        # Create RTSP server for this camera
        self.rtsp = RTSPServer(host=self.bind_addr, port=self.rtsp_port,
                               snapshot_host=self.bind_addr)
        await self.rtsp.start()

        # Create protocol and connect
        await self._create_and_connect()

        # Start reconnect monitor
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _create_and_connect(self):
        """Create a fresh protocol+transport and connect to camera."""
        # Video callback that also tracks last DRW time
        def video_cb(frame_type, timestamp, data):
            self._last_drw_time = asyncio.get_event_loop().time()
            if self.rtsp:
                self.rtsp.push_video_frame(frame_type, timestamp, data)

        def audio_cb(data, codec):
            self._last_drw_time = asyncio.get_event_loop().time()
            if self.rtsp:
                self.rtsp.push_audio_frame(data, codec)

        self.protocol = PPPPUnifiedProtocol(
            username=self.username, password=self.password,
            video_callback=video_cb, audio_callback=audio_cb,
            p2p_key=self.p2p_key,
            psk_list=self.psk_list, enc_mode=self.enc_mode,
            alarm_server_addr=self.alarm_server_addr,
        )

        # Wire motion detection if webhook is configured
        if self.motion_webhook:
            if not self.motion_handler:
                self.motion_handler = MotionHandler(
                    uid=self.camera.uid, webhook=self.motion_webhook,
                    cooldown=self.motion_cooldown)
            self.protocol.alarm_callback = self.motion_handler.on_alarm_status
            self.protocol.alarm_poll_interval = self.motion_poll_interval

        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self.protocol,
            local_addr=("0.0.0.0", 0),
            allow_broadcast=True,
        )
        sock = self.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Run targeted discovery to this camera
        search_pkt = build_lan_search()
        self.transport.sendto(search_pkt, (self.camera.ip, PPPP_PORT))
        # Also broadcast for good measure
        for bcast in get_broadcast_addresses():
            try:
                self.transport.sendto(search_pkt, (bcast, PPPP_PORT))
            except OSError:
                pass

        # Wait for camera to appear
        end_t = asyncio.get_event_loop().time() + 3.0
        while asyncio.get_event_loop().time() < end_t:
            if self.protocol.cameras:
                break
            self.transport.sendto(search_pkt, (self.camera.ip, PPPP_PORT))
            await asyncio.sleep(0.5)

        # Update camera info if IP changed
        for ip, cam in self.protocol.cameras.items():
            if cam.uid == self.camera.uid:
                self.camera.ip = ip
                self.camera.port = cam.port
                self.camera.discovery_port = cam.discovery_port
                break

        # Connect
        await self.protocol.connect_to_camera(self.camera)

        # Wire up RTSP play callback with debounce to avoid flooding
        # the camera with audio requests when go2rtc opens multiple connections
        self._last_audio_request = 0.0
        async def on_rtsp_play():
            if self.protocol and self.protocol.enc_mode:
                now = asyncio.get_event_loop().time()
                if now - self._last_audio_request > 2.0:
                    self._last_audio_request = now
                    await self.protocol._send_start_audio()
        if self.rtsp:
            self.rtsp.play_callback = on_rtsp_play

        self.state = STATE_CONNECTED
        self._last_drw_time = asyncio.get_event_loop().time()
        log.info("[%s] Connected — RTSP at rtsp://%s:%d/", self.camera.uid, self.bind_addr, self.rtsp_port)

    async def stop(self):
        """Clean shutdown."""
        self._running = False
        self.state = STATE_STOPPED
        if self._reconnect_task:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
        if self.motion_handler:
            self.motion_handler.stop()
        if self.protocol:
            await self.protocol.stop()
        if self.rtsp:
            await self.rtsp.stop()
        log.info("[%s] Session stopped", self.camera.uid)

    async def _teardown_protocol(self):
        """Tear down protocol+transport without stopping RTSP server."""
        if self.protocol:
            await self.protocol.stop()
            self.protocol = None
        self.transport = None

    async def _reconnect_loop(self):
        """Monitor connection health, auto-reconnect when camera comes back."""
        stale_logged = False
        while self._running:
            await asyncio.sleep(5)
            if not self._running:
                break

            now = asyncio.get_event_loop().time()

            # Track DRW time from protocol too
            if self.protocol and hasattr(self.protocol, '_last_drw_time'):
                proto_drw = self.protocol._last_drw_time
                if proto_drw > self._last_drw_time:
                    self._last_drw_time = proto_drw
                proto_audio = getattr(self.protocol, '_last_audio_drw_time', 0)
                if proto_audio > self._last_audio_drw_time:
                    self._last_audio_drw_time = proto_audio

            gap = now - self._last_drw_time if self._last_drw_time > 0 else 0

            if self.state == STATE_CONNECTED:
                if gap > 30:
                    log.warning("[%s] No data for %.0fs — camera OFFLINE", self.camera.uid, gap)
                    self.state = STATE_OFFLINE
                    stale_logged = False
                elif gap > 10:
                    if not stale_logged:
                        log.info("[%s] No data for %.0fs — STALE, re-requesting video",
                                 self.camera.uid, gap)
                        stale_logged = True
                    self.state = STATE_STALE
                    if self.protocol and self.protocol.enc_mode:
                        await self.protocol._send_start_video()
                else:
                    if self.state != STATE_CONNECTED or stale_logged:
                        stale_logged = False
                    self.state = STATE_CONNECTED

            elif self.state == STATE_STALE:
                if gap <= 5:
                    log.info("[%s] Video resumed — CONNECTED", self.camera.uid)
                    self.state = STATE_CONNECTED
                    stale_logged = False
                elif gap > 30:
                    log.warning("[%s] No data for %.0fs — camera OFFLINE", self.camera.uid, gap)
                    self.state = STATE_OFFLINE

            elif self.state == STATE_OFFLINE:
                log.info("[%s] Tearing down stale session, entering RECONNECTING", self.camera.uid)
                await self._teardown_protocol()
                # Clear cached I-frame so Scrypted doesn't serve a stale snapshot
                if self.rtsp:
                    self.rtsp._cached_iframe = None
                self.state = STATE_RECONNECTING
                # Wait before first reconnect to let camera sessions expire
                # and stagger reconnects across cameras
                import random
                jitter = random.uniform(5, 15)
                log.info("[%s] Waiting %.0fs before reconnect attempt...", self.camera.uid, jitter)
                await asyncio.sleep(jitter)

            elif self.state == STATE_RECONNECTING:
                log.info("[%s] Attempting reconnect to %s...", self.camera.uid, self.camera.ip)
                try:
                    await self._attempt_reconnect()
                except Exception as e:
                    log.warning("[%s] Reconnect failed: %s — retrying in 15s", self.camera.uid, e)
                    await asyncio.sleep(10)  # Extra backoff (total ~15s with loop sleep)

    async def _attempt_reconnect(self):
        """Try to reconnect to the camera using its last known address.
        Avoids creating probe sessions that count against camera's user limit."""
        log.info("[%s] Reconnecting directly to %s (no probe)...",
                 self.camera.uid, self.camera.ip)
        try:
            await self._create_and_connect()
        except Exception as e:
            log.warning("[%s] Direct reconnect failed: %s", self.camera.uid, e)


# =============================================================================
# Module 8: RTSP Server
# =============================================================================

class RTSPServer:
    """Minimal RTSP server that serves H.264/H.265 video + audio over RTP (TCP interleaved)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8554,
                 play_callback=None, snapshot_host: str = "0.0.0.0"):
        self.host = host
        self.port = port
        self.snapshot_host = snapshot_host
        self.play_callback = play_callback  # Called when a client starts PLAY
        self._server: Optional[asyncio.Server] = None
        self._clients: list["RTSPClient"] = []
        # Video state
        self._sps: Optional[bytes] = None
        self._pps: Optional[bytes] = None
        self._vps: Optional[bytes] = None  # HEVC VPS
        self._codec: Optional[str] = None  # "h264" or "h265"
        self._rtp_seq = 0
        self._rtp_ts = 0
        self._ssrc = random.randint(0, 0xFFFFFFFF)
        self._frame_queue: asyncio.Queue = asyncio.Queue(maxsize=300)
        self._sender_task: Optional[asyncio.Task] = None
        self._running = False
        self.frames_sent = 0
        # Audio state
        self._audio_codec: Optional[str] = None  # AUDIO_PCM_L16, AUDIO_PCMA, AUDIO_PCMU
        self._audio_rtp_seq = 0
        self._audio_rtp_ts = 0
        self._audio_ssrc = random.randint(0, 0xFFFFFFFF)
        self._audio_queue: asyncio.Queue = asyncio.Queue(maxsize=300)
        self._audio_sender_task: Optional[asyncio.Task] = None
        self._audio_packets_received = 0
        self._last_audio_push_time: float = 0
        self.audio_frames_sent = 0
        # Cached last I-frame for instant start of new clients
        self._cached_iframe: Optional[bytes] = None

    async def start(self):
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port)
        self._sender_task = asyncio.create_task(self._frame_sender())
        self._audio_sender_task = asyncio.create_task(self._audio_sender())
        # Snapshot HTTP server on RTSP port + 1000
        self._snapshot_server = await asyncio.start_server(
            self._handle_snapshot_http, self.snapshot_host, self.port + 1000)
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        log.info("RTSP server listening on %s (snapshot at :%d/snapshot.jpg)", addrs, self.port + 1000)

    async def stop(self):
        self._running = False
        for task in [self._sender_task, self._audio_sender_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._snapshot_server:
            self._snapshot_server.close()
            await self._snapshot_server.wait_closed()
        for c in self._clients:
            c.close()

    async def _handle_snapshot_http(self, reader: asyncio.StreamReader,
                                      writer: asyncio.StreamWriter):
        """Serve /snapshot.jpg — convert cached I-frame to JPEG via ffmpeg."""
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not raw:
                return

            if not self._cached_iframe or not self._sps or not self._pps:
                writer.write(b"HTTP/1.0 503 No Frame\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            # Build raw H.264 byte stream: SPS + PPS + IDR frame
            start_code = b'\x00\x00\x00\x01'
            h264_data = start_code + self._sps + start_code + self._pps + self._cached_iframe

            # Pipe through ffmpeg to get JPEG
            proc = await asyncio.create_subprocess_exec(
                "ffmpeg", "-hide_banner", "-loglevel", "error",
                "-f", "h264", "-i", "pipe:0",
                "-frames:v", "1", "-f", "image2", "-c:v", "mjpeg",
                "-q:v", "5", "pipe:1",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            jpeg_data, stderr = await asyncio.wait_for(
                proc.communicate(input=h264_data), timeout=5.0)

            if proc.returncode != 0 or not jpeg_data:
                log.warning("Snapshot ffmpeg failed: %s", stderr.decode(errors="replace")[:200])
                writer.write(b"HTTP/1.0 500 Conversion Failed\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            resp = (f"HTTP/1.0 200 OK\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(jpeg_data)}\r\n"
                    f"Cache-Control: no-cache\r\n\r\n").encode()
            writer.write(resp + jpeg_data)
            await writer.drain()

        except Exception as e:
            log.warning("Snapshot request error: %s", e)
        finally:
            writer.close()

    def push_video_frame(self, frame_type: int, timestamp: int, data: bytes):
        if frame_type == FRAME_I or frame_type == 0:
            self._extract_sps_pps(data)
        try:
            self._frame_queue.put_nowait((frame_type, timestamp, data))
        except asyncio.QueueFull:
            try:
                self._frame_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self._frame_queue.put_nowait((frame_type, timestamp, data))
            except asyncio.QueueFull:
                pass

    def push_audio_frame(self, data: bytes, codec: str):
        """Push decoded audio data. Codec is determined by AudioReassembly from STREAMHEAD."""
        self._audio_packets_received += 1
        now = asyncio.get_event_loop().time()
        if not self._audio_codec or self._audio_codec != codec:
            self._audio_codec = codec
            log.info("Audio codec set to: %s", codec)
        # Log inter-frame timing for first 50 frames and every 500th
        if self._audio_packets_received <= 50 or self._audio_packets_received % 500 == 0:
            delta = (now - self._last_audio_push_time) * 1000 if self._last_audio_push_time else 0
            log.info("Audio frame #%d: %d bytes, delta=%.1fms, qlen=%d codec=%s",
                     self._audio_packets_received, len(data), delta,
                     self._audio_queue.qsize(), self._audio_codec)
        self._last_audio_push_time = now
        try:
            self._audio_queue.put_nowait(data)
        except asyncio.QueueFull:
            try:
                self._audio_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self._audio_queue.put_nowait(data)
            except asyncio.QueueFull:
                pass

    def _extract_sps_pps(self, data: bytes):
        nals = self._split_nals(data)
        for nal in nals:
            if not nal or len(nal) < 2:
                continue
            # Detect codec from NAL headers.
            # HEVC NAL header: 2 bytes, type = (byte0 >> 1) & 0x3F
            #   Valid HEVC: forbidden_zero_bit=0, nuh_layer_id MSB=0 → byte0 & 0x81 == 0
            #   VPS has temporal_id_plus1=1 → byte1 & 0x07 == 1
            # H.264 NAL header: 1 byte, type = byte0 & 0x1F
            is_hevc_nal = (nal[0] & 0x81) == 0 and (nal[1] & 0x07) == 1
            hevc_type = (nal[0] >> 1) & 0x3F if is_hevc_nal else -1
            h264_type = nal[0] & 0x1F

            # Once codec is locked, don't switch
            if hevc_type == 32 and self._codec != "h264":  # VPS — HEVC
                self._codec = "h265"
                self._vps = nal
                log.info("Extracted HEVC VPS: %d bytes (codec=h265)", len(nal))
            elif hevc_type == 33 and self._codec == "h265":  # HEVC SPS
                self._sps = nal
                log.info("Extracted HEVC SPS: %d bytes", len(nal))
            elif hevc_type == 34 and self._codec == "h265":  # HEVC PPS
                self._pps = nal
                log.info("Extracted HEVC PPS: %d bytes", len(nal))
            elif h264_type == 7 and self._codec != "h265":  # H.264 SPS
                self._codec = "h264"
                self._sps = nal
                log.info("Extracted H.264 SPS: %d bytes (codec=h264)", len(nal))
            elif h264_type == 8 and self._codec == "h264":  # H.264 PPS
                self._pps = nal
                log.info("Extracted H.264 PPS: %d bytes", len(nal))

    @staticmethod
    def _split_nals(data: bytes) -> list[bytes]:
        """Split NAL units using C-speed bytes.find() for start code scanning."""
        nals = []
        # Find all start code positions using bytes.find()
        starts = []  # (nal_data_offset, start_code_offset) tuples
        i = 0
        dlen = len(data)
        while i < dlen - 2:
            j = data.find(b'\x00\x00\x01', i)
            if j < 0:
                break
            # Check for 4-byte start code (00 00 00 01)
            if j > 0 and data[j - 1] == 0:
                starts.append((j + 3, j - 1))
            else:
                starts.append((j + 3, j))
            i = j + 3

        for k, (nal_start, _sc_start) in enumerate(starts):
            if k + 1 < len(starts):
                nals.append(data[nal_start:starts[k + 1][1]])
            else:
                nals.append(data[nal_start:])

        if not starts and data:
            nals.append(data)
        return nals

    async def _send_frame_to_clients(self, data: bytes, clients: list):
        """Split NALs and send via RTP to given clients.
        Batches all RTP packets into a single write+drain per client
        to avoid dozens of event-loop yields per frame."""
        nals = self._split_nals(data)
        # Build all RTP packets for this frame
        all_packets = []
        for nal in nals:
            if not nal:
                continue
            all_packets.extend(self._packetize_nal(nal))
        if not all_packets:
            return
        for client in clients:
            await client.send_rtp_batch(all_packets)

    async def _frame_sender(self):
        while self._running:
            try:
                frame_type, timestamp, data = await asyncio.wait_for(
                    self._frame_queue.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            is_iframe = (frame_type == FRAME_I or frame_type == 0)

            # Always cache I-frames, even when no clients are playing,
            # so new clients can get instant video start.
            if is_iframe:
                self._cached_iframe = data

            playing_clients = [c for c in self._clients if c.playing]
            if not playing_clients:
                continue

            # Check for new clients that need their first I-frame
            new_clients = [c for c in playing_clients if not c.got_iframe]
            if new_clients:
                # Send cached I-frame for instant video start.
                iframe_data = data if is_iframe else self._cached_iframe
                if not iframe_data:
                    log.info(":%d New client waiting for I-frame (cached=%s, is_iframe=%s, ft=%d)",
                             self.port, self._cached_iframe is not None, is_iframe, frame_type)
                if iframe_data:
                    for c in new_clients:
                        c.got_iframe = True
                    log.info(":%d Sending %s I-frame (%d bytes) to %d new client(s)",
                             self.port, "live" if is_iframe else "cached",
                             len(iframe_data), len(new_clients))
                    if not is_iframe:
                        await self._send_frame_to_clients(iframe_data, new_clients)
                        self._rtp_ts = (self._rtp_ts + 3000) & 0xFFFFFFFF

            # Send current frame to all clients that have received an I-frame
            ready_clients = [c for c in playing_clients if c.got_iframe]
            if not ready_clients:
                continue

            await self._send_frame_to_clients(data, ready_clients)
            self._rtp_ts = (self._rtp_ts + 3000) & 0xFFFFFFFF
            self.frames_sent += 1
            if self.frames_sent % 100 == 0:
                log.info(":%d Sent %d frames to %d clients (playing=%d, new=%d)",
                         self.port, self.frames_sent, len(ready_clients),
                         len(playing_clients), len([c for c in playing_clients if not c.got_iframe]))

    async def _audio_sender(self):
        while self._running:
            try:
                data = await asyncio.wait_for(
                    self._audio_queue.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            # Gate audio on got_iframe too — don't send audio before the client
            # has received its first video I-frame, to avoid A/V timestamp mismatch.
            playing_clients = [c for c in self._clients
                               if c.playing and c.audio_setup and c.got_iframe]
            if not playing_clients:
                continue

            # Packetize audio into RTP — one packet per audio chunk
            # G.711 (PCMU/PCMA) = 1 byte per sample, no byte-swap needed
            MAX_AUDIO_RTP = 1400
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + MAX_AUDIO_RTP]
                offset += MAX_AUDIO_RTP
                marker = (offset >= len(data))
                rtp = self._build_audio_rtp_header(marker=marker) + chunk
                for client in playing_clients:
                    await client.send_audio_rtp(rtp)

            # Advance audio timestamp by number of samples
            # G.711 = 1 byte per sample; L16 = 2 bytes per sample (fallback)
            if self._audio_codec == AUDIO_PCM_L16:
                samples = len(data) // 2
            else:
                samples = len(data)
            self._audio_rtp_ts = (self._audio_rtp_ts + samples) & 0xFFFFFFFF
            self.audio_frames_sent += 1
            if self.audio_frames_sent % 500 == 0:
                log.info("Sent %d audio frames to %d clients",
                         self.audio_frames_sent, len(playing_clients))

    def _build_audio_rtp_header(self, marker: bool = False) -> bytes:
        byte0 = 0x80
        # Payload type: 97 for dynamic (PCM L16), 8 for PCMA, 0 for PCMU
        if self._audio_codec == AUDIO_PCMA:
            pt = 8
        elif self._audio_codec == AUDIO_PCMU:
            pt = 0
        else:
            pt = 97  # Dynamic PT for L16
        byte1 = pt | (0x80 if marker else 0x00)
        seq = self._audio_rtp_seq
        self._audio_rtp_seq = (self._audio_rtp_seq + 1) & 0xFFFF
        return struct.pack("!BBHII", byte0, byte1, seq, self._audio_rtp_ts, self._audio_ssrc)

    def _packetize_nal(self, nal: bytes) -> list[bytes]:
        MAX_RTP_PAYLOAD = 1400
        packets = []

        if self._codec == "h265":
            return self._packetize_nal_hevc(nal)

        # H.264 FU-A packetization (RFC 6184)
        if len(nal) <= MAX_RTP_PAYLOAD:
            rtp = self._build_rtp_header(marker=True) + nal
            packets.append(rtp)
        else:
            nal_header = nal[0]
            nal_type = nal_header & 0x1F
            nri = nal_header & 0x60
            payload = nal[1:]
            offset = 0
            while offset < len(payload):
                end = min(offset + MAX_RTP_PAYLOAD - 2, len(payload))
                is_first = (offset == 0)
                is_last = (end >= len(payload))
                fu_indicator = nri | 28
                fu_header = nal_type
                if is_first:
                    fu_header |= 0x80
                if is_last:
                    fu_header |= 0x40
                rtp = (self._build_rtp_header(marker=is_last)
                       + bytes([fu_indicator, fu_header])
                       + payload[offset:end])
                packets.append(rtp)
                offset = end
        return packets

    def _packetize_nal_hevc(self, nal: bytes) -> list[bytes]:
        """HEVC RTP packetization (RFC 7798)."""
        MAX_RTP_PAYLOAD = 1400
        packets = []

        if len(nal) <= MAX_RTP_PAYLOAD:
            rtp = self._build_rtp_header(marker=True) + nal
            packets.append(rtp)
        else:
            # HEVC FU (Fragmentation Unit)
            # NAL header is 2 bytes: [F(1)|Type(6)|LayerId(6)] [TID(3)]
            nal_type = (nal[0] >> 1) & 0x3F
            # FU indicator: same as NAL header but type=49 (FU)
            fu_indicator_b0 = (nal[0] & 0x81) | (49 << 1)  # Keep F and LayerId high bits, set type=49
            fu_indicator_b1 = nal[1]  # Keep TID
            payload = nal[2:]  # Skip 2-byte NAL header
            offset = 0
            while offset < len(payload):
                end = min(offset + MAX_RTP_PAYLOAD - 3, len(payload))  # 3 = 2 byte FU indicator + 1 byte FU header
                is_first = (offset == 0)
                is_last = (end >= len(payload))
                fu_header = nal_type
                if is_first:
                    fu_header |= 0x80
                if is_last:
                    fu_header |= 0x40
                rtp = (self._build_rtp_header(marker=is_last)
                       + bytes([fu_indicator_b0, fu_indicator_b1, fu_header])
                       + payload[offset:end])
                packets.append(rtp)
                offset = end
        return packets

    def _build_rtp_header(self, marker: bool = False) -> bytes:
        byte0 = 0x80
        byte1 = 96 | (0x80 if marker else 0x00)
        seq = self._rtp_seq
        self._rtp_seq = (self._rtp_seq + 1) & 0xFFFF
        return struct.pack("!BBHII", byte0, byte1, seq, self._rtp_ts, self._ssrc)

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        client = RTSPClient(self, reader, writer)
        self._clients.append(client)
        addr = writer.get_extra_info("peername")
        log.info("RTSP client connected from %s", addr)
        try:
            await client.run()
        except Exception as e:
            log.debug("RTSP client %s error: %s", addr, e)
        finally:
            client.close()
            if client in self._clients:
                self._clients.remove(client)
            log.info("RTSP client %s disconnected", addr)

    def _get_audio_sdp_lines(self) -> str:
        """Return SDP media section for audio, or empty string if no audio detected."""
        if not self._audio_codec:
            return ""
        if self._audio_codec == AUDIO_PCMA:
            return (
                "m=audio 0 RTP/AVP 8\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=control:streamid=1\r\n"
            )
        elif self._audio_codec == AUDIO_PCMU:
            return (
                "m=audio 0 RTP/AVP 0\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=control:streamid=1\r\n"
            )
        else:
            # PCM L16 — dynamic payload type 97
            return (
                "m=audio 0 RTP/AVP 97\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=rtpmap:97 L16/8000/1\r\n"
                "a=control:streamid=1\r\n"
            )

    def get_sdp(self, client_ip: str) -> str:
        import base64

        audio_sdp = self._get_audio_sdp_lines()

        if self._codec == "h265":
            # HEVC SDP (RFC 7798)
            vps_b64 = base64.b64encode(self._vps).decode() if self._vps else ""
            sps_b64 = base64.b64encode(self._sps).decode() if self._sps else ""
            pps_b64 = base64.b64encode(self._pps).decode() if self._pps else ""
            fmtp_parts = []
            if vps_b64:
                fmtp_parts.append(f"sprop-vps={vps_b64}")
            if sps_b64:
                fmtp_parts.append(f"sprop-sps={sps_b64}")
            if pps_b64:
                fmtp_parts.append(f"sprop-pps={pps_b64}")
            fmtp_str = "; ".join(fmtp_parts) if fmtp_parts else ""
            return (
                "v=0\r\n"
                f"o=- {int(time.time())} 1 IN IP4 {client_ip}\r\n"
                "s=Eye4 Camera\r\n"
                "t=0 0\r\n"
                "a=range:npt=0-\r\n"
                "m=video 0 RTP/AVP 96\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=rtpmap:96 H265/90000\r\n"
                f"a=fmtp:96 {fmtp_str}\r\n"
                "a=control:streamid=0\r\n"
                + audio_sdp
            )
        else:
            # H.264 SDP (RFC 6184)
            sps_b64 = base64.b64encode(self._sps).decode() if self._sps else ""
            pps_b64 = base64.b64encode(self._pps).decode() if self._pps else ""
            if self._sps and len(self._sps) >= 4:
                profile_level_id = f"{self._sps[1]:02X}{self._sps[2]:02X}{self._sps[3]:02X}"
            else:
                profile_level_id = "640028"
            sprop = ""
            if sps_b64 and pps_b64:
                sprop = f";sprop-parameter-sets={sps_b64},{pps_b64}"
            return (
                "v=0\r\n"
                f"o=- {int(time.time())} 1 IN IP4 {client_ip}\r\n"
                "s=Eye4 Camera\r\n"
                "t=0 0\r\n"
                "a=range:npt=0-\r\n"
                "m=video 0 RTP/AVP 96\r\n"
                "c=IN IP4 0.0.0.0\r\n"
                "a=rtpmap:96 H264/90000\r\n"
                f"a=fmtp:96 packetization-mode=1;profile-level-id={profile_level_id}{sprop}\r\n"
                "a=control:streamid=0\r\n"
                + audio_sdp
            )


class RTSPClient:
    """Handles a single RTSP client connection."""

    def __init__(self, server: RTSPServer, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.playing = False
        self.interleaved = True
        # Video interleaved channels
        self.rtp_channel = 0
        self.rtcp_channel = 1
        # Audio interleaved channels
        self.audio_rtp_channel = 2
        self.audio_rtcp_channel = 3
        self.audio_setup = False  # True after audio SETUP
        self.got_iframe = False  # True after first I-frame sent to this client
        self._cseq = 0
        self._session_id = f"{random.randint(10000000, 99999999)}"
        self._setup_count = 0  # Track which SETUP this is (0=video, 1=audio)

    def close(self):
        self.playing = False
        if not self.writer.is_closing():
            self.writer.close()

    async def run(self):
        while True:
            try:
                line = await self.reader.readline()
            except (ConnectionError, asyncio.IncompleteReadError):
                break
            if not line:
                break
            line = line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            method = parts[0]
            uri = parts[1]
            headers = {}
            while True:
                hline = await self.reader.readline()
                hline = hline.decode("utf-8", errors="replace").strip()
                if not hline:
                    break
                if ":" in hline:
                    key, val = hline.split(":", 1)
                    headers[key.strip()] = val.strip()

            self._cseq = int(headers.get("CSeq", "0"))

            if method == "OPTIONS":
                await self._send_options()
            elif method == "DESCRIBE":
                await self._send_describe(uri)
            elif method == "SETUP":
                await self._send_setup(uri, headers)
            elif method == "PLAY":
                await self._send_play()
            elif method == "TEARDOWN":
                await self._send_teardown()
                break
            elif method in ("GET_PARAMETER", "SET_PARAMETER"):
                # Keepalive — return 200 OK (Scrypted and other clients use this)
                resp = (f"RTSP/1.0 200 OK\r\n"
                        f"CSeq: {self._cseq}\r\n"
                        f"Session: {self._session_id}\r\n\r\n")
                self.writer.write(resp.encode())
                await self.writer.drain()
            else:
                await self._send_response(405, "Method Not Allowed")

    async def send_rtp(self, rtp_packet: bytes):
        if not self.playing or self.writer.is_closing():
            return
        if self.interleaved:
            header = struct.pack("!BcH", 0x24, bytes([self.rtp_channel]),
                                 len(rtp_packet))
            try:
                self.writer.write(header + rtp_packet)
                await asyncio.wait_for(self.writer.drain(), timeout=2.0)
            except (ConnectionError, OSError):
                self.playing = False
            except asyncio.TimeoutError:
                log.warning("RTP drain timeout — dropping slow client")
                self.playing = False

    async def send_rtp_batch(self, rtp_packets: list):
        """Send multiple RTP packets with a single drain() call."""
        if not self.playing or self.writer.is_closing():
            return
        if self.interleaved:
            ch = bytes([self.rtp_channel])
            try:
                for pkt in rtp_packets:
                    header = struct.pack("!BcH", 0x24, ch, len(pkt))
                    self.writer.write(header + pkt)
                await asyncio.wait_for(self.writer.drain(), timeout=2.0)
            except (ConnectionError, OSError):
                self.playing = False
            except asyncio.TimeoutError:
                log.warning("RTP drain timeout — dropping slow client")
                self.playing = False

    async def send_audio_rtp(self, rtp_packet: bytes):
        if not self.playing or not self.audio_setup or self.writer.is_closing():
            return
        if self.interleaved:
            header = struct.pack("!BcH", 0x24, bytes([self.audio_rtp_channel]),
                                 len(rtp_packet))
            try:
                self.writer.write(header + rtp_packet)
                await asyncio.wait_for(self.writer.drain(), timeout=2.0)
            except (ConnectionError, OSError):
                self.playing = False
            except asyncio.TimeoutError:
                log.warning("Audio RTP drain timeout — dropping slow client")
                self.playing = False

    async def _send_options(self):
        resp = (f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n\r\n")
        self.writer.write(resp.encode())
        await self.writer.drain()

    async def _send_describe(self, uri: str):
        addr = self.writer.get_extra_info("sockname")
        server_ip = addr[0] if addr else "127.0.0.1"
        sdp = self.server.get_sdp(server_ip)
        content_base = uri.rstrip("/") + "/"
        resp = (f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Content-Type: application/sdp\r\n"
                f"Content-Base: {content_base}\r\n"
                f"Content-Length: {len(sdp)}\r\n\r\n{sdp}")
        self.writer.write(resp.encode())
        await self.writer.drain()

    async def _send_setup(self, uri: str, headers: dict):
        # Determine if this is video (streamid=0) or audio (streamid=1) SETUP
        is_audio = "streamid=1" in uri or "trackID=1" in uri or "audio" in uri.lower()
        # Also use SETUP order: first SETUP = video, second = audio
        if not is_audio and self._setup_count > 0:
            is_audio = True

        transport = headers.get("Transport", "")
        if "TCP" in transport or "interleaved" in transport:
            self.interleaved = True
            rtp_ch = None
            rtcp_ch = None
            for part in transport.split(";"):
                if part.strip().startswith("interleaved="):
                    channels = part.split("=")[1]
                    ch = channels.split("-")
                    rtp_ch = int(ch[0])
                    rtcp_ch = int(ch[1]) if len(ch) > 1 else rtp_ch + 1

            if is_audio:
                self.audio_rtp_channel = rtp_ch if rtp_ch is not None else 2
                self.audio_rtcp_channel = rtcp_ch if rtcp_ch is not None else 3
                self.audio_setup = True
                transport_resp = (f"RTP/AVP/TCP;unicast;"
                                  f"interleaved={self.audio_rtp_channel}-{self.audio_rtcp_channel}")
                log.info("RTSP SETUP audio: interleaved=%d-%d",
                         self.audio_rtp_channel, self.audio_rtcp_channel)
            else:
                self.rtp_channel = rtp_ch if rtp_ch is not None else 0
                self.rtcp_channel = rtcp_ch if rtcp_ch is not None else 1
                transport_resp = (f"RTP/AVP/TCP;unicast;"
                                  f"interleaved={self.rtp_channel}-{self.rtcp_channel}")
                log.info("RTSP SETUP video: interleaved=%d-%d",
                         self.rtp_channel, self.rtcp_channel)
        else:
            # Client requested UDP — we only support TCP interleaved.
            # Return 461 so the client retries with TCP transport.
            log.info("RTSP SETUP: client requested UDP, returning 461 Unsupported Transport")
            resp = (f"RTSP/1.0 461 Unsupported Transport\r\n"
                    f"CSeq: {self._cseq}\r\n\r\n")
            self.writer.write(resp.encode())
            await self.writer.drain()
            return

        self._setup_count += 1
        resp = (f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Transport: {transport_resp}\r\n"
                f"Session: {self._session_id}\r\n\r\n")
        self.writer.write(resp.encode())
        await self.writer.drain()

    async def _send_play(self):
        self.playing = True
        self.got_iframe = False  # Wait for next I-frame before sending video
        rtp_info = (f"url=streamid=0;seq={self.server._rtp_seq};"
                    f"rtptime={self.server._rtp_ts}")
        if self.audio_setup:
            rtp_info += (f",url=streamid=1;seq={self.server._audio_rtp_seq};"
                         f"rtptime={self.server._audio_rtp_ts}")
        resp = (f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Session: {self._session_id}\r\n"
                f"Range: npt=0.000-\r\n"
                f"RTP-Info: {rtp_info}\r\n\r\n")
        self.writer.write(resp.encode())
        await self.writer.drain()
        log.info("RTSP client started playing")
        # Notify the PPPP layer to request fresh video
        if self.server.play_callback:
            asyncio.ensure_future(self.server.play_callback())

    async def _send_teardown(self):
        self.playing = False
        resp = (f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Session: {self._session_id}\r\n\r\n")
        self.writer.write(resp.encode())
        await self.writer.drain()

    async def _send_response(self, code: int, reason: str):
        resp = (f"RTSP/1.0 {code} {reason}\r\n"
                f"CSeq: {self._cseq}\r\n\r\n")
        self.writer.write(resp.encode())
        await self.writer.drain()


# =============================================================================
# Module 9: LAN Discovery
# =============================================================================

def get_broadcast_addresses() -> list[str]:
    broadcasts = ["255.255.255.255"]
    if HAS_NETIFACES:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        bcast = addr_info.get("broadcast")
                        ip = addr_info.get("addr", "")
                        if bcast and bcast not in broadcasts:
                            broadcasts.append(bcast)
                            log.info("  Interface %s: ip=%s broadcast=%s", iface, ip, bcast)
        except Exception as e:
            log.warning("netifaces error: %s", e)
    else:
        log.info("  netifaces not installed — using fallback")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        parts[3] = "255"
        guess = ".".join(parts)
        if guess not in broadcasts:
            broadcasts.append(guess)
            log.info("  Guessed broadcast: %s (from local IP %s)", guess, local_ip)
    except Exception:
        pass
    return broadcasts


async def discover_and_create_protocol(
        username: str, password: str, timeout: float = 5.0,
        target_ip: Optional[str] = None,
        video_callback=None,
        p2p_key: Optional[bytes] = None,
        psk_list: Optional[list[str]] = None,
        enc_mode: Optional[str] = None,
) -> tuple[PPPPUnifiedProtocol, asyncio.DatagramTransport, list[CameraInfo]]:
    """Create the unified protocol, run discovery, and return everything."""
    loop = asyncio.get_event_loop()

    protocol = PPPPUnifiedProtocol(
        username=username, password=password,
        video_callback=video_callback, p2p_key=p2p_key,
        psk_list=psk_list, enc_mode=enc_mode,
    )

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=("0.0.0.0", 0),
        allow_broadcast=True,
    )

    sock = transport.get_extra_info("socket")
    if sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    targets: list[tuple[str, int]] = []
    if target_ip:
        targets.append((target_ip, PPPP_PORT))
        log.info("Will send LAN_SEARCH directly to %s:%d", target_ip, PPPP_PORT)

    log.info("Detecting network interfaces...")
    for bcast in get_broadcast_addresses():
        targets.append((bcast, PPPP_PORT))

    search_pkt = build_lan_search()
    log.info("Broadcasting to %d targets over %ds...", len(targets), timeout)

    packets_sent = 0
    for i in range(5):
        for dest_ip, dest_port in targets:
            try:
                transport.sendto(search_pkt, (dest_ip, dest_port))
                packets_sent += 1
            except OSError as e:
                log.warning("Failed to send to %s:%d: %s", dest_ip, dest_port, e)
        await asyncio.sleep(min(1.0, timeout / 5))

    remaining = timeout - 5 * min(1.0, timeout / 5)
    if remaining > 0:
        await asyncio.sleep(remaining)

    cameras = list(protocol.cameras.values())
    log.info("Discovery complete: sent=%d cameras=%d", packets_sent, len(cameras))
    return protocol, transport, cameras


# =============================================================================
# Module 10: Diagnostics
# =============================================================================

async def run_diag(args):
    """Network diagnostics mode."""
    log.info("=== Eye4 Network Diagnostics ===")
    log.info("")

    log.info("--- Local Network Interfaces ---")
    if HAS_NETIFACES:
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for a in addrs[netifaces.AF_INET]:
                        log.info("  %s: ip=%s netmask=%s broadcast=%s",
                                 iface, a.get("addr"), a.get("netmask"), a.get("broadcast"))
        except Exception as e:
            log.warning("  netifaces error: %s", e)
    else:
        log.info("  netifaces not installed — pip install netifaces for full interface info")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        log.info("  Default route IP: %s", local_ip)
    except Exception:
        pass
    log.info("")

    log.info("--- P2P Key Test ---")
    for psk_str in KNOWN_PSKS:
        if psk_str:
            key4 = p2p_derive_key(psk_str.encode("ascii"))
        else:
            key4 = bytes([0, 0, 0, 0])
        log.info("  PSK=%r key=%s", psk_str, key4.hex())
    log.info("")

    log.info("--- UDP Broadcast Test ---")
    search_pkt = build_lan_search()
    log.info("LAN_SEARCH raw bytes: %s", search_pkt.hex())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.1)
    sock.bind(("0.0.0.0", 0))
    local_port = sock.getsockname()[1]
    log.info("Bound to 0.0.0.0:%d", local_port)

    broadcasts = get_broadcast_addresses()
    if args.target_ip:
        broadcasts = [args.target_ip] + broadcasts

    log.info("Sending LAN_SEARCH to %d destinations...", len(broadcasts))
    for dest in broadcasts:
        try:
            sock.sendto(search_pkt, (dest, PPPP_PORT))
            log.info("  Sent to %s:%d — OK", dest, PPPP_PORT)
        except OSError as e:
            log.error("  Sent to %s:%d — FAILED: %s", dest, PPPP_PORT, e)

    log.info("")
    log.info("Listening for responses (10 seconds)...")
    sock.settimeout(1.0)
    end_time = time.time() + 10
    responses = 0
    while time.time() < end_time:
        try:
            data, addr = sock.recvfrom(4096)
            responses += 1
            decoded = xor_obfuscate(data)
            type_names = {
                0xE0: "LAN_SEARCH", 0x91: "LAN_NOTIFY", 0x92: "PUNCH_RSP",
                0x30: "PUNCH_TO", 0x31: "PUNCH_PKT", 0x00: "DRW(xor)", 0x01: "DRW_ACK(xor)",
            }
            if decoded[0] == PPPP_MAGIC:
                mtype = decoded[1]
                tname = type_names.get(mtype, f"UNKNOWN(0x{mtype:02X})")
                log.info("  Response #%d from %s:%d — %s (%d bytes)",
                         responses, addr[0], addr[1], tname, len(data))
                log.info("    raw:     %s", data[:32].hex())
                log.info("    decoded: %s", decoded[:32].hex())
                if mtype == 0x91 and len(decoded) >= 24:
                    uid = decoded[4:24]
                    log.info("    UID hex: %s", uid.hex())
        except socket.timeout:
            remaining = int(end_time - time.time())
            if remaining > 0 and remaining % 3 == 0:
                for dest in broadcasts:
                    try:
                        sock.sendto(search_pkt, (dest, PPPP_PORT))
                    except OSError:
                        pass
    sock.close()

    log.info("")
    log.info("--- Results ---")
    log.info("Total responses received: %d", responses)
    if responses == 0:
        log.info("No responses. Check: firewall, camera power, network connectivity.")
        log.info("  Try: --target-ip <camera_ip>")


# =============================================================================
# Module 11: Main
# =============================================================================

def resolve_encryption(config: dict) -> tuple[Optional[bytes], Optional[list[str]], Optional[str]]:
    """Resolve PSK/encryption settings from config. Returns (p2p_key, psk_list, enc_mode)."""
    psk_str = config.get("psk")
    enc_mode_str = config.get("enc_mode")

    if enc_mode_str == "xor":
        return b'\x00\x00\x00\x00', None, ENC_XOR_ONLY
    elif enc_mode_str == "p2p" and psk_str:
        key = p2p_derive_key(psk_str.encode("ascii"))
        log.info("P2P key: %s (from PSK=%r)", key.hex(), psk_str)
        return key, None, ENC_P2P
    elif psk_str and enc_mode_str != "auto":
        # PSK specified but enc_mode not explicitly set — use P2P
        key = p2p_derive_key(psk_str.encode("ascii"))
        log.info("P2P key: %s (from PSK=%r)", key.hex(), psk_str)
        return key, None, ENC_P2P
    else:
        # Auto-detect
        log.info("Encryption: auto-detect (PSKs: %s)", KNOWN_PSKS)
        return None, KNOWN_PSKS, None


# =============================================================================
# Motion Detection — polls alarm_status via DRW, triggers Scrypted webhooks
# =============================================================================

class MotionHandler:
    """Manages motion state and Scrypted webhook calls for one camera.

    The camera's alarm_status field (polled via get_status.cgi over DRW) changes
    from 0 to non-zero when motion is detected.  This handler triggers Scrypted
    webhooks to toggle a virtual motion sensor with a configurable cooldown.
    """

    def __init__(self, uid: str, webhook: str, cooldown: float = 30.0):
        self.uid = uid
        self.webhook = webhook
        self.cooldown = cooldown
        self._motion_active = False
        self._cooldown_task: Optional[asyncio.Task] = None

    def on_alarm_status(self, status: int):
        """Called by PPPPUnifiedProtocol when alarm_status changes."""
        if status != 0:
            asyncio.create_task(self._trigger_motion())
        # status == 0 means camera cleared alarm; we use our own cooldown

    async def _trigger_motion(self):
        """Set motion ON and reset cooldown timer."""
        if not self._motion_active:
            self._motion_active = True
            log.info("[%s] Motion ON (alarm_status changed)", self.uid)
            await self._call_webhook(on=True)
        else:
            log.debug("[%s] Motion sustained — resetting cooldown", self.uid)

        # Reset cooldown timer
        if self._cooldown_task:
            self._cooldown_task.cancel()
        self._cooldown_task = asyncio.create_task(self._cooldown_wait())

    async def _cooldown_wait(self):
        """Wait for cooldown period, then set motion OFF."""
        try:
            await asyncio.sleep(self.cooldown)
            self._motion_active = False
            log.info("[%s] Motion OFF — cooldown expired (%.0fs)", self.uid, self.cooldown)
            await self._call_webhook(on=False)
        except asyncio.CancelledError:
            pass  # Cooldown reset by new alarm event

    async def _call_webhook(self, on: bool):
        """Call Scrypted webhook to toggle motion state."""
        action = "turnOn" if on else "turnOff"
        url = f"{self.webhook.rstrip('/')}/{action}"
        try:
            loop = asyncio.get_event_loop()
            req = urllib.request.Request(url, method="POST", data=b"")
            await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=5))
            log.info("[%s] Webhook %s → %s", self.uid, action, url)
        except Exception as e:
            log.warning("[%s] Webhook call failed: %s (url=%s)", self.uid, e, url)

    def stop(self):
        if self._cooldown_task:
            self._cooldown_task.cancel()


async def discover_cameras_broadcast(
        timeout: float = 3.0,
        target_ip: Optional[str] = None,
) -> list[CameraInfo]:
    """Run a broadcast discovery and return found cameras. Cleans up after itself."""
    loop = asyncio.get_event_loop()
    probe = PPPPUnifiedProtocol(username="", password="")
    transport, _ = await loop.create_datagram_endpoint(
        lambda: probe, local_addr=("0.0.0.0", 0), allow_broadcast=True)
    sock = transport.get_extra_info("socket")
    if sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    targets = []
    if target_ip:
        targets.append((target_ip, PPPP_PORT))
    for bcast in get_broadcast_addresses():
        targets.append((bcast, PPPP_PORT))

    search_pkt = build_lan_search()
    for _ in range(5):
        for dest_ip, dest_port in targets:
            try:
                transport.sendto(search_pkt, (dest_ip, dest_port))
            except OSError:
                pass
        await asyncio.sleep(min(1.0, timeout / 5))

    remaining = timeout - 5 * min(1.0, timeout / 5)
    if remaining > 0:
        await asyncio.sleep(remaining)

    cameras = list(probe.cameras.values())
    transport.close()
    return cameras


async def run_proxy(config: dict, config_path: str, target_ip: Optional[str] = None):
    """Main entry point: discover cameras, connect each, and serve RTSP."""

    # Decode init string
    servers, _ = decode_init_string(
        INIT_STRINGS.get("VC0", list(INIT_STRINGS.values())[0]))
    log.info("P2P relay servers: %s", servers)

    # Resolve encryption settings
    p2p_key, psk_list, enc_mode = resolve_encryption(config)
    base_port = config.get("base_port", DEFAULT_CONFIG["base_port"])
    username = config.get("username", DEFAULT_CONFIG["username"])
    password = config.get("password", DEFAULT_CONFIG["password"])
    discovery_time = config.get("discovery_time", DEFAULT_CONFIG["discovery_time"])

    # Alarm/motion settings
    alarm_port = config.get("alarm_server_port", 0)
    alarm_addr = config.get("alarm_server_addr", "")
    motion_cooldown = config.get("motion_cooldown", 30)
    motion_poll_interval = config.get("motion_poll_interval", 1)
    camera_configs = config.get("cameras", {})

    if motion_cooldown:
        log.info("Motion detection: polling alarm_status every %gs (cooldown=%ds)", motion_poll_interval, motion_cooldown)

    # Active sessions keyed by camera UID
    sessions: dict[str, CameraSession] = {}

    async def start_session_for_camera(cam: CameraInfo):
        """Create and start a CameraSession for a discovered camera."""
        if cam.uid in sessions:
            # Already have a session — update IP if changed
            existing = sessions[cam.uid]
            if existing.camera.ip != cam.ip:
                log.info("[%s] IP changed %s → %s", cam.uid, existing.camera.ip, cam.ip)
                existing.camera.ip = cam.ip
                existing.camera.port = cam.port
                existing.camera.discovery_port = cam.discovery_port
            return

        port = assign_port(config, cam.uid, base_port)
        save_config(config_path, config)
        log.info("[%s] Assigned RTSP port %d", cam.uid, port)

        # Look up per-camera motion_webhook from config
        cam_cfg = camera_configs.get(cam.uid, {})
        motion_webhook = cam_cfg.get("motion_webhook") if isinstance(cam_cfg, dict) else None

        session = CameraSession(
            camera=cam, rtsp_port=port,
            username=username, password=password,
            p2p_key=p2p_key, psk_list=psk_list, enc_mode=enc_mode,
            alarm_server_addr=None,
            motion_webhook=motion_webhook,
            motion_cooldown=float(motion_cooldown),
            motion_poll_interval=float(motion_poll_interval),
            bind_addr=config.get("bind_addr", "127.0.0.1"),
        )
        sessions[cam.uid] = session
        await session.start()

    # Initial discovery
    log.info("=== Camera Discovery ===")
    cameras = await discover_cameras_broadcast(
        timeout=discovery_time, target_ip=target_ip)

    if not cameras:
        log.error("No cameras found on LAN!")
        log.info("Run with --diag to troubleshoot.")
        log.info("Run with --target-ip <camera_ip> to skip broadcast.")
        return

    log.info("Found %d camera(s):", len(cameras))
    for cam in cameras:
        log.info("  %s", cam)

    # Start sessions for all discovered cameras
    for cam in cameras:
        try:
            await start_session_for_camera(cam)
        except Exception as e:
            log.error("[%s] Failed to start session: %s", cam.uid, e)

    log.info("=== Proxy Running ===")
    for uid, sess in sessions.items():
        webhook_status = f" [motion→webhook]" if sess.motion_webhook else ""
        log.info("  %s → rtsp://%s:%d/%s", uid, sess.bind_addr, sess.rtsp_port, webhook_status)
    webhooks = sum(1 for s in sessions.values() if s.motion_webhook)
    if webhooks:
        log.info("  Motion detection: %d camera(s) polling alarm_status (cooldown=%ds)", webhooks, motion_cooldown)
    log.info("Press Ctrl+C to stop.")

    try:
        rediscovery_interval = 60
        while True:
            await asyncio.sleep(rediscovery_interval)
            # Only probe for new cameras if we don't already have sessions
            # (probing creates UDP sessions that count against camera user limits)
            active = sum(1 for s in sessions.values()
                        if s.state in (STATE_CONNECTED, STATE_STALE))
            if active >= len(sessions) and len(sessions) > 0:
                log.debug("All %d cameras active, skipping re-discovery", active)
                continue
            log.info("Re-discovering cameras (%d/%d active)...",
                     active, len(sessions))
            new_cameras = await discover_cameras_broadcast(
                timeout=min(3, discovery_time), target_ip=target_ip)
            for cam in new_cameras:
                if cam.uid not in sessions:
                    log.info("New camera discovered: %s", cam)
                    try:
                        await start_session_for_camera(cam)
                    except Exception as e:
                        log.error("[%s] Failed to start session: %s", cam.uid, e)
    except asyncio.CancelledError:
        pass
    finally:
        log.info("Shutting down %d session(s)...", len(sessions))
        for session in sessions.values():
            await session.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Eye4 Camera RTSP Proxy — streams Eye4/VStarcam cameras via RTSP")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"Config file path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("-u", "--username", default=None,
                        help="Camera username (overrides config)")
    parser.add_argument("-p", "--password", default=None,
                        help="Camera password (overrides config)")
    parser.add_argument("--base-port", type=int, default=None,
                        help="RTSP base port (overrides config)")
    parser.add_argument("--discovery-time", type=float, default=None,
                        help="Camera discovery timeout in seconds (overrides config)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--target-ip", type=str, default=None,
                        help="Camera IP address (skip broadcast, send directly)")
    parser.add_argument("--diag", action="store_true",
                        help="Run network diagnostics only")
    parser.add_argument("--psk", type=str, default=None,
                        help="P2P encryption PSK (overrides config)")
    parser.add_argument("--enc-mode", type=str, default=None, dest="enc_mode",
                        choices=["xor", "p2p", "auto"],
                        help="DRW encryption mode (overrides config)")
    parser.add_argument("--alarm-port", type=int, default=None, dest="alarm_server_port",
                        help="HTTP port for camera alarm listener (0=disabled, overrides config)")
    parser.add_argument("--alarm-addr", type=str, default=None, dest="alarm_server_addr",
                        help="IP address cameras send alarms to (this host's LAN IP)")
    parser.add_argument("--motion-cooldown", type=int, default=None,
                        help="Seconds to keep motion ON after last alarm event")
    parser.add_argument("--bind-addr", type=str, default=None, dest="bind_addr",
                        help="Bind address for RTSP and snapshot servers "
                             "(default 127.0.0.1; use 0.0.0.0 to expose on the LAN)")
    args = parser.parse_args()

    # Load config from YAML, then apply CLI overrides
    config = load_config(args.config)

    if args.username is not None:
        config["username"] = args.username
    if args.password is not None:
        config["password"] = args.password
    if args.base_port is not None:
        config["base_port"] = args.base_port
    if args.discovery_time is not None:
        config["discovery_time"] = args.discovery_time
    if args.verbose:
        config["verbose"] = True
    if args.psk is not None:
        config["psk"] = args.psk
    if args.enc_mode is not None:
        config["enc_mode"] = args.enc_mode if args.enc_mode != "auto" else "auto"
    if args.alarm_server_port is not None:
        config["alarm_server_port"] = args.alarm_server_port
    if args.alarm_server_addr is not None:
        config["alarm_server_addr"] = args.alarm_server_addr
    if args.motion_cooldown is not None:
        config["motion_cooldown"] = args.motion_cooldown
    if args.bind_addr is not None:
        config["bind_addr"] = args.bind_addr

    if args.diag:
        config["verbose"] = True

    # Determine log level: verbose flag → DEBUG, else log_level config, else INFO
    _log_level_str = config.get("log_level", "info").upper()
    if config.get("verbose"):
        _log_level_str = "DEBUG"
    _log_level = getattr(logging, _log_level_str, logging.INFO)
    logging.basicConfig(
        level=_log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    log.info("C accelerator: %s", "loaded" if HAS_ACCEL else "not available (pure Python fallback)")
    log.info("Config: %s (from %s + CLI overrides)", {k: v for k, v in config.items() if k != "cameras"}, args.config)
    if config.get("cameras"):
        log.info("Known cameras: %s", config["cameras"])

    try:
        if args.diag:
            # Diag still uses the old args-style interface
            diag_args = argparse.Namespace(
                target_ip=args.target_ip, verbose=True)
            asyncio.run(run_diag(diag_args))
        else:
            asyncio.run(run_proxy(config, args.config, target_ip=args.target_ip))
    except KeyboardInterrupt:
        log.info("Interrupted by user.")


if __name__ == "__main__":
    main()
