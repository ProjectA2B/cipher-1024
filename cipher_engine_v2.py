#!/usr/bin/env python3
"""
===============================================================================
CIPHER ENGINE 1024 v2 — Visual Cryptographic Workbench & Python Library
Experimental & Educational 1,024-Glyph Cipher Studio with Safety Guardrails
Protocol V5: encrypt-then-MAC + labeled key separation (Legend V3 keyfiles)
===============================================================================
Drop this script directly into your unzipped 1,024-glyph White/Grayscale folder
alongside the 8 archetype folders:
  circuits/  monoliths/  braids/  constellations/
  harpoons/  totems/     labyrinths/  fractures/
and cipher_manifest_1024_*.json.

Compatibility: Legend keyfiles from v1 load unchanged, but v1 ciphertexts
(Protocol V4 .CIPH / PNG files) must be decrypted with cipher_engine.py v1.
===============================================================================
"""

import sys
import json
import math
import zlib
import hmac
import struct
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Any, Optional

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    tk = None


# =============================================================================
# 0. SAFETY GUARDRAILS (CONFIGURABLE BY DEVELOPERS)
# =============================================================================

class SafetyConfig:
    """
    Safety guardrails to prevent out-of-memory crashes, CPU hangs, or oversized
    image generation when testing files.
    Developers can adjust or disable these limits for custom pipelines.
    """
    ENABLE_SAFETY_GUARDS = True

    # Maximum allowed output/input PNG dimensions (4096 x 4096 px = 256 x 256 tiles)
    MAX_PNG_WIDTH_PX  = 4096
    MAX_PNG_HEIGHT_PX = 4096
    MAX_PNG_TILES     = (MAX_PNG_WIDTH_PX // 16) * (MAX_PNG_HEIGHT_PX // 16)  # 65,536 tiles max

    # Reconciled input byte limits and worst-case expanded glyph stream limits
    MAX_TEXT_INPUT_CHARS      = 25_000           # ~25 KB of text/code in Tab 1
    MAX_FILE_BYTES_FOR_PNG    = 45 * 1024        # 45 KiB raw file limit for Visual PNG Matrix output
    MAX_FILE_BYTES_FOR_CIPH   = 512 * 1024       # 512 KiB raw file limit for .CIPH Vault output
    MAX_ENVELOPE_OVERHEAD     = 512              # Max binary file envelope header overhead
    MAX_CIPH_GLYPHS           = 786_432          # Accommodates 512 KiB incompressible data under supported schedules (chaff >= 5, rotor >= 16)
    MAX_IMPORT_PNG_FILE_SIZE  = 12 * 1024 * 1024 # 12 MiB max file size when importing a PNG or .CIPH vault
    MAX_GLYPH_ASSET_BYTES     = 64 * 1024        # 64 KiB max file size for individual 16x16 glyph PNG assets
    MAX_JSON_CONFIG_BYTES     = 1 * 1024 * 1024  # 1 MiB max file size for .legend.json and manifest JSON files
    MAX_ZLIB_DECOMPRESS_BYTES = 68 * 1024 * 1024 # 68 MiB max raw RGBA scanline decompression ceiling

    # PBKDF2-HMAC-SHA512 work-factor bounds
    MIN_PBKDF2_ITERATIONS     = 100_000
    MAX_PBKDF2_ITERATIONS     = 2_000_000

    # GUI responsiveness limits
    MAX_XRAY_RECT_OVERLAYS    = 2048             # Max Tkinter rectangle objects drawn on canvas
    MAX_TK_PREVIEW_DIM_PX     = 4096             # Max zoomed preview dimension inside Tkinter canvas

    # High-volume media/archive extensions refused immediately in Visual PNG mode
    BLOCKED_PNG_MEDIA_EXTENSIONS = {
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".m4v", ".webm",
        ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a",
        ".iso", ".img", ".vmdk", ".vhd", ".exe", ".dll", ".so", ".dylib",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
    }


class SafetyLimitExceeded(ValueError):
    """Raised when an input or output exceeds SafetyConfig guardrails."""
    pass


def strict_zlib_decompress(compressed_bytes: bytes, max_bytes: int = 0) -> bytes:
    """
    Strictly decompresses a single complete zlib stream while enforcing:
    1. Hard output byte ceiling (`max_bytes`) without unbounded allocation.
    2. Complete stream termination (`dobj.eof == True`, verifying Adler-32 trailer).
    3. Zero trailing or concatenated data (`dobj.unused_data == b""`).
    """
    if not isinstance(compressed_bytes, (bytes, bytearray)) or len(compressed_bytes) < 6:
        raise ValueError("Invalid or truncated zlib stream.")
    dobj = zlib.decompressobj()
    cap = (max_bytes + 1) if max_bytes > 0 else 0
    out = dobj.decompress(compressed_bytes, cap)
    if cap > 0 and (len(out) > max_bytes or dobj.unconsumed_tail):
        raise SafetyLimitExceeded("Safety Refusal: Decompressed stream exceeded maximum safe memory ceiling.")
    if not dobj.eof:
        raise ValueError("Truncated or incomplete zlib stream (missing or invalid Adler-32 checksum).")
    if dobj.unused_data:
        raise ValueError("Invalid zlib stream: unexpected trailing or concatenated data.")
    tail = dobj.flush()
    if tail:
        out += tail
        if cap > 0 and len(out) > max_bytes:
            raise SafetyLimitExceeded("Safety Refusal: Decompressed stream exceeded maximum safe memory ceiling.")
    return out


# =============================================================================
# 1. PURE-PYTHON PNG DECODER & ENCODER (WITH STRICT CHUNK, CRC & ZLIB CHECKS)
# =============================================================================

class PurePNG:
    """Reads and writes 8-bit PNG files using Python's standard zlib & struct with strict validation."""

    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    KNOWN_CRITICAL_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}

    @staticmethod
    def _paeth(a: int, b: int, c: int) -> int:
        p = a + b - c
        pa = abs(p - a)
        pb = abs(p - b)
        pc = abs(p - c)
        if pa <= pb and pa <= pc:
            return a
        elif pb <= pc:
            return b
        return c

    @classmethod
    def inspect_png_header(cls, path_or_bytes) -> tuple:
        """
        Fast pre-flight inspection of the PNG IHDR header and its CRC-32 without
        decompressing the image body. Returns (width, height, bit_depth, color_type).
        """
        if isinstance(path_or_bytes, (bytes, bytearray)):
            if SafetyConfig.ENABLE_SAFETY_GUARDS and len(path_or_bytes) > SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE:
                size_mb = len(path_or_bytes) / (1024 * 1024)
                raise SafetyLimitExceeded(
                    f"Safety Refusal: PNG buffer is {size_mb:.1f} MB, which exceeds "
                    f"the {SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE // (1024*1024)} MB import safety limit."
                )
            head = bytes(path_or_bytes[:33])
        else:
            p = Path(path_or_bytes)
            if SafetyConfig.ENABLE_SAFETY_GUARDS and p.stat().st_size > SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE:
                size_mb = p.stat().st_size / (1024 * 1024)
                raise SafetyLimitExceeded(
                    f"Safety Refusal: PNG file '{p.name}' is {size_mb:.1f} MB on disk, which exceeds "
                    f"the {SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE // (1024*1024)} MB import safety limit."
                )
            with open(p, "rb") as f:
                head = f.read(33)

        if len(head) < 33 or head[:8] != cls.PNG_SIG or head[12:16] != b"IHDR":
            raise ValueError("File is not a valid PNG image.")

        ihdr_len = struct.unpack(">I", head[8:12])[0]
        if ihdr_len != 13:
            raise ValueError(f"Invalid PNG IHDR chunk length: {ihdr_len} (expected 13).")

        expected_crc = struct.unpack(">I", head[29:33])[0]
        actual_crc = zlib.crc32(head[12:29]) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("Corrupted PNG header: IHDR CRC-32 mismatch.")

        width, height, bit_depth, color_type, comp_m, filt_m, interlace_m = struct.unpack(">IIBBBBB", head[16:29])
        if width <= 0 or height <= 0:
            raise ValueError(f"Invalid PNG dimensions: {width}×{height} px.")
        if comp_m != 0 or filt_m != 0 or interlace_m != 0:
            raise ValueError("Unsupported PNG compression, filter, or interlace method.")
        if bit_depth != 8 or color_type not in (0, 2, 3, 4, 6):
            raise ValueError(f"Unsupported PNG bit depth ({bit_depth}) or color type ({color_type}).")
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if width > SafetyConfig.MAX_PNG_WIDTH_PX or height > SafetyConfig.MAX_PNG_HEIGHT_PX:
                raise SafetyLimitExceeded(
                    f"Safety Refusal: PNG dimensions ({width}×{height} px) exceed the maximum safe "
                    f"canvas limit of {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px."
                )
        return width, height, bit_depth, color_type

    @classmethod
    def read_rgba(cls, path_or_bytes) -> tuple:
        """Returns (width, height, bytearray_rgba) for any standard 8-bit PNG with full CRC & chunk validation."""
        hdr_w, hdr_h, hdr_bd, hdr_ct = cls.inspect_png_header(path_or_bytes)
        raw = bytes(path_or_bytes) if isinstance(path_or_bytes, (bytes, bytearray)) else Path(path_or_bytes).read_bytes()
        if SafetyConfig.ENABLE_SAFETY_GUARDS and len(raw) > SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE:
            raise SafetyLimitExceeded("Safety Refusal: PNG input exceeds maximum import byte limit.")

        pos = 8
        width = height = bit_depth = color_type = 0
        seen_ihdr = False
        seen_idat = False
        idat_closed = False
        seen_iend = False
        palette = None
        trns = None
        idat_chunks = []

        while pos < len(raw):
            if pos + 12 > len(raw):
                raise ValueError("Truncated PNG chunk header.")
            length = struct.unpack(">I", raw[pos:pos + 4])[0]
            if pos + 12 + length > len(raw):
                raise ValueError("Truncated or corrupted PNG chunk data.")
            ctype = raw[pos + 4:pos + 8]
            cdata = raw[pos + 8:pos + 8 + length]
            expected_crc = struct.unpack(">I", raw[pos + 8 + length:pos + 12 + length])[0]
            actual_crc = zlib.crc32(raw[pos + 4:pos + 8 + length]) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                raise ValueError(f"Corrupted PNG chunk '{ctype.decode('latin1', errors='replace')}': CRC-32 mismatch.")
            pos += 12 + length

            # PNG Spec: all 4 chunk-type bytes must be ASCII letters (A-Z or a-z), and bit 5 of byte 2 (reserved bit) must be 0
            if not all((65 <= b <= 90) or (97 <= b <= 122) for b in ctype):
                raise ValueError(f"Invalid PNG chunk type {ctype!r}: chunk type must consist of 4 ASCII letters.")
            if (ctype[2] & 0x20) != 0:
                raise ValueError(f"Invalid PNG chunk type {ctype!r}: reserved bit in third byte must be zero.")

            if not seen_ihdr and ctype != b"IHDR":
                raise ValueError("Invalid PNG: IHDR must be the first chunk.")

            # Reject unknown critical chunks (ancillary bit is bit 5 of first byte: 0 = critical, 1 = ancillary)
            if (ctype[0] & 0x20) == 0 and ctype not in cls.KNOWN_CRITICAL_CHUNKS:
                raise ValueError(f"Unsupported critical PNG chunk: {ctype!r}")

            if ctype != b"IDAT" and seen_idat:
                idat_closed = True

            if ctype == b"IHDR":
                if seen_ihdr or len(cdata) != 13:
                    raise ValueError("Invalid PNG: duplicate or malformed IHDR chunk.")
                seen_ihdr = True
                width, height, bit_depth, color_type, comp_m, filt_m, interlace_m = struct.unpack(">IIBBBBB", cdata)
                if (width, height, bit_depth, color_type) != (hdr_w, hdr_h, hdr_bd, hdr_ct):
                    raise ValueError("PNG IHDR mismatch.")
            elif ctype == b"PLTE":
                if seen_idat or palette is not None:
                    raise ValueError("Invalid PNG: misplaced or duplicate PLTE chunk.")
                if color_type in (0, 4):
                    raise ValueError(f"Invalid PNG: PLTE chunk is forbidden for grayscale color type {color_type}.")
                if len(cdata) == 0 or len(cdata) % 3 != 0 or len(cdata) > 768:
                    raise ValueError("Invalid PNG PLTE chunk length.")
                palette = cdata
            elif ctype == b"tRNS":
                if seen_idat or trns is not None:
                    raise ValueError("Invalid PNG: misplaced or duplicate tRNS chunk.")
                if color_type in (4, 6):
                    raise ValueError(f"Invalid PNG: tRNS chunk not permitted for color type {color_type}.")
                if color_type == 3 and palette is None:
                    raise ValueError("Invalid PNG: tRNS chunk must appear after PLTE chunk for indexed-color images.")
                trns = cdata
            elif ctype == b"IDAT":
                if idat_closed:
                    raise ValueError("Invalid PNG: IDAT chunks must be consecutive with no intervening chunks.")
                seen_idat = True
                idat_chunks.append(cdata)
            elif ctype == b"IEND":
                if len(cdata) != 0:
                    raise ValueError("Invalid PNG: non-empty IEND chunk.")
                seen_iend = True
                if pos != len(raw):
                    raise ValueError("Invalid PNG: trailing bytes after IEND chunk.")
                break

        if not seen_ihdr or not seen_idat or not seen_iend:
            raise ValueError("Incomplete PNG file: missing required IHDR, IDAT, or IEND chunk.")

        if color_type == 3 and palette is None:
            raise ValueError("Invalid indexed-color PNG: missing required PLTE palette chunk.")

        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
        stride = width * channels
        expected_decomp_bytes = height * (1 + stride)
        if SafetyConfig.ENABLE_SAFETY_GUARDS and expected_decomp_bytes > SafetyConfig.MAX_ZLIB_DECOMPRESS_BYTES:
            raise SafetyLimitExceeded("Safety Refusal: PNG raw scanline size exceeds safe memory ceiling.")

        decompressed = strict_zlib_decompress(b"".join(idat_chunks), expected_decomp_bytes)
        if len(decompressed) != expected_decomp_bytes:
            raise ValueError(
                "Invalid PNG IDAT stream: decompressed scanline byte count does not match IHDR dimensions."
            )

        recon = bytearray(height * stride)

        in_pos = 0
        for r in range(height):
            ftype = decompressed[in_pos]
            in_pos += 1
            row_start = r * stride
            prev_start = (r - 1) * stride

            for c in range(stride):
                x = decompressed[in_pos]
                in_pos += 1
                a = recon[row_start + c - channels] if c >= channels else 0
                b = recon[prev_start + c] if r > 0 else 0
                c_val = recon[prev_start + c - channels] if (r > 0 and c >= channels) else 0

                if ftype == 0:
                    val = x
                elif ftype == 1:
                    val = (x + a) & 0xFF
                elif ftype == 2:
                    val = (x + b) & 0xFF
                elif ftype == 3:
                    val = (x + ((a + b) >> 1)) & 0xFF
                elif ftype == 4:
                    val = (x + cls._paeth(a, b, c_val)) & 0xFF
                else:
                    raise ValueError(f"Unsupported PNG filter: {ftype}")
                recon[row_start + c] = val

        if color_type == 6:
            return width, height, recon

        out = bytearray(width * height * 4)
        if color_type == 2:
            tr_rgb = None
            if trns is not None:
                if len(trns) != 6:
                    raise ValueError("Invalid PNG tRNS chunk length for truecolor image (expected 6 bytes).")
                tr_r, tr_g, tr_b = struct.unpack(">HHH", trns)
                tr_rgb = (tr_r & 0xFF, tr_g & 0xFF, tr_b & 0xFF)
            for i in range(width * height):
                rgb = (recon[i * 3], recon[i * 3 + 1], recon[i * 3 + 2])
                out[i * 4:i * 4 + 3] = bytes(rgb)
                out[i * 4 + 3] = 0 if (tr_rgb is not None and rgb == tr_rgb) else 255
        elif color_type == 0:
            tr_gray = None
            if trns is not None:
                if len(trns) != 2:
                    raise ValueError("Invalid PNG tRNS chunk length for grayscale image (expected 2 bytes).")
                tr_gray = struct.unpack(">H", trns)[0] & 0xFF
            for i in range(width * height):
                v = recon[i]
                a = 0 if (tr_gray is not None and v == tr_gray) else 255
                out[i * 4:i * 4 + 4] = bytes((v, v, v, a))
        elif color_type == 4:
            for i in range(width * height):
                v = recon[i * 2]
                a = recon[i * 2 + 1]
                out[i * 4:i * 4 + 4] = bytes((v, v, v, a))
        elif color_type == 3:
            num_pal = len(palette) // 3
            if trns is not None and len(trns) > num_pal:
                raise ValueError("Invalid PNG: tRNS chunk has more entries than PLTE palette.")
            for i in range(width * height):
                idx = recon[i]
                if idx >= num_pal:
                    raise ValueError(f"Invalid PNG palette index {idx} (palette has {num_pal} entries).")
                r_v = palette[idx * 3]
                g_v = palette[idx * 3 + 1]
                b_v = palette[idx * 3 + 2]
                a_v = trns[idx] if (trns is not None and idx < len(trns)) else 255
                out[i * 4:i * 4 + 4] = bytes((r_v, g_v, b_v, a_v))
        return width, height, out

    @classmethod
    def encode_rgba_bytes(cls, width: int, height: int, rgba: bytes) -> bytes:
        """Encodes an RGBA buffer into valid PNG bytes in memory (enforcing 4096x4096 limit)."""
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if width > SafetyConfig.MAX_PNG_WIDTH_PX or height > SafetyConfig.MAX_PNG_HEIGHT_PX:
                raise SafetyLimitExceeded(
                    f"Safety Refusal: Output PNG ({width}×{height} px) exceeds the maximum allowed "
                    f"{SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px safety limit."
                )

        def make_chunk(ctype: bytes, data: bytes) -> bytes:
            crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        stride = width * 4
        raw_rows = bytearray()
        for r in range(height):
            raw_rows.append(0)
            start = r * stride
            raw_rows.extend(rgba[start:start + stride])

        compressed = zlib.compress(bytes(raw_rows), level=6)
        return (
            cls.PNG_SIG
            + make_chunk(b"IHDR", ihdr)
            + make_chunk(b"IDAT", compressed)
            + make_chunk(b"IEND", b"")
        )

    @classmethod
    def write_rgba(cls, path, width: int, height: int, rgba: bytes):
        Path(path).write_bytes(cls.encode_rgba_bytes(width, height, rgba))


# =============================================================================
# 2. BUILT-IN FALLBACK 1,024 WHITE GLYPH SYNTHESIZER
# =============================================================================

ARCHETYPE_FAMILIES = [
    ("circuits",       "Family 1: Circuit-Lattices (#0000-#0127)"),
    ("monoliths",      "Family 2: Void-Monoliths (#0128-#0255)"),
    ("braids",         "Family 3: Braided Sigils (#0256-#0383)"),
    ("constellations", "Family 4: Constellation Matrices (#0384-#0511)"),
    ("harpoons",       "Family 5: Barbed Harpoons & Vectors (#0512-#0639)"),
    ("totems",         "Family 6: Binary Totems (#0640-#0767)"),
    ("labyrinths",     "Family 7: Labyrinthine Seals (#0768-#0895)"),
    ("fractures",      "Family 8: Fractured Runes & Control Sigils (#0896-#1023)")
]
VALID_ARCHETYPE_FAMILIES = {fam_key for fam_key, _ in ARCHETYPE_FAMILIES}

ONSETS_16 = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v']
VOWELS_4  = ['a', 'e', 'o', 'u']
CODAS_16  = ['rk', 'rn', 'lt', 'lx', 'nd', 'nx', 'nt', 'nv', 'kr', 'kl', 'tr', 'tl', 'vr', 'vl', 'zr', 'zl']

GRAY_RAMP = {
    '1': (0x2b, 0x2b, 0x2b, 255),
    '2': (0x45, 0x45, 0x45, 255),
    '3': (0x63, 0x63, 0x63, 255),
    '4': (0x82, 0x82, 0x82, 255),
    '5': (0xa3, 0xa3, 0xa3, 255),
    '6': (0xc4, 0xc4, 0xc4, 255),
    '7': (0xe3, 0xe3, 0xe3, 255),
    '8': (0xff, 0xff, 0xff, 255),
    'K': (0x12, 0x0d, 0x10, 255)
}


def get_codename_for_id(gid: int) -> str:
    p = (gid * 197 + 53) & 1023
    return f"{ONSETS_16[p & 15]}{VOWELS_4[(p >> 4) & 3]}{CODAS_16[(p >> 6) & 15]}"


def get_role_for_id(gid: int) -> str:
    if gid < 960:
        return "DATA_GLYPH"
    elif gid < 976:
        return "POLY_NULL_CHAFF"
    elif gid < 992:
        return "ROTOR_MUTATOR"
    elif gid < 1008:
        return "RLE_FRAMING"
    return "TAMPER_CHECKSUM"


# =============================================================================
# 3. CORE 1,024-GLYPH VISUAL CRYPTOGRAPHIC ENGINE (WITH PRE-FLIGHT GUARDS)
# =============================================================================

class CipherEngine1024:
    """
    Two-Secret 1,024-Glyph Visual Cryptographic Engine (Protocol V5 / Legend V3):
    - Secret 1: Portable .legend.json keyfile (one 1,024-glyph permutation + rotor schedule + 256-bit salt).
    - Secret 2: User Passphrase, combined with the Legend digest via PBKDF2-HMAC-SHA512.
    - Key separation: independent HMAC-labeled subkeys for the genesis table, nonce mask, and per-message
      encryption / MAC / glyph-layout keys.
    - 128-bit (16-byte) per-message random session nonce.
    - Encrypt-then-MAC: SHAKE-256 keystream encryption, then a full 256-bit (32-byte) HMAC-SHA256 tag over
      protocol schema + nonce + ciphertext (the encrypted canonical frame header and compressed payload).
      The tag is verified before anything is decrypted.
    - Glyph layer: homophones, chaff, rotors, 32-bit (8-seal) visual checksum and authenticated padding,
      all required to match the exact canonical encoding.
    - Exact 16×16 RGBA tile verification in default strict PNG decoding.
    """

    PROTOCOL_VERSION = 5
    PACKET_SCHEMA = "CIPHER_1024_PACKET_V5"
    LEGEND_SCHEMA = "CIPHER_ENGINE_1024_LEGEND_V3"
    SUPPORTED_LEGEND_SCHEMAS = ("CIPHER_ENGINE_1024_LEGEND_V3",)
    KDF_LABEL_PREFIX = b"CIPHER1024-V5|"
    DEFAULT_PBKDF2_ITERATIONS = 210_000  # OWASP guidance for PBKDF2-HMAC-SHA512

    EOF_GLYPH_ID = 1007  # Default baseline EOF index prior to full 1,024-glyph permutation
    BIN_ENV_MAGIC = b"CE10"
    NONCE_BYTES = 16  # 128-bit per-message random session nonce
    FRAME_HEADER_BYTES = 24  # >BBBBIIIII canonical frame header (encrypted + authenticated)
    HMAC_TAG_BYTES = 32  # Full 256-bit HMAC-SHA256 tag
    VISUAL_SEAL_COUNT = 8  # 8 visual checksum glyphs = 32-bit visual seal
    LAYOUT_TO_CODE = {
        "scroll_16": 0,
        "scroll_32": 1,
        "square_block": 2,
        "strip_horizontal": 3,
    }
    CODE_TO_LAYOUT = {v: k for k, v in LAYOUT_TO_CODE.items()}
    UNIFORM_AUTH_FAILURE_MSG = (
        "Cryptographic Authentication Failed: Ciphertext integrity or 256-bit HMAC-SHA256 "
        "verification failed (wrong passphrase, wrong Legend keyfile, or tampered glyph stream)."
    )

    def __init__(self, root_dir=None, auto_create_legend: bool = False):
        """
        Loads glyph assets and, if present, the default master_genesis.legend.json.
        A missing Legend is only created when auto_create_legend=True is passed explicitly;
        otherwise self.legend stays None until generate_new_legend() or load_legend() is called.
        """
        self.root_dir = Path(root_dir).resolve() if root_dir else Path(__file__).resolve().parent
        self.glyphs = {}
        self.name_to_id = {}
        self.hash_to_id = {}
        self.exact_rgba_to_id = {}
        self.manifest_path = None
        self.legend_path = self.root_dir / "master_genesis.legend.json"
        self.legend = None
        self.disk_loaded_count = 0

        self.discover_and_load_glyphs()
        if auto_create_legend or self.legend_path.exists():
            self.ensure_default_legend()

    def _require_legend(self) -> dict:
        """Raises a clear error instead of silently creating a Legend when none is loaded."""
        if not self.legend:
            raise ValueError(
                "No Legend keyfile is loaded. Create one with generate_new_legend() "
                "or load an existing one with load_legend() first."
            )
        return self.legend

    def _assert_within_root(self, candidate_path: Path) -> Path:
        root_resolved = self.root_dir.resolve()
        cand_resolved = Path(candidate_path).resolve()
        if not cand_resolved.is_relative_to(root_resolved):
            raise ValueError(
                f"Path containment violation: '{candidate_path}' resolves outside root directory '{root_resolved}'."
            )
        return cand_resolved

    @staticmethod
    def _is_strict_int(val: Any) -> bool:
        return isinstance(val, int) and not isinstance(val, bool)

    @staticmethod
    def _validate_passphrase(passphrase: str) -> None:
        if not isinstance(passphrase, str) or not passphrase.strip():
            raise ValueError("Passphrase cannot be empty or whitespace-only.")

    @staticmethod
    def _normalize_tile_signature(rgba: bytes) -> bytes:
        sig = bytearray(256)
        for i in range(256):
            r = rgba[i * 4]
            g = rgba[i * 4 + 1]
            b = rgba[i * 4 + 2]
            a = rgba[i * 4 + 3]
            if a < 64:
                sig[i] = 0
            else:
                lum = (r * 299 + g * 587 + b * 114) // 1000
                if lum < 30:
                    sig[i] = 1
                else:
                    sig[i] = min(9, 2 + (lum // 32))
        return bytes(sig)

    def discover_and_load_glyphs(self):
        self.glyphs.clear()
        self.name_to_id.clear()
        self.hash_to_id.clear()
        self.exact_rgba_to_id.clear()

        manifests = sorted(self.root_dir.glob("cipher_manifest_1024*.json"))
        if len(manifests) > 1:
            raise ValueError(
                f"Ambiguous manifest configuration: found {len(manifests)} matching 'cipher_manifest_1024*.json' files in '{self.root_dir}'."
            )
        manifest_data = None
        if manifests:
            self.manifest_path = self._assert_within_root(manifests[0])
            if SafetyConfig.ENABLE_SAFETY_GUARDS and self.manifest_path.stat().st_size > SafetyConfig.MAX_JSON_CONFIG_BYTES:
                raise SafetyLimitExceeded(
                    f"Safety Refusal: Manifest file '{self.manifest_path.name}' exceeds {SafetyConfig.MAX_JSON_CONFIG_BYTES:,} bytes."
                )
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            if not isinstance(manifest_data, dict) or not isinstance(manifest_data.get("glyphs"), list):
                raise ValueError(f"Malformed manifest '{self.manifest_path.name}': expected JSON object with 'glyphs' list.")
            entries = manifest_data["glyphs"]
            if len(entries) != 1024:
                raise ValueError(
                    f"Malformed manifest '{self.manifest_path.name}': expected 1,024 glyph entries, found {len(entries)}."
                )
            seen_names = set()
            for expected_id, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"Malformed manifest entry at index {expected_id}: expected JSON object.")
                raw_id = entry.get("id", expected_id)
                if not self._is_strict_int(raw_id) or raw_id != expected_id:
                    raise ValueError(f"Malformed manifest entry at index {expected_id}: invalid id {raw_id!r}.")
                name = entry.get("name") or entry.get("codename")
                if not isinstance(name, str) or len(name) != 4 or not name.isalpha() or not name.islower():
                    raise ValueError(f"Malformed manifest entry #{expected_id}: invalid 4-letter codename {name!r}.")
                if name in seen_names:
                    raise ValueError(f"Duplicate codename '{name}' in manifest at index {expected_id}.")
                seen_names.add(name)
                fam = entry.get("family")
                if not isinstance(fam, str) or fam not in VALID_ARCHETYPE_FAMILIES:
                    raise ValueError(
                        f"Malformed manifest entry #{expected_id}: invalid 'family' {fam!r} "
                        f"(must be one of {sorted(VALID_ARCHETYPE_FAMILIES)})."
                    )
                file_field = entry.get("file")
                if file_field is not None and (not isinstance(file_field, str) or file_field != f"{name}.png"):
                    raise ValueError(
                        f"Malformed manifest entry #{expected_id}: 'file' {file_field!r} must match '{name}.png'."
                    )

        png_lookup = {}
        for fam_dir, _ in ARCHETYPE_FAMILIES:
            fam_path = self.root_dir / fam_dir
            if fam_path.exists() and fam_path.is_dir():
                self._assert_within_root(fam_path)
                for p in sorted(fam_path.glob("*.png")):
                    if len(p.stem) == 4 and p.stem.isalpha() and p.stem.islower() and p.stem not in png_lookup:
                        png_lookup[p.stem] = self._assert_within_root(p)

        loaded_count = 0
        for gid in range(1024):
            if manifest_data and "glyphs" in manifest_data and gid < len(manifest_data["glyphs"]):
                entry = manifest_data["glyphs"][gid]
                name = entry.get("name") or entry.get("codename")
                fam = entry["family"]
                role = entry.get("role", get_role_for_id(gid))
            else:
                name = get_codename_for_id(gid)
                fam = ARCHETYPE_FAMILIES[gid // 128][0]
                role = get_role_for_id(gid)

            expected_path = self._assert_within_root(self.root_dir / fam / f"{name}.png")
            found_path = png_lookup.get(name, expected_path)
            found_path = self._assert_within_root(found_path)

            if found_path.exists():
                if SafetyConfig.ENABLE_SAFETY_GUARDS and found_path.stat().st_size > SafetyConfig.MAX_GLYPH_ASSET_BYTES:
                    raise SafetyLimitExceeded(
                        f"Safety Refusal: Glyph asset '{found_path.name}' ({found_path.stat().st_size:,} bytes) "
                        f"exceeds the {SafetyConfig.MAX_GLYPH_ASSET_BYTES:,}-byte glyph asset cap."
                    )
                hdr_w, hdr_h, _, _ = PurePNG.inspect_png_header(found_path)
                if (hdr_w, hdr_h) != (16, 16):
                    raise ValueError(
                        f"Invalid glyph asset dimensions in '{found_path.name}': expected 16×16 px, found {hdr_w}×{hdr_h} px."
                    )
                w, h, rgba = PurePNG.read_rgba(found_path)
                if (w, h) != (16, 16):
                    raise ValueError(
                        f"Decoded glyph asset dimensions mismatch in '{found_path.name}': expected 16×16 px, found {w}×{h} px."
                    )
                loaded_count += 1
            else:
                rgba = self._synthesize_fallback_glyph_rgba(gid)
                found_path = expected_path

            rgba_bytes = bytes(rgba)
            norm_sig = self._normalize_tile_signature(rgba_bytes)

            if rgba_bytes in self.exact_rgba_to_id:
                prev_id = self.exact_rgba_to_id[rgba_bytes]
                prev_name = self.glyphs[prev_id]["name"]
                raise ValueError(
                    f"Duplicate 16×16 glyph image detected: glyph #{gid:04d} ('{name}.png') "
                    f"is pixel-identical to glyph #{prev_id:04d} ('{prev_name}.png')."
                )
            if norm_sig in self.hash_to_id:
                prev_id = self.hash_to_id[norm_sig]
                prev_name = self.glyphs[prev_id]["name"]
                raise ValueError(
                    f"Duplicate normalized 16×16 glyph signature detected: glyph #{gid:04d} ('{name}.png') "
                    f"collides with glyph #{prev_id:04d} ('{prev_name}.png')."
                )

            self.glyphs[gid] = {
                "id": gid,
                "name": name,
                "family": fam,
                "role": role,
                "path": found_path,
                "rgba": rgba_bytes,
                "sig": norm_sig
            }
            self.name_to_id[name] = gid
            self.hash_to_id[norm_sig] = gid
            self.exact_rgba_to_id[rgba_bytes] = gid

        if len(self.name_to_id) != 1024 or len(self.exact_rgba_to_id) != 1024 or len(self.hash_to_id) != 1024:
            raise ValueError("Glyph library integrity failure: expected 1,024 distinct codenames, RGBA tiles, and signatures.")

        self.disk_loaded_count = loaded_count

    def _synthesize_fallback_glyph_rgba(self, gid: int) -> bytes:
        """
        Synthesizes a deterministic 16x16 RGBA fallback glyph that encodes all 10 bits
        (0..9) of gid into disjoint 2x2 pixel cells plus family framing markers,
        guaranteeing 1,024 distinct images and 1,024 distinct normalized signatures.
        """
        mask = [[False] * 16 for _ in range(16)]

        # Top header bar so even gid=0 has a crisp visible structure
        for c in range(4, 12):
            mask[2][c] = True

        # Encode all 10 bits (bit 0 .. bit 9) of gid in a disjoint 4x3 grid of 2x2 blocks
        for bit in range(10):
            if (gid >> bit) & 1:
                r0 = 4 + (bit // 3) * 3   # rows: 4, 7, 10, 13
                c0 = 3 + (bit % 3) * 4    # cols: 3, 7, 11
                mask[r0][c0] = mask[r0][c0 + 1] = True
                mask[r0 + 1][c0] = mask[r0 + 1][c0 + 1] = True

        # Also encode parity & archetype family (gid // 128) in the bottom-right cell (row 13, col 7..12)
        fam_idx = (gid >> 7) & 7
        if fam_idx & 1:
            mask[13][7] = mask[13][8] = True
        if fam_idx & 2:
            mask[14][7] = mask[14][8] = True
        if fam_idx & 4:
            mask[13][11] = mask[14][11] = True

        rgba = bytearray(16 * 16 * 4)
        for y in range(16):
            for x in range(16):
                idx = (y * 16 + x) * 4
                if mask[y][x]:
                    has_up = y > 0 and mask[y - 1][x]
                    ch = '8' if not has_up else ('7' if x < 8 else '5')
                    rgba[idx:idx + 4] = bytes(GRAY_RAMP[ch])
                else:
                    n = any(
                        0 <= y + dy < 16 and 0 <= x + dx < 16 and mask[y + dy][x + dx]
                        for dy in (-1, 0, 1) for dx in (-1, 0, 1) if (dy or dx)
                    )
                    if n:
                        rgba[idx:idx + 4] = bytes(GRAY_RAMP['K'])
        return bytes(rgba)

    @classmethod
    def generate_random_passphrase(cls) -> str:
        """
        Generates a high-entropy passphrase using 8 random glyph codenames (80 bits)
        + 6 random hex bytes (48 bits) = 128 bits of cryptographic entropy.
        """
        rng = secrets.SystemRandom()
        words = [get_codename_for_id(rng.randrange(1024)) for _ in range(8)]
        return f"{'-'.join(words)}-{secrets.token_hex(6).upper()}!"

    # -------------------------------------------------------------------------
    # COMPACT BINARY FILE ENVELOPE (SAVES 33% SPACE OVER BASE64 JSON)
    # -------------------------------------------------------------------------

    @classmethod
    def pack_file_envelope(cls, filename: str, raw_bytes: bytes) -> bytes:
        """Packs filename + SHA-256 + raw file bytes into a compact binary envelope (UTF-8 boundary safe)."""
        base_str = Path(filename).name or "restored_file.bin"
        raw_name = base_str.encode("utf-8")
        if len(raw_name) > 255:
            safe_name = raw_name[:255].decode("utf-8", errors="ignore").encode("utf-8")
            if not safe_name:
                safe_name = b"restored_file.bin"
        else:
            safe_name = raw_name
        sha_digest = hashlib.sha256(raw_bytes).digest()
        return (
            cls.BIN_ENV_MAGIC
            + struct.pack(">BH", len(safe_name), 0)
            + safe_name
            + sha_digest
            + raw_bytes
        )

    @classmethod
    def unpack_file_envelope(cls, env_bytes: bytes) -> tuple:
        """Unpacks (safe_filename, raw_bytes) and verifies SHA-256 integrity."""
        if env_bytes[:4] == cls.BIN_ENV_MAGIC:
            if len(env_bytes) < 39:
                raise ValueError("Truncated binary file envelope.")
            name_len, _ = struct.unpack(">BH", env_bytes[4:7])
            pos = 7
            if len(env_bytes) < pos + name_len + 32:
                raise ValueError("Corrupted binary file envelope header.")
            safe_name = Path(env_bytes[pos:pos + name_len].decode("utf-8", errors="replace")).name
            pos += name_len
            expected_sha = env_bytes[pos:pos + 32]
            pos += 32
            raw = env_bytes[pos:]
            if not hmac.compare_digest(hashlib.sha256(raw).digest(), expected_sha):
                raise ValueError("Inner SHA-256 file hash mismatch (corrupted payload)!")
            return safe_name or "restored_file.bin", raw

        # Backward compatibility with JSON Base64 envelopes
        env = json.loads(env_bytes.decode("utf-8"))
        safe_name = Path(env.get("filename", "restored_file.bin")).name
        raw = base64.b64decode(env["b64"])
        if hashlib.sha256(raw).hexdigest() != env.get("sha256"):
            raise ValueError("Inner SHA-256 file hash mismatch!")
        return safe_name, raw

    @classmethod
    def validate_file_before_encryption(cls, file_path, for_png_output: bool = True):
        """
        Pre-flight safety check run BEFORE reading large files from disk.
        Refuses video/audio/archive files and oversized files immediately.
        """
        if not SafetyConfig.ENABLE_SAFETY_GUARDS:
            return
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {p}")

        ext = p.suffix.lower()
        size_bytes = p.stat().st_size

        if for_png_output and ext in SafetyConfig.BLOCKED_PNG_MEDIA_EXTENSIONS:
            raise SafetyLimitExceeded(
                f"Safety Guardrail Refusal:\n\n"
                f"'{p.name}' ({ext}) is a high-volume media/archive/binary format.\n\n"
                f"Visual Glyph PNGs are designed for text, source code, config files, and small assets "
                f"(up to {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px).\n\n"
                f"Encoding video/audio files into 16×16 glyph tiles would generate a massive multi-gigabyte "
                f"image canvas and is blocked for system stability."
            )

        limit = SafetyConfig.MAX_FILE_BYTES_FOR_PNG if for_png_output else SafetyConfig.MAX_FILE_BYTES_FOR_CIPH
        if size_bytes > limit:
            kb = size_bytes / 1024.0
            lim_kb = limit / 1024.0
            mode_label = "Visual Glyph PNG" if for_png_output else ".CIPH Vault"
            raise SafetyLimitExceeded(
                f"Safety Guardrail Refusal:\n\n"
                f"Selected file '{p.name}' is {kb:,.1f} KB, which exceeds the safe {mode_label} input limit "
                f"of {lim_kb:,.0f} KB.\n\n"
                f"Maximum allowed PNG canvas size is {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px "
                f"({SafetyConfig.MAX_PNG_TILES:,} glyph tiles).\n"
                f"(Developers can adjust SafetyConfig at the top of cipher_engine.py if needed.)"
            )

    # -------------------------------------------------------------------------
    # LEGEND KEYFILE GENERATION & MANAGEMENT (.legend.json)
    # -------------------------------------------------------------------------

    def generate_new_legend(self, save_path=None, comment="1,024-Glyph Master Genesis Legend (Full 1,024! Permutation)") -> dict:
        rng = secrets.SystemRandom()

        # Permute all 1,024 glyph IDs across all functional pools so role assignments are secret
        full_permutation = list(range(1024))
        rng.shuffle(full_permutation)

        data_permutation = full_permutation[:960]
        chaff_pool = full_permutation[960:976]
        rotor_pool = full_permutation[976:992]
        rle_pool = full_permutation[992:1007]
        eof_sigil = full_permutation[1007]
        checksum_pool = full_permutation[1008:1024]

        # Primes strictly coprime to both 960 (2^6 * 3 * 5) and 1,007 (19 * 53)
        coprimes = [7, 11, 13, 17, 23, 29, 31, 37, 41, 43, 47, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109]
        rotor_strides = [rng.choice(coprimes) for _ in range(16)]

        legend_obj = {
            "schema": self.LEGEND_SCHEMA,
            "comment": comment,
            "legend_id": secrets.token_hex(16),
            "genesis_salt": secrets.token_hex(32),
            "pbkdf2_iterations": self.DEFAULT_PBKDF2_ITERATIONS,
            "genesis_sbox_960": data_permutation,
            "pools": {
                "poly_null_chaff_16": chaff_pool,
                "rotor_mutators_16": rotor_pool,
                "rle_framing_15": rle_pool,
                "eof_sigil": eof_sigil,
                "tamper_checksum_16": checksum_pool
            },
            "rotor_strides_16": rotor_strides
        }

        target = Path(save_path) if save_path else self.legend_path
        with open(target, "w", encoding="utf-8") as f:
            json.dump(legend_obj, f, indent=2)

        self.legend_path = target
        self.legend = legend_obj
        return legend_obj

    @classmethod
    def _extract_full_1024_from_legend(cls, data: dict) -> list:
        """
        Extracts and strictly validates the complete 1,024-glyph permutation and parameters
        from a legend dict:
        - schema == 'CIPHER_ENGINE_1024_LEGEND_V3'
        - legend_id is a non-empty string (1..128 chars)
        - genesis_salt is an exact 64-character hex string (32 bytes, no whitespace)
        - pbkdf2_iterations is a strict int in [MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS]
        - all 1,024 glyph IDs are strict ints forming a bijection of 0..1023
        - all 16 rotor strides are strict ints in 1..959 coprime to both 960 and 1,007
        """
        if not isinstance(data, dict) or data.get("schema") not in cls.SUPPORTED_LEGEND_SCHEMAS:
            raise ValueError("Invalid or unsupported .legend.json schema.")

        legend_id = data.get("legend_id")
        if not isinstance(legend_id, str) or not (1 <= len(legend_id.strip()) <= 128):
            raise ValueError("Corrupted .legend.json: 'legend_id' must be a non-empty string (1..128 chars).")

        salt_hex = data.get("genesis_salt")
        if not isinstance(salt_hex, str) or len(salt_hex) != 64 or salt_hex != salt_hex.strip():
            raise ValueError("Corrupted .legend.json: 'genesis_salt' must be an exact 64-character hex string (256 bits).")
        try:
            salt_bytes = bytes.fromhex(salt_hex)
        except ValueError as e:
            raise ValueError("Corrupted .legend.json: 'genesis_salt' contains non-hexadecimal characters.") from e
        if len(salt_bytes) != 32:
            raise ValueError("Corrupted .legend.json: 'genesis_salt' must decode to 32 bytes.")

        iters = data.get("pbkdf2_iterations")
        if not cls._is_strict_int(iters):
            raise ValueError("Corrupted .legend.json: 'pbkdf2_iterations' must be a strict integer.")
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if not (SafetyConfig.MIN_PBKDF2_ITERATIONS <= iters <= SafetyConfig.MAX_PBKDF2_ITERATIONS):
                raise ValueError(
                    f"Corrupted .legend.json: 'pbkdf2_iterations' ({iters:,}) must be between "
                    f"{SafetyConfig.MIN_PBKDF2_ITERATIONS:,} and {SafetyConfig.MAX_PBKDF2_ITERATIONS:,}."
                )
        elif iters < 1:
            raise ValueError("Corrupted .legend.json: 'pbkdf2_iterations' must be >= 1.")

        sbox = data.get("genesis_sbox_960", [])
        pools = data.get("pools", {})
        if not isinstance(sbox, list) or not isinstance(pools, dict):
            raise ValueError("Invalid .legend.json pool structure.")

        chaff = pools.get("poly_null_chaff_16", [])
        rotor = pools.get("rotor_mutators_16", [])
        rle = pools.get("rle_framing_15", pools.get("framing_decoys_15", []))
        eof_g = pools.get("eof_sigil", cls.EOF_GLYPH_ID)
        chk = pools.get("tamper_checksum_16", [])
        strides = data.get("rotor_strides_16", [])

        if (
            not isinstance(chaff, list) or not isinstance(rotor, list)
            or not isinstance(rle, list) or not isinstance(chk, list)
            or not isinstance(strides, list)
            or len(sbox) != 960
            or len(chaff) != 16
            or len(rotor) != 16
            or len(rle) != 15
            or not cls._is_strict_int(eof_g)
            or len(chk) != 16
            or len(strides) != 16
        ):
            raise ValueError("Invalid .legend.json pool lengths.")

        for s in strides:
            if not cls._is_strict_int(s) or not (1 <= s < 960) or math.gcd(s, 960) != 1:
                raise ValueError(
                    "Invalid .legend.json: 'rotor_strides_16' must contain 16 strict integers in 1..959 coprime to both 960 and 1,007."
                )
            if math.gcd(s, 1007) != 1:
                raise ValueError(
                    f"Invalid .legend.json: rotor stride {s} is not coprime to 1,007 (19 × 53). "
                    "The active 1,007-glyph body table requires strides coprime to both 960 and 1,007."
                )

        full_1024 = list(sbox) + list(chaff) + list(rotor) + list(rle) + [eof_g] + list(chk)
        if not all(cls._is_strict_int(g) for g in full_1024):
            raise ValueError("Corrupted .legend.json: all glyph IDs must be strict integers.")
        if len(full_1024) != 1024 or set(full_1024) != set(range(1024)):
            raise ValueError("Corrupted .legend.json: glyph pools do not form a valid 1,024-glyph bijection.")
        return full_1024

    def load_legend(self, path) -> dict:
        p = Path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Legend keyfile not found: {p}")
        if SafetyConfig.ENABLE_SAFETY_GUARDS and p.stat().st_size > SafetyConfig.MAX_JSON_CONFIG_BYTES:
            raise SafetyLimitExceeded(
                f"Safety Refusal: Legend keyfile '{p.name}' exceeds {SafetyConfig.MAX_JSON_CONFIG_BYTES:,} bytes."
            )
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._extract_full_1024_from_legend(data)
        self.legend_path = p
        self.legend = data
        return data

    def ensure_default_legend(self):
        """
        Loads the default legend if present, or generates a fresh one ONLY if no file exists.
        Never silently overwrites a damaged or modified legend file on disk.
        """
        if self.legend_path.exists():
            try:
                self.load_legend(self.legend_path)
                return
            except Exception as e:
                raise ValueError(
                    f"Existing legend keyfile '{self.legend_path.name}' is corrupted or invalid ({e}). "
                    f"Refusing to overwrite it automatically to prevent key loss."
                ) from e
        self.generate_new_legend(self.legend_path)

    # -------------------------------------------------------------------------
    # TWO-SECRET KEY DERIVATION, KEY SEPARATION & MUTATING S-BOX STATE MACHINE
    # -------------------------------------------------------------------------

    def _derive_2fa_master_key(self, passphrase: str, legend: dict) -> bytes:
        self._validate_passphrase(passphrase)
        full_1024 = self._extract_full_1024_from_legend(legend)
        canonical_obj = {
            "perm_1024": full_1024,
            "strides": legend["rotor_strides_16"]
        }
        legend_canonical = json.dumps(canonical_obj, separators=(",", ":")).encode("utf-8")
        legend_digest = hashlib.sha512(legend_canonical + bytes.fromhex(legend["genesis_salt"])).digest()
        iters = int(legend["pbkdf2_iterations"])
        return hashlib.pbkdf2_hmac(
            "sha512",
            passphrase.encode("utf-8") + legend_digest[:32],
            legend_digest[32:],
            iters,
            dklen=64
        )

    @classmethod
    def _subkey(cls, key: bytes, label: str) -> bytes:
        """Derives an independent 32-byte subkey for exactly one purpose (HMAC-SHA256 over a distinct label)."""
        return hmac.new(key, cls.KDF_LABEL_PREFIX + label.encode("ascii"), hashlib.sha256).digest()

    def _derive_static_keys(self, passphrase: str) -> dict:
        """
        Runs PBKDF2 once and splits the 512-bit master output into independent labeled subkeys,
        so no key bytes are reused for two different jobs.
        """
        master = self._derive_2fa_master_key(passphrase, self._require_legend())
        return {
            "table": self._subkey(master, "genesis-table"),
            "nonce_mask": self._subkey(master, "nonce-mask"),
            "session_root": self._subkey(master, "session-root"),
        }

    @classmethod
    def _derive_session_keys(cls, session_root: bytes, nonce: bytes) -> dict:
        """Derives the per-message encryption, MAC, and glyph-layout keys from the session root and nonce."""
        session_secret = hmac.new(session_root, cls.KDF_LABEL_PREFIX + b"session|" + nonce, hashlib.sha256).digest()
        return {
            "enc": cls._subkey(session_secret, "encrypt"),
            "mac": cls._subkey(session_secret, "mac"),
            "layout": cls._subkey(session_secret, "layout"),
        }

    @staticmethod
    def _init_sbox_from_key(base_sbox: list, key_material: bytes) -> list:
        """Deterministically permutes a glyph list of any length (e.g. 1,024 or 960) using SHAKE-256."""
        sbox = list(base_sbox)
        n = len(sbox)
        stream = hashlib.shake_256(key_material).digest(n * 4)
        for i in range(n - 1, 0, -1):
            rand_u32 = struct.unpack(">I", stream[i * 4:(i + 1) * 4])[0]
            j = rand_u32 % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    @staticmethod
    def _mutate_sbox_rotor(
        sbox: list,
        rotor_idx: int,
        step_num: int,
        stride: int,
        layout_key: bytes,
        inv_sbox: Optional[list] = None,
    ):
        """
        Mutates the active glyph table in-place across all elements of `sbox`
        (1,007 active body/chaff/rotor/framing slots in V3).
        If `inv_sbox` (a 1,024-slot inverse lookup list) is provided, updates it in O(1) per swap.
        """
        n = len(sbox)
        seed = hashlib.sha256(layout_key + struct.pack(">II", rotor_idx, step_num)).digest()
        offset = (seed[0] << 8) | seed[1]
        for k in range(32):
            a = (offset + k * stride) % n
            b = (a + seed[2 + (k % 30)] + 1) % n
            ga, gb = sbox[a], sbox[b]
            sbox[a], sbox[b] = gb, ga
            if inv_sbox is not None:
                inv_sbox[ga] = b
                inv_sbox[gb] = a

    @staticmethod
    def _byte_to_homophone_range(b_val: int) -> tuple:
        if b_val < 192:
            return b_val * 4, 4
        return 768 + (b_val - 192) * 3, 3

    @staticmethod
    def _sbox_index_to_byte_and_slot(sbox_idx: int) -> tuple:
        if sbox_idx < 768:
            return sbox_idx // 4, sbox_idx % 4, 4
        rem = sbox_idx - 768
        return 192 + (rem // 3), rem % 3, 3

    # -------------------------------------------------------------------------
    # PRE-FLIGHT GLYPH COUNT & 4096x4096 GRID DIMENSION CALCULATOR
    # -------------------------------------------------------------------------

    @classmethod
    def _compute_grid_dims(cls, num_glyphs: int, layout_mode: str, enforce_png_limit: bool = True) -> tuple:
        """
        Computes (cols, rows, total_cells) while enforcing SafetyConfig's
        4096x4096 px (256x256 tiles = 65,536 tiles) ceiling when enforce_png_limit is True,
        and SafetyConfig.MAX_CIPH_GLYPHS when enforce_png_limit is False.
        """
        if layout_mode not in cls.LAYOUT_TO_CODE:
            raise ValueError(f"Unsupported layout_mode: {layout_mode!r}")

        max_cols = SafetyConfig.MAX_PNG_WIDTH_PX // 16   # 256
        max_rows = SafetyConfig.MAX_PNG_HEIGHT_PX // 16  # 256

        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if enforce_png_limit and num_glyphs > SafetyConfig.MAX_PNG_TILES:
                est_side = math.ceil(math.sqrt(num_glyphs)) * 16
                raise SafetyLimitExceeded(
                    f"Safety Guardrail Refusal:\n\n"
                    f"This payload requires {num_glyphs:,} glyph tiles (~{est_side}×{est_side} px), "
                    f"which exceeds the maximum safe PNG limit of {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px "
                    f"({SafetyConfig.MAX_PNG_TILES:,} tiles)."
                )
            if not enforce_png_limit and num_glyphs > SafetyConfig.MAX_CIPH_GLYPHS:
                raise SafetyLimitExceeded(
                    f"Safety Guardrail Refusal:\n\n"
                    f"This payload requires {num_glyphs:,} glyphs, which exceeds the maximum safe .CIPH limit "
                    f"of {SafetyConfig.MAX_CIPH_GLYPHS:,} glyphs."
                )

        if layout_mode == "strip_horizontal":
            if not (SafetyConfig.ENABLE_SAFETY_GUARDS and enforce_png_limit) or num_glyphs <= max_cols:
                cols = max(1, num_glyphs)
                rows = 1
            else:
                cols = max_cols
                rows = (num_glyphs + cols - 1) // cols

        elif layout_mode == "scroll_16":
            cols = 16
            rows = (num_glyphs + cols - 1) // cols
            if SafetyConfig.ENABLE_SAFETY_GUARDS and enforce_png_limit and rows > max_rows:
                cols = min(max_cols, math.ceil(num_glyphs / max_rows))
                rows = (num_glyphs + cols - 1) // cols

        elif layout_mode == "square_block":
            side = max(1, math.ceil(math.sqrt(num_glyphs)))
            cols, rows = side, side

        else:  # "scroll_32"
            cols = 32
            rows = (num_glyphs + cols - 1) // cols
            if SafetyConfig.ENABLE_SAFETY_GUARDS and enforce_png_limit and rows > max_rows:
                cols = min(max_cols, math.ceil(num_glyphs / max_rows))
                rows = (num_glyphs + cols - 1) // cols

        total_cells = cols * rows
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if enforce_png_limit and (cols * 16 > SafetyConfig.MAX_PNG_WIDTH_PX or rows * 16 > SafetyConfig.MAX_PNG_HEIGHT_PX or total_cells > SafetyConfig.MAX_PNG_TILES):
                raise SafetyLimitExceeded(
                    f"Safety Guardrail Refusal: Computed grid {cols}×{rows} ({total_cells:,} tiles) exceeds safe PNG limits."
                )
            if not enforce_png_limit and total_cells > SafetyConfig.MAX_CIPH_GLYPHS:
                raise SafetyLimitExceeded(
                    f"Safety Guardrail Refusal: Computed grid ({total_cells:,} glyphs) exceeds safe .CIPH limit of {SafetyConfig.MAX_CIPH_GLYPHS:,} glyphs."
                )
        return cols, rows, total_cells

    # -------------------------------------------------------------------------
    # ENCRYPTION PIPELINE (TEXT / BINARY -> GLYPH STREAM + TELEMETRY)
    # -------------------------------------------------------------------------

    def encrypt_bytes(
        self,
        plaintext: bytes,
        passphrase: str,
        chaff_interval: int = 7,
        rotor_interval: int = 16,
        layout_mode: str = "scroll_32",
        for_png_output: bool = True,
        include_telemetry: Optional[bool] = None,
    ) -> dict:
        self._require_legend()

        self._validate_passphrase(passphrase)
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext payload must be bytes or bytearray.")
        if layout_mode not in self.LAYOUT_TO_CODE:
            raise ValueError(f"Unsupported layout_mode: {layout_mode!r}")
        if not self._is_strict_int(chaff_interval) or not (0 <= chaff_interval <= 255):
            raise ValueError("chaff_interval must be an integer in 0..255.")
        if not self._is_strict_int(rotor_interval) or not (0 <= rotor_interval <= 255):
            raise ValueError("rotor_interval must be an integer in 0..255.")

        # Pre-flight input byte limit BEFORE calling zlib.compress (prevents zip-bomb bypasses)
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            raw_limit = (
                SafetyConfig.MAX_FILE_BYTES_FOR_PNG + 512
                if for_png_output
                else SafetyConfig.MAX_FILE_BYTES_FOR_CIPH + 512
            )
            if len(plaintext) > raw_limit:
                mode_label = "Visual Glyph PNG" if for_png_output else ".CIPH Vault"
                raise SafetyLimitExceeded(
                    f"Safety Refusal: Input payload ({len(plaintext):,} bytes) exceeds the maximum safe "
                    f"{mode_label} limit of {raw_limit - 512:,} bytes."
                )

        compressed = zlib.compress(bytes(plaintext), level=9)

        # Key separation (V5): independent labeled subkeys for the genesis table, nonce mask and session root
        static_keys = self._derive_static_keys(passphrase)
        base_1024 = self._extract_full_1024_from_legend(self.legend)
        genesis_table_1024 = self._init_sbox_from_key(base_1024, static_keys["table"])
        genesis_sbox = genesis_table_1024[:960]
        nonce_mask = static_keys["nonce_mask"]

        raw_nonce = secrets.token_bytes(self.NONCE_BYTES)
        if not isinstance(raw_nonce, (bytes, bytearray)) or len(raw_nonce) != self.NONCE_BYTES:
            raise RuntimeError(
                f"CSPRNG failure: secrets.token_bytes({self.NONCE_BYTES}) returned "
                f"{len(raw_nonce) if isinstance(raw_nonce, (bytes, bytearray)) else type(raw_nonce).__name__} bytes "
                f"(expected {self.NONCE_BYTES})."
            )
        nonce = bytes(raw_nonce)

        # Per-message subkeys: 'enc' (keystream), 'mac' (authentication tag), 'layout' (glyph encoding layer)
        session_keys = self._derive_session_keys(static_keys["session_root"], nonce)
        layout_key = session_keys["layout"]

        # Pre-calculate exact deterministic glyph counts so the canonical frame header can be encrypted & authenticated
        full_body_len = self.FRAME_HEADER_BYTES + len(compressed) + self.HMAC_TAG_BYTES
        slot_stream = hashlib.shake_256(layout_key + b"SLOT").digest(full_body_len)
        chaff_stream = hashlib.shake_256(layout_key + b"CHAFF").digest(full_body_len * 3 + 128)

        chaff_count = 0
        if chaff_interval > 0:
            mod_c = max(2, chaff_interval)
            for idx in range(full_body_len):
                if (chaff_stream[idx * 3] % mod_c) == 0:
                    chaff_count += 1 + (1 if (chaff_stream[idx * 3 + 2] & 0x07) == 0 else 0)
        rotor_count = (full_body_len // rotor_interval) if rotor_interval > 0 else 0
        base_before_tail = self.NONCE_BYTES + full_body_len + chaff_count + rotor_count

        tail_offset = full_body_len * 3
        pre_eof_total = base_before_tail + self.VISUAL_SEAL_COUNT + 1
        bucket_pad = (32 - (pre_eof_total % 32)) % 32
        jitter_pad = chaff_stream[tail_offset] % 16
        extra_decoys = bucket_pad + jitter_pad
        if SafetyConfig.ENABLE_SAFETY_GUARDS and for_png_output:
            max_extra = max(0, SafetyConfig.MAX_PNG_TILES - pre_eof_total)
            extra_decoys = min(extra_decoys, max_extra)

        eof_pos = base_before_tail + extra_decoys + self.VISUAL_SEAL_COUNT
        cols, rows, total_cells = self._compute_grid_dims(eof_pos + 1, layout_mode, enforce_png_limit=for_png_output)

        layout_code = self.LAYOUT_TO_CODE[layout_mode]
        for_png_flag = 1 if for_png_output else 0
        ver_and_flags = ((self.PROTOCOL_VERSION & 0x0F) << 4) | (for_png_flag & 0x0F)
        frame_header = struct.pack(
            ">BBBBIIIII",
            layout_code,
            ver_and_flags,
            chaff_interval,
            rotor_interval,
            cols,
            rows,
            eof_pos,
            total_cells,
            len(compressed),
        )
        framed_payload = frame_header + compressed

        # Encrypt-then-MAC: XOR with a SHAKE-256 keystream, then a full 256-bit HMAC-SHA256 tag over
        # Protocol Schema + Nonce + Ciphertext (the encrypted frame header + compressed payload)
        keystream = hashlib.shake_256(session_keys["enc"] + b"STREAM").digest(len(framed_payload))
        ciphertext = bytes(p ^ k for p, k in zip(framed_payload, keystream))
        auth_tag = hmac.new(
            session_keys["mac"],
            self.PACKET_SCHEMA.encode("ascii") + b"\x00" + nonce + ciphertext,
            hashlib.sha256,
        ).digest()
        wire_body = ciphertext + auth_tag

        if include_telemetry is None:
            build_telemetry = bool(for_png_output) or (total_cells <= 16_384)
        else:
            build_telemetry = bool(include_telemetry)

        sequence = []
        telemetry = []

        # Step A: Encode the 16-byte (128-bit) Nonce using Genesis S-Box (first 960 slots of genesis_table_1024)
        prev_b = 0x5A
        for i, nb in enumerate(nonce):
            masked = (nb ^ nonce_mask[i] ^ prev_b) & 0xFF
            base_idx, num_slots = self._byte_to_homophone_range(masked)
            slot = (i + prev_b) % num_slots
            gid = genesis_sbox[base_idx + slot]
            sequence.append(gid)
            if build_telemetry:
                telemetry.append({
                    "pos": len(sequence) - 1,
                    "glyph_id": gid,
                    "codename": self.glyphs[gid]["name"],
                    "family": self.glyphs[gid]["family"],
                    "type": "NONCE_HEADER",
                    "detail": f"Session Nonce Byte #{i+1}/{self.NONCE_BYTES} • Homophone Slot {slot+1}/{num_slots}"
                })
            prev_b = masked

        # Step B: Permute all 1,024 glyphs with the layout key so every role pool is session-secret
        session_table_1024 = self._init_sbox_from_key(genesis_table_1024, layout_key)
        body_table_1007 = list(session_table_1024[:1007])
        session_eof_gid = session_table_1024[1007]
        checksum_pool = session_table_1024[1008:1024]
        strides = self.legend["rotor_strides_16"]

        rotor_gen = 0

        # Glyph layer: encode each ciphertext/tag byte as one of its 3-4 homophones in the mutating body table
        for idx, c_byte in enumerate(wire_body):
            base_idx, num_slots = self._byte_to_homophone_range(c_byte)
            slot = slot_stream[idx] % num_slots

            gid = body_table_1007[base_idx + slot]
            is_auth_byte = idx >= len(ciphertext)
            sequence.append(gid)
            if build_telemetry:
                telemetry.append({
                    "pos": len(sequence) - 1,
                    "glyph_id": gid,
                    "codename": self.glyphs[gid]["name"],
                    "family": self.glyphs[gid]["family"],
                    "type": "AUTH_MAC_BYTE" if is_auth_byte else "DATA_GLYPH",
                    "detail": (
                        f"{'256-Bit HMAC Tag Byte #' + str(idx - len(ciphertext) + 1) + '/32' if is_auth_byte else f'Ciphertext Byte #{idx}'} • "
                        f"Homophone {slot+1}/{num_slots} • Rotor Gen #{rotor_gen}"
                    )
                })

            # Key-driven randomized chaff injection (authenticated & verified on decode)
            if chaff_interval > 0:
                c_trig = chaff_stream[idx * 3]
                c_sel1 = chaff_stream[idx * 3 + 1]
                c_sel2 = chaff_stream[idx * 3 + 2]
                if (c_trig % max(2, chaff_interval)) == 0:
                    chaff_gid = body_table_1007[960 + (c_sel1 % 16)]
                    sequence.append(chaff_gid)
                    if build_telemetry:
                        telemetry.append({
                            "pos": len(sequence) - 1,
                            "glyph_id": chaff_gid,
                            "codename": self.glyphs[chaff_gid]["name"],
                            "family": self.glyphs[chaff_gid]["family"],
                            "type": "POLY_NULL_CHAFF",
                            "detail": "Key-Driven Poly-Null Chaff (Session-permuted decoy; verified & stripped on decode)"
                        })
                    if (c_sel2 & 0x07) == 0:
                        burst_gid = body_table_1007[992 + ((c_sel1 ^ c_sel2) % 15)]
                        sequence.append(burst_gid)
                        if build_telemetry:
                            telemetry.append({
                                "pos": len(sequence) - 1,
                                "glyph_id": burst_gid,
                                "codename": self.glyphs[burst_gid]["name"],
                                "family": self.glyphs[burst_gid]["family"],
                                "type": "POLY_NULL_CHAFF",
                                "detail": "Key-Driven Framing Decoy (Obfuscates compressed message length)"
                            })

            if rotor_interval > 0 and (idx + 1) % rotor_interval == 0:
                r_idx = (idx // rotor_interval) % 16
                r_gid = body_table_1007[976 + r_idx]
                self._mutate_sbox_rotor(body_table_1007, r_idx, idx + 1, strides[r_idx], layout_key)
                rotor_gen += 1
                sequence.append(r_gid)
                if build_telemetry:
                    telemetry.append({
                        "pos": len(sequence) - 1,
                        "glyph_id": r_gid,
                        "codename": self.glyphs[r_gid]["name"],
                        "family": self.glyphs[r_gid]["family"],
                        "type": "ROTOR_MUTATOR",
                        "detail": f"Rotor Step Sigil #{r_idx} → Mutated 1,007-Glyph Body Table to Gen #{rotor_gen}"
                    })

        # Step B.2: Pre-EOF Length-Obfuscating Bucket & Jitter Padding
        for d_i in range(extra_decoys):
            b_ent = chaff_stream[tail_offset + 1 + (d_i % 64)]
            if (b_ent & 1) == 0:
                decoy_gid = body_table_1007[960 + ((b_ent >> 1) + d_i) % 16]
            else:
                decoy_gid = body_table_1007[992 + ((b_ent >> 1) + d_i) % 15]
            sequence.append(decoy_gid)
            if build_telemetry:
                telemetry.append({
                    "pos": len(sequence) - 1,
                    "glyph_id": decoy_gid,
                    "codename": self.glyphs[decoy_gid]["name"],
                    "family": self.glyphs[decoy_gid]["family"],
                    "type": "POLY_NULL_CHAFF",
                    "detail": "Pre-EOF Length-Masking Decoy (Quantizes & blurs payload length)"
                })

        # Step C: Append 8 Visual Tamper-Checksum Sigils (32-Bit Seal) + 1 Session EOF Sigil
        stream_digest = hmac.new(layout_key, struct.pack(f">{len(sequence)}H", *sequence), hashlib.sha256).digest()
        for k in range(self.VISUAL_SEAL_COUNT):
            byte_val = stream_digest[k // 2]
            nib = ((byte_val >> 4) if (k % 2 == 0) else byte_val) & 0x0F
            chk_gid = checksum_pool[nib]
            sequence.append(chk_gid)
            if build_telemetry:
                telemetry.append({
                    "pos": len(sequence) - 1,
                    "glyph_id": chk_gid,
                    "codename": self.glyphs[chk_gid]["name"],
                    "family": self.glyphs[chk_gid]["family"],
                    "type": "TAMPER_CHECKSUM",
                    "detail": f"Visual Tamper-Checksum Seal #{k+1}/{self.VISUAL_SEAL_COUNT} (Nibble 0x{nib:X} • 32-Bit Seal)"
                })

        eof_gid = session_eof_gid
        sequence.append(eof_gid)
        if build_telemetry:
            telemetry.append({
                "pos": len(sequence) - 1,
                "glyph_id": eof_gid,
                "codename": self.glyphs[eof_gid]["name"],
                "family": self.glyphs[eof_gid]["family"],
                "type": "EOF_SIGIL",
                "detail": f"Session-Permuted End-Of-Frame Sigil (#{eof_gid:04d})"
            })

        # Step D: Pad trailing grid cells across all 1,007 body glyphs
        pad_needed = total_cells - len(sequence)
        pad_seed = hashlib.shake_256(layout_key + b"PAD" + stream_digest).digest(max(2, pad_needed * 2))
        for p in range(pad_needed):
            u16 = (pad_seed[p * 2] << 8) | pad_seed[p * 2 + 1]
            pad_gid = session_table_1024[u16 % 1007]
            sequence.append(pad_gid)
            if build_telemetry:
                telemetry.append({
                    "pos": len(sequence) - 1,
                    "glyph_id": pad_gid,
                    "codename": self.glyphs[pad_gid]["name"],
                    "family": self.glyphs[pad_gid]["family"],
                    "type": "GRID_PAD_CHAFF",
                    "detail": "Authenticated Post-EOF Grid Padding (Uniformly distributed across 1,007 glyphs)"
                })

        return {
            "schema": self.PACKET_SCHEMA,
            "protocol_version": self.PROTOCOL_VERSION,
            "legend_id": self.legend["legend_id"],
            "nonce_hex": nonce.hex(),
            "layout_mode": layout_mode,
            "grid_cols": cols,
            "grid_rows": rows,
            "session_eof_id": eof_gid,
            "sequence": sequence,
            "codenames": "-".join(self.glyphs[g]["name"] for g in sequence) if build_telemetry else "",
            "telemetry": telemetry,
            "final_sbox_sample": body_table_1007[:64]
        }

    # -------------------------------------------------------------------------
    # DECRYPTION PIPELINE (GLYPH STREAM / PNG -> VERIFIED PLAINTEXT BYTES)
    # -------------------------------------------------------------------------

    def decrypt_sequence(
        self,
        sequence: list,
        passphrase: str,
        expected_grid: Optional[tuple[int, int]] = None,
        require_png_flag: bool = False,
    ) -> bytes:
        """
        Verifies and decrypts a Protocol V5 glyph sequence (encrypt-then-MAC).

        Order of operations:
        1. Decode the glyph layer back into ciphertext bytes (nonce header, seals, padding, chaff, rotors).
        2. Verify the full 256-bit HMAC-SHA256 tag over the ciphertext BEFORE any decryption happens.
        3. Decrypt, then verify the canonical frame header, grid geometry and exact glyph schedule.
        4. Only then decompress the message payload.

        Digest comparisons use hmac.compare_digest and every verification failure raises the same uniform message.
        (As a pure-Python implementation, total execution time still varies with message length and runtime behavior.)
        """
        self._require_legend()
        self._validate_passphrase(passphrase)
        if not isinstance(sequence, list):
            raise ValueError("Invalid ciphertext sequence: expected a list of glyph IDs in 0..1023.")

        if SafetyConfig.ENABLE_SAFETY_GUARDS and len(sequence) > SafetyConfig.MAX_CIPH_GLYPHS:
            raise SafetyLimitExceeded(
                f"Safety Refusal: Ciphertext sequence ({len(sequence):,} glyphs) exceeds the maximum safe limit "
                f"of {SafetyConfig.MAX_CIPH_GLYPHS:,} glyphs."
            )

        if not all(self._is_strict_int(g) and 0 <= g < 1024 for g in sequence):
            raise ValueError("Invalid ciphertext sequence: expected a list of glyph IDs in 0..1023.")

        min_valid_len = self.NONCE_BYTES + self.FRAME_HEADER_BYTES + self.HMAC_TAG_BYTES + self.VISUAL_SEAL_COUNT + 1
        if len(sequence) < min_valid_len:
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        static_keys = self._derive_static_keys(passphrase)
        base_1024 = self._extract_full_1024_from_legend(self.legend)
        genesis_table_1024 = self._init_sbox_from_key(base_1024, static_keys["table"])
        genesis_sbox = genesis_table_1024[:960]
        inv_genesis = {gid: idx for idx, gid in enumerate(genesis_sbox)}
        nonce_mask = static_keys["nonce_mask"]

        # Step 1: Decode the 16-glyph (128-bit) Nonce Header
        nonce_bytes = bytearray()
        prev_b = 0x5A
        cursor = 0
        auth_ok = True
        while len(nonce_bytes) < self.NONCE_BYTES and cursor < len(sequence):
            gid = sequence[cursor]
            cursor += 1
            sbox_idx = inv_genesis.get(gid)
            if sbox_idx is None:
                auth_ok = False
                nonce_bytes.append(0)
                continue
            masked, slot, num_slots = self._sbox_index_to_byte_and_slot(sbox_idx)
            expected_slot = ((len(nonce_bytes)) + prev_b) % num_slots
            if slot != expected_slot:
                auth_ok = False
            nb = (masked ^ nonce_mask[len(nonce_bytes)] ^ prev_b) & 0xFF
            nonce_bytes.append(nb)
            prev_b = masked

        nonce = bytes(nonce_bytes)
        session_keys = self._derive_session_keys(static_keys["session_root"], nonce)
        layout_key = session_keys["layout"]

        # Step 2: Derive session-permuted 1,024-glyph table & locate session EOF sigil
        session_table_1024 = self._init_sbox_from_key(genesis_table_1024, layout_key)
        session_eof_gid = session_table_1024[1007]
        checksum_pool = session_table_1024[1008:1024]

        tail_seq = sequence[cursor:]
        eof_occurrences = [cursor + i for i, g in enumerate(tail_seq) if g == session_eof_gid]
        if len(eof_occurrences) != 1:
            auth_ok = False
            eof_pos = len(sequence) - 1
        else:
            eof_pos = eof_occurrences[0]

        if eof_pos < self.NONCE_BYTES + self.VISUAL_SEAL_COUNT + self.FRAME_HEADER_BYTES + self.HMAC_TAG_BYTES:
            auth_ok = False
            eof_pos = max(self.NONCE_BYTES + self.VISUAL_SEAL_COUNT, len(sequence) - 1)

        core_seq = sequence[:eof_pos]
        pad_seq = sequence[eof_pos + 1:]

        body_seq = core_seq[:-self.VISUAL_SEAL_COUNT]
        chk_seq = core_seq[-self.VISUAL_SEAL_COUNT:]

        # Step 3: Digest comparison via hmac.compare_digest of all 8 Visual Checksum Seals (32-Bit Seal)
        stream_digest = hmac.new(layout_key, struct.pack(f">{len(body_seq)}H", *body_seq), hashlib.sha256).digest()
        expected_seals = []
        for k in range(self.VISUAL_SEAL_COUNT):
            byte_val = stream_digest[k // 2]
            nib = ((byte_val >> 4) if (k % 2 == 0) else byte_val) & 0x0F
            expected_seals.append(checksum_pool[nib])

        if len(chk_seq) != self.VISUAL_SEAL_COUNT:
            auth_ok = False
        else:
            actual_chk_bytes = struct.pack(f">{self.VISUAL_SEAL_COUNT}H", *chk_seq)
            expected_chk_bytes = struct.pack(f">{self.VISUAL_SEAL_COUNT}H", *expected_seals)
            if not hmac.compare_digest(actual_chk_bytes, expected_chk_bytes):
                auth_ok = False

        # Step 4: Digest comparison via hmac.compare_digest of all Post-EOF Grid Padding Tiles
        if pad_seq:
            pad_seed = hashlib.shake_256(layout_key + b"PAD" + stream_digest).digest(max(2, len(pad_seq) * 2))
            expected_pad = []
            for p in range(len(pad_seq)):
                u16 = (pad_seed[p * 2] << 8) | pad_seed[p * 2 + 1]
                expected_pad.append(session_table_1024[u16 % 1007])
            actual_pad_bytes = struct.pack(f">{len(pad_seq)}H", *pad_seq)
            expected_pad_bytes = struct.pack(f">{len(expected_pad)}H", *expected_pad)
            if not hmac.compare_digest(actual_pad_bytes, expected_pad_bytes):
                auth_ok = False

        # Step 5: Decode the glyph layer (mutating 1,007-glyph body table) back into ciphertext + tag bytes
        body_table_1007 = list(session_table_1024[:1007])
        inv_body = [-1] * 1024
        for idx, g in enumerate(body_table_1007):
            inv_body[g] = idx
        strides = self.legend["rotor_strides_16"]
        slot_stream = hashlib.shake_256(layout_key + b"SLOT").digest(len(body_seq) + 64)

        wire_body = bytearray()
        data_idx = 0

        for pos in range(cursor, len(body_seq)):
            gid = body_seq[pos]
            pool_idx = inv_body[gid]
            if pool_idx < 0:
                auth_ok = False
                continue

            # Chaff pool (960..975) or Framing/Decoy pool (992..1006)
            if (960 <= pool_idx < 976) or (992 <= pool_idx < 1007):
                continue

            # Rotor Mutator pool (976..991)
            if 976 <= pool_idx < 992:
                r_idx = pool_idx - 976
                self._mutate_sbox_rotor(body_table_1007, r_idx, data_idx, strides[r_idx], layout_key, inv_body)
                continue

            # Active Data/MAC Homophone S-Box (0..959)
            c_byte, slot, num_slots = self._sbox_index_to_byte_and_slot(pool_idx)
            if slot != slot_stream[data_idx] % num_slots:
                auth_ok = False
            wire_body.append(c_byte)
            data_idx += 1

        if len(wire_body) < self.FRAME_HEADER_BYTES + self.HMAC_TAG_BYTES:
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        # Step 6: Encrypt-then-MAC — verify the 256-bit tag over the ciphertext BEFORE decrypting anything
        ciphertext = bytes(wire_body[:-self.HMAC_TAG_BYTES])
        received_tag = bytes(wire_body[-self.HMAC_TAG_BYTES:])
        expected_tag = hmac.new(
            session_keys["mac"],
            self.PACKET_SCHEMA.encode("ascii") + b"\x00" + nonce + ciphertext,
            hashlib.sha256,
        ).digest()
        tag_ok = hmac.compare_digest(received_tag, expected_tag)
        if not tag_ok or not auth_ok:
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        # Step 7: Decrypt the authenticated ciphertext
        keystream = hashlib.shake_256(session_keys["enc"] + b"STREAM").digest(len(ciphertext))
        framed_payload = bytes(c ^ k for c, k in zip(ciphertext, keystream))

        # Step 8: Verify canonical 24-byte frame header (including protocol version & layout geometry)
        (
            layout_code,
            ver_and_flags,
            chaff_interval,
            rotor_interval,
            expected_cols,
            expected_rows,
            expected_eof_pos,
            expected_total_cells,
            comp_len,
        ) = struct.unpack(">BBBBIIIII", framed_payload[:self.FRAME_HEADER_BYTES])

        protocol_version = (ver_and_flags >> 4) & 0x0F
        for_png_flag = ver_and_flags & 0x0F

        if (
            protocol_version != self.PROTOCOL_VERSION
            or (ver_and_flags & 0x0E) != 0
            or layout_code not in self.CODE_TO_LAYOUT
            or for_png_flag not in (0, 1)
            or (require_png_flag and for_png_flag != 1)
            or comp_len != len(framed_payload) - self.FRAME_HEADER_BYTES
            or eof_pos != expected_eof_pos
            or len(sequence) != expected_total_cells
            or expected_cols <= 0
            or expected_rows <= 0
            or expected_cols * expected_rows != expected_total_cells
        ):
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        try:
            calc_cols, calc_rows, calc_total = self._compute_grid_dims(
                expected_eof_pos + 1,
                self.CODE_TO_LAYOUT[layout_code],
                enforce_png_limit=bool(for_png_flag),
            )
        except Exception as e:
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG) from e

        if (expected_cols, expected_rows, expected_total_cells) != (calc_cols, calc_rows, calc_total):
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        if expected_grid is not None and expected_grid != (expected_cols, expected_rows):
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        # Step 9: Require the exact canonical glyph encoding (homophones + chaff + decoys + rotors + pre-EOF pad)
        chaff_stream = hashlib.shake_256(layout_key + b"CHAFF").digest(len(wire_body) * 3 + 128)
        verify_table_1007 = list(session_table_1024[:1007])
        expected_body_seq = list(sequence[:cursor])

        for idx, c_byte in enumerate(wire_body):
            base_idx, num_slots = self._byte_to_homophone_range(c_byte)
            slot = slot_stream[idx] % num_slots
            expected_body_seq.append(verify_table_1007[base_idx + slot])

            if chaff_interval > 0:
                c_trig = chaff_stream[idx * 3]
                c_sel1 = chaff_stream[idx * 3 + 1]
                c_sel2 = chaff_stream[idx * 3 + 2]
                if (c_trig % max(2, chaff_interval)) == 0:
                    expected_body_seq.append(verify_table_1007[960 + (c_sel1 % 16)])
                    if (c_sel2 & 0x07) == 0:
                        expected_body_seq.append(verify_table_1007[992 + ((c_sel1 ^ c_sel2) % 15)])

            if rotor_interval > 0 and (idx + 1) % rotor_interval == 0:
                r_idx = (idx // rotor_interval) % 16
                expected_body_seq.append(verify_table_1007[976 + r_idx])
                self._mutate_sbox_rotor(verify_table_1007, r_idx, idx + 1, strides[r_idx], layout_key)

        tail_offset = len(wire_body) * 3
        base_before_tail = len(expected_body_seq)
        pre_eof_total = base_before_tail + self.VISUAL_SEAL_COUNT + 1
        bucket_pad = (32 - (pre_eof_total % 32)) % 32
        jitter_pad = chaff_stream[tail_offset] % 16
        expected_extra_decoys = bucket_pad + jitter_pad
        if SafetyConfig.ENABLE_SAFETY_GUARDS and bool(for_png_flag):
            max_extra = max(0, SafetyConfig.MAX_PNG_TILES - pre_eof_total)
            expected_extra_decoys = min(expected_extra_decoys, max_extra)

        extra_decoys = len(body_seq) - base_before_tail
        if extra_decoys != expected_extra_decoys:
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        for d_i in range(extra_decoys):
            b_ent = chaff_stream[tail_offset + 1 + (d_i % 64)]
            if (b_ent & 1) == 0:
                decoy_gid = verify_table_1007[960 + ((b_ent >> 1) + d_i) % 16]
            else:
                decoy_gid = verify_table_1007[992 + ((b_ent >> 1) + d_i) % 15]
            expected_body_seq.append(decoy_gid)

        if len(expected_body_seq) != len(body_seq):
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)
        actual_body_bytes = struct.pack(f">{len(body_seq)}H", *body_seq)
        expected_body_bytes = struct.pack(f">{len(expected_body_seq)}H", *expected_body_seq)
        if not hmac.compare_digest(actual_body_bytes, expected_body_bytes):
            raise ValueError(self.UNIFORM_AUTH_FAILURE_MSG)

        # Step 10: Message-payload decompression happens only after every check above has passed
        compressed = framed_payload[self.FRAME_HEADER_BYTES:self.FRAME_HEADER_BYTES + comp_len]
        max_out = (SafetyConfig.MAX_FILE_BYTES_FOR_CIPH + 4096) if SafetyConfig.ENABLE_SAFETY_GUARDS else (64 * 1024 * 1024)
        return strict_zlib_decompress(compressed, max_out)

    def decrypt_ciph_packet(self, pkt: dict, passphrase: str) -> bytes:
        """
        Validates outer .CIPH packet metadata (schema, protocol_version, legend_id, codenames)
        and dispatches strictly to the Protocol V5 decrypt_sequence().
        Files from cipher_engine.py v1 (Protocol V4) must be opened with that v1 script.
        """
        self._require_legend()
        if not isinstance(pkt, dict):
            raise ValueError("Malformed .CIPH packet: expected a JSON object.")

        schema = pkt.get("schema")
        if schema != self.PACKET_SCHEMA:
            hint = ""
            if schema == "CIPHER_1024_PACKET_V4":
                hint = " This file was made with cipher_engine.py v1 (Protocol V4); open it with that script."
            raise ValueError(
                f"Unsupported .CIPH packet schema {schema!r} (expected '{self.PACKET_SCHEMA}').{hint}"
            )
        if "protocol_version" in pkt and (
            not self._is_strict_int(pkt["protocol_version"]) or pkt["protocol_version"] != self.PROTOCOL_VERSION
        ):
            raise ValueError(
                f"Invalid .CIPH protocol_version {pkt.get('protocol_version')!r} (expected {self.PROTOCOL_VERSION})."
            )

        pkt_legend_id = pkt.get("legend_id")
        active_legend_id = self.legend.get("legend_id")
        if not isinstance(pkt_legend_id, str) or pkt_legend_id != active_legend_id:
            raise ValueError(
                f"Legend Keyfile Mismatch: packet was encrypted with Legend ID '{pkt_legend_id}', "
                f"but the currently loaded Legend ID is '{active_legend_id}'."
            )

        seq = pkt.get("sequence")
        if not isinstance(seq, list):
            raise ValueError("Malformed .CIPH packet: missing 'sequence' list.")

        codenames_val = pkt.get("codenames")
        if codenames_val is not None:
            if not isinstance(codenames_val, str):
                raise ValueError("Malformed .CIPH packet: 'codenames' must be a string.")
            if codenames_val:
                expected_cn = "-".join(
                    self.glyphs[g]["name"] if (self._is_strict_int(g) and 0 <= g < 1024) else "?"
                    for g in seq
                )
                if codenames_val != expected_cn:
                    raise ValueError("Malformed .CIPH packet: 'codenames' does not match 'sequence'.")

        return self.decrypt_sequence(seq, passphrase)

    # -------------------------------------------------------------------------
    # OPTICAL 2D PNG SCROLL RENDERING & OPTICAL PNG SCANNER
    # -------------------------------------------------------------------------

    def render_sequence_to_rgba(self, sequence: list, cols: int, rows: int) -> tuple:
        """Stitches a sequence of 16x16 Glyph IDs into a single (W, H, RGBA) image buffer."""
        img_w = cols * 16
        img_h = rows * 16
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if img_w > SafetyConfig.MAX_PNG_WIDTH_PX or img_h > SafetyConfig.MAX_PNG_HEIGHT_PX:
                raise SafetyLimitExceeded(
                    f"Safety Refusal: Requested PNG canvas ({img_w}×{img_h} px) exceeds the "
                    f"{SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px safety limit."
                )

        canvas = bytearray(img_w * img_h * 4)

        for idx, gid in enumerate(sequence):
            if idx >= cols * rows:
                break
            gx = (idx % cols) * 16
            gy = (idx // cols) * 16
            tile_rgba = self.glyphs[gid]["rgba"]

            for ty in range(16):
                dest_start = ((gy + ty) * img_w + gx) * 4
                src_start = ty * 16 * 4
                canvas[dest_start:dest_start + 64] = tile_rgba[src_start:src_start + 64]

        return img_w, img_h, bytes(canvas)

    def encode_to_png(self, data: bytes, passphrase: str, output_png_path, layout_mode: str = "scroll_32") -> dict:
        """High-level Developer API: Encrypts bytes directly to a stitched Glyph Scroll PNG."""
        packet = self.encrypt_payload_with_options(data, passphrase, layout_mode=layout_mode)
        w, h, rgba = self.render_sequence_to_rgba(packet["sequence"], packet["grid_cols"], packet["grid_rows"])
        PurePNG.write_rgba(output_png_path, w, h, rgba)
        return packet

    def encrypt_payload_with_options(self, data: bytes, passphrase: str, layout_mode: str = "scroll_32") -> dict:
        return self.encrypt_bytes(
            data,
            passphrase,
            chaff_interval=7,
            rotor_interval=16,
            layout_mode=layout_mode,
            for_png_output=True
        )

    def decode_from_png(self, input_png_path, passphrase: str, strict_pixel_check: bool = True) -> bytes:
        """
        Optical Scanner: Inspects the PNG header first (refusing >4096x4096 images),
        validates and decompresses PNG image data under configured limits to recover 16x16 tiles,
        verifies exact decoded 16x16 RGBA tile pixels against the loaded glyph library in default
        strict mode (strict_pixel_check=True), and authenticates the frame and payload before
        message-payload decompression occurs.
        """
        self._validate_passphrase(passphrase)
        w, h, _, _ = PurePNG.inspect_png_header(input_png_path)
        if w % 16 != 0 or h % 16 != 0:
            raise ValueError(f"Image dimensions ({w}×{h} px) are not a multiple of 16×16 glyph tiles.")

        w, h, rgba = PurePNG.read_rgba(input_png_path)
        cols = w // 16
        rows = h // 16
        sequence = []

        for r in range(rows):
            for c in range(cols):
                tile = bytearray(16 * 16 * 4)
                for ty in range(16):
                    src_start = ((r * 16 + ty) * w + (c * 16)) * 4
                    tile[ty * 64:(ty + 1) * 64] = rgba[src_start:src_start + 64]

                tile_bytes = bytes(tile)
                if strict_pixel_check:
                    gid = self.exact_rgba_to_id.get(tile_bytes)
                    if gid is None:
                        fuzzy_gid = self.hash_to_id.get(self._normalize_tile_signature(tile_bytes))
                        if fuzzy_gid is not None:
                            g_name = self.glyphs[fuzzy_gid]["name"]
                            raise ValueError(
                                f"SINGLE-PIXEL TAMPER DETECTED at Row {r}, Col {c} (Tile #{len(sequence)}):\n"
                                f"Tile visually resembles glyph '{g_name}.png' (#{fuzzy_gid:04d}), "
                                f"but one or more pixel RGBA values were modified!"
                            )
                        raise ValueError(
                            f"Unrecognized or modified 16×16 glyph tile at Row {r}, Col {c} (Tile #{len(sequence)})."
                        )
                else:
                    sig = self._normalize_tile_signature(tile_bytes)
                    gid = self.hash_to_id.get(sig)
                    if gid is None:
                        src_label = "<memory>" if isinstance(input_png_path, (bytes, bytearray)) else Path(input_png_path).name
                        raise ValueError(
                            f"Unrecognized 16×16 glyph tile at Row {r}, Col {c} in '{src_label}'."
                        )
                sequence.append(gid)

        return self.decrypt_sequence(sequence, passphrase, expected_grid=(cols, rows), require_png_flag=True)


# =============================================================================
# 4. INTERACTIVE TKINTER DESKTOP WORKBENCH GUI
# =============================================================================

def prompt_for_legend(engine: "CipherEngine1024", parent=None) -> bool:
    """
    First-run Legend setup for the GUI. Never creates a Legend silently.
    Returns True once a Legend is loaded, or False if the user chooses to exit.
    """
    while engine.legend is None:
        choice = messagebox.askyesnocancel(
            "Legend Keyfile Required",
            f"No Legend keyfile was found at:\n{engine.legend_path}\n\n"
            "The Legend is one of your two secrets: everything you encrypt needs BOTH this Legend file "
            "AND your passphrase to decrypt.\n\n"
            "Yes  —  Create a brand-new Legend here\n"
            "No  —  Locate an existing Legend keyfile\n"
            "Cancel  —  Exit without making any changes",
            parent=parent,
        )
        if choice is None:
            return False
        if choice:
            engine.generate_new_legend(engine.legend_path)
            messagebox.showwarning(
                "Back Up Your New Legend",
                f"A new Legend keyfile was created at:\n{engine.legend_path}\n\n"
                "Back this file up somewhere safe now. If it is lost, deleted, or replaced, anything encrypted "
                "with it can NEVER be recovered — even with the correct passphrase.\n\n"
                "Never share it publicly or include it in a release.",
                parent=parent,
            )
        else:
            path = filedialog.askopenfilename(
                title="Select Existing .legend.json Keyfile",
                filetypes=[("Legend Keyfile", "*.json")],
                parent=parent,
            )
            if not path:
                continue
            try:
                engine.load_legend(path)
            except Exception as e:
                messagebox.showerror("Invalid Legend File", str(e), parent=parent)
    return True


class CipherWorkbenchApp:
    ROLE_COLORS = {
        "NONCE_HEADER":    "#38bdf8",  # Cyan
        "DATA_GLYPH":      "#6366f1",  # Indigo
        "AUTH_MAC_BYTE":   "#14b8a6",  # Teal
        "POLY_NULL_CHAFF": "#f59e0b",  # Amber
        "ROTOR_MUTATOR":   "#d946ef",  # Magenta
        "TAMPER_CHECKSUM": "#10b981",  # Emerald
        "EOF_SIGIL":       "#ef4444",  # Red
        "GRID_PAD_CHAFF":  "#64748b",  # Slate
    }

    def __init__(self, root, engine: Optional[CipherEngine1024] = None, root_dir=None):
        self.root = root
        self.root.title("CIPHER ENGINE 1024 v2 — Visual Cryptographic Workbench")
        self.root.geometry("1340x860")
        self.root.configure(bg="#0d0f14")

        self.engine = engine if engine is not None else CipherEngine1024(root_dir=root_dir, auto_create_legend=False)
        if self.engine.legend is None and not prompt_for_legend(self.engine, self.root):
            raise SystemExit(0)

        self.current_packet = None
        self.scroll_photo = None
        self.zoom_scale = 2
        self.effective_zoom = 2
        self._last_hover_idx = None
        self.codenames_truncated = False
        self._codenames_preview_snapshot = None
        self.show_xray = tk.BooleanVar(value=True)

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        # No automatic encryption at startup: the passphrase field is empty until the user fills it
        self.lbl_telemetry.config(
            text="Enter a passphrase (or click 🎲 New Pass and save it), then click ⚡ Encrypt to build a glyph scroll."
        )

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#0d0f14", foreground="#f3f4f6", fieldbackground="#11131a")
        style.configure("TNotebook", background="#0d0f14", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#161922",
            foreground="#9ca3af",
            padding=[14, 8],
            font=("Segoe UI", 10, "bold")
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#6366f1")],
            foreground=[("selected", "#ffffff")]
        )

    def _build_header(self):
        hdr = tk.Frame(self.root, bg="#161922", padx=16, pady=10, highlightthickness=1, highlightbackground="#282d3e")
        hdr.pack(fill=tk.X, padx=12, pady=(10, 4))

        left = tk.Frame(hdr, bg="#161922")
        left.pack(side=tk.LEFT)
        tk.Label(
            left,
            text="CIPHER ENGINE 1024 — Visual Cryptographic Studio & Workbench",
            font=("Segoe UI", 14, "bold"),
            fg="#f8fafc",
            bg="#161922"
        ).pack(anchor=tk.W)

        self.lbl_status = tk.Label(
            left,
            text=(
                f"✓ Folder Glyphs Loaded: {self.engine.disk_loaded_count}/1,024 White PNGs • "
                f"Safety Guard: Max {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px • "
                f"Active Legend: {self.engine.legend_path.name}"
            ),
            font=("Consolas", 9),
            fg="#6ee7b7",
            bg="#161922"
        )
        self.lbl_status.pack(anchor=tk.W)

        right = tk.Frame(hdr, bg="#161922")
        right.pack(side=tk.RIGHT)
        tk.Label(right, text="Passphrase:", font=("Segoe UI", 9, "bold"), fg="#cbd5e1", bg="#161922").pack(side=tk.LEFT, padx=(0, 6))
        self.ent_pass = tk.Entry(right, show="•", width=28, font=("Consolas", 10), bg="#0d0f14", fg="#f8fafc", insertbackground="#fff", relief=tk.FLAT, highlightthickness=1, highlightbackground="#383f54")
        self.ent_pass.pack(side=tk.LEFT, ipady=4, padx=(0, 6))
        # Intentionally starts EMPTY: never pre-fill a hidden passphrase the user has not seen or saved

        self.show_pass = False
        self.btn_eye = tk.Button(right, text="Show", bg="#222634", fg="#e5e7eb", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=8, pady=3, command=self._toggle_pass)
        self.btn_eye.pack(side=tk.LEFT, padx=(0, 4))
        self.btn_rand_pass = tk.Button(right, text="🎲 New Pass", bg="#3730a3", fg="#e0e7ff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=8, pady=3, command=self._randomize_pass)
        self.btn_rand_pass.pack(side=tk.LEFT)

    def _toggle_pass(self):
        self.show_pass = not self.show_pass
        self.ent_pass.config(show="" if self.show_pass else "•")
        self.btn_eye.config(text="Hide" if self.show_pass else "Show")

    def _randomize_pass(self):
        if self.ent_pass.get().strip() and not messagebox.askyesno(
            "Replace Current Passphrase?",
            "This replaces the passphrase currently in the field.\n\n"
            "Anything you already encrypted still needs the OLD passphrase to decrypt. Continue?"
        ):
            return
        new_pwd = self.engine.generate_random_passphrase()
        self.ent_pass.delete(0, tk.END)
        self.ent_pass.insert(0, new_pwd)
        # Always reveal a generated passphrase so the user can actually see and save it
        self.show_pass = True
        self.ent_pass.config(show="")
        self.btn_eye.config(text="Hide")
        messagebox.showwarning(
            "Save This Passphrase Now",
            f"Your new random passphrase is:\n\n{new_pwd}\n\n"
            "Write it down or store it in a password manager BEFORE encrypting anything.\n"
            "It is never saved by this app — if you lose it, files encrypted with it cannot be recovered."
        )
        self._maybe_reencrypt()

    def _maybe_reencrypt(self):
        """Refreshes the Tab 1 preview only when a passphrase is present (never prompts on its own)."""
        if self.ent_pass.get().strip():
            self.encrypt_text_action()

    def _get_validated_passphrase(self) -> Optional[str]:
        pwd = self.ent_pass.get()
        if not isinstance(pwd, str) or not pwd.strip():
            messagebox.showwarning(
                "Missing Passphrase",
                "Please enter a passphrase in the top bar (or click 🎲 New Pass to generate one you can save)."
            )
            return None
        return pwd

    @staticmethod
    def _read_tk_text_exact(widget) -> str:
        """Reads text from a Tkinter Text widget while removing only Tk's single sentinel trailing newline."""
        raw_text = widget.get("1.0", tk.END)
        return raw_text[:-1] if raw_text.endswith("\n") else raw_text

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        self.tab_studio = tk.Frame(self.notebook, bg="#0d0f14")
        self.tab_files = tk.Frame(self.notebook, bg="#0d0f14")
        self.tab_legend = tk.Frame(self.notebook, bg="#0d0f14")

        self.notebook.add(self.tab_studio, text=" 1. Visual Text & Code Cipher Studio (X-Ray Telemetry) ")
        self.notebook.add(self.tab_files,  text=" 2. Binary File Vault (.PNG Scroll / .CIPH) ")
        self.notebook.add(self.tab_legend, text=" 3. Two-Factor Legend Keyfile & Safety Guardrails ")

        self._build_tab1_studio()
        self._build_tab2_files()
        self._build_tab3_legend()

    # -------------------------------------------------------------------------
    # TAB 1: VISUAL TEXT & CODE CIPHER STUDIO + X-RAY TELEMETRY
    # -------------------------------------------------------------------------

    def _build_tab1_studio(self):
        pane = tk.Frame(self.tab_studio, bg="#0d0f14")
        pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        pane.columnconfigure(0, weight=5, uniform="studio_split")
        pane.columnconfigure(1, weight=7, uniform="studio_split")
        pane.rowconfigure(0, weight=1)

        left = tk.Frame(pane, bg="#161922", padx=14, pady=12, highlightthickness=1, highlightbackground="#282d3e")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.pack_propagate(False)

        tk.Label(
            left,
            text=f"1. Plaintext / Source Code Input (Max {SafetyConfig.MAX_TEXT_INPUT_CHARS:,} chars)",
            font=("Segoe UI", 10, "bold"),
            fg="#f8fafc",
            bg="#161922"
        ).pack(anchor=tk.W)
        self.txt_plain = tk.Text(left, height=7, font=("Consolas", 10), bg="#0d0f14", fg="#f3f4f6", insertbackground="#fff", relief=tk.FLAT, highlightthickness=1, highlightbackground="#2e3446", wrap=tk.WORD)
        self.txt_plain.pack(fill=tk.X, pady=(4, 10))
        self.txt_plain.insert(
            "1.0",
            "KERNEL_INIT(0x7F00): Authenticate Root Vault!\n"
            "Passcode: #9942-Alpha @ 2FA-Verified [OK]"
        )

        opts = tk.Frame(left, bg="#161922")
        opts.pack(fill=tk.X, pady=(0, 8))

        tk.Label(opts, text="PNG Layout:", font=("Segoe UI", 9, "bold"), fg="#9ca3af", bg="#161922").grid(row=0, column=0, sticky=tk.W)
        self.cmb_layout = ttk.Combobox(opts, state="readonly", width=18, values=["scroll_32", "scroll_16", "square_block", "strip_horizontal"])
        self.cmb_layout.current(1)
        self.cmb_layout.grid(row=0, column=1, padx=(6, 14), pady=2)

        tk.Label(opts, text="Chaff Rate:", font=("Segoe UI", 9, "bold"), fg="#9ca3af", bg="#161922").grid(row=0, column=2, sticky=tk.W)
        self.cmb_chaff = ttk.Combobox(opts, state="readonly", width=15, values=["Every 5 Bytes (High)", "Every 7 Bytes (Med)", "Every 11 Bytes (Low)"])
        self.cmb_chaff.current(1)
        self.cmb_chaff.grid(row=0, column=3, padx=(6, 0), pady=2)

        btns1 = tk.Frame(left, bg="#161922")
        btns1.pack(fill=tk.X, pady=4)
        tk.Button(btns1, text="⚡ Encrypt → Visual Glyph Scroll", bg="#6366f1", fg="#fff", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=10, pady=6, command=self.encrypt_text_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        tk.Button(btns1, text="🔓 Decrypt Active Stream", bg="#10b981", fg="#fff", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=10, pady=6, command=self.decrypt_active_stream_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        btns2 = tk.Frame(left, bg="#161922")
        btns2.pack(fill=tk.X, pady=4)
        tk.Button(btns2, text="💾 Export Encrypted Scroll (.PNG)", bg="#f59e0b", fg="#111318", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=10, pady=6, command=self.export_scroll_png_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        tk.Button(btns2, text="📷 Import & Decode Scroll (.PNG)", bg="#222634", fg="#f3f4f6", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=10, pady=6, command=self.import_scroll_png_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        btns3 = tk.Frame(left, bg="#161922")
        btns3.pack(fill=tk.X, pady=(4, 10))
        tk.Button(btns3, text="🧪 Tamper Test (Corrupt 1 Tile)", bg="#be123c", fg="#fff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=8, pady=5, command=self.tamper_test_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        tk.Button(btns3, text="🌊 Avalanche Test (Flip 1 Char)", bg="#3730a3", fg="#e0e7ff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=8, pady=5, command=self.avalanche_test_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        tk.Label(left, text="2. Pronounceable 4-Letter Codename Stream (Copy/Pasteable):", font=("Segoe UI", 9, "bold"), fg="#cbd5e1", bg="#161922").pack(anchor=tk.W)
        self.txt_codenames = tk.Text(left, height=7, font=("Consolas", 9), bg="#0d0f14", fg="#a5b4fc", insertbackground="#fff", relief=tk.FLAT, highlightthickness=1, highlightbackground="#2e3446", wrap=tk.WORD)
        self.txt_codenames.pack(fill=tk.BOTH, expand=True, pady=(4, 6))

        cname_btns = tk.Frame(left, bg="#161922")
        cname_btns.pack(fill=tk.X)
        tk.Button(cname_btns, text="🔓 Decode From Edited Codename String Above", bg="#222634", fg="#e5e7eb", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, pady=4, command=self.decode_from_codenames_action).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        tk.Button(cname_btns, text="📋 Copy Full Stream", bg="#3730a3", fg="#e0e7ff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=8, pady=4, command=self.copy_full_codenames_action).pack(side=tk.RIGHT)

        right = tk.Frame(pane, bg="#161922", padx=14, pady=12, highlightthickness=1, highlightbackground="#282d3e")
        right.grid(row=0, column=1, sticky="nsew")
        right.pack_propagate(False)

        r_top = tk.Frame(right, bg="#161922")
        r_top.pack(fill=tk.X)
        tk.Label(r_top, text="Visual Encrypted Glyph Scroll (Hover Any Tile for X-Ray Telemetry)", font=("Segoe UI", 10, "bold"), fg="#f8fafc", bg="#161922").pack(side=tk.LEFT)

        tk.Checkbutton(
            r_top,
            text="X-Ray Role Borders",
            variable=self.show_xray,
            bg="#161922",
            fg="#fde68a",
            selectcolor="#0d0f14",
            activebackground="#161922",
            font=("Segoe UI", 9, "bold"),
            command=self._redraw_scroll_canvas
        ).pack(side=tk.RIGHT, padx=6)

        tk.Button(r_top, text="Zoom +", bg="#222634", fg="#fff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=6, command=lambda: self._set_zoom(1)).pack(side=tk.RIGHT, padx=2)
        tk.Button(r_top, text="Zoom -", bg="#222634", fg="#fff", font=("Segoe UI", 8, "bold"), relief=tk.FLAT, padx=6, command=lambda: self._set_zoom(-1)).pack(side=tk.RIGHT, padx=2)

        legend_bar = tk.Frame(right, bg="#11131a", pady=5, padx=8)
        legend_bar.pack(fill=tk.X, pady=(6, 6))
        for label, col in [
            ("Nonce (16)", "#38bdf8"),
            ("Data Homophone", "#6366f1"),
            ("Key-Driven Chaff", "#f59e0b"),
            ("Rotor Mutator", "#d946ef"),
            ("256-b HMAC & Seal", "#10b981"),
            ("Session EOF", "#ef4444"),
            ("Auth Grid Pad", "#64748b")
        ]:
            tk.Label(legend_bar, text="■", fg=col, bg="#11131a", font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=(6, 2))
            tk.Label(legend_bar, text=label, fg="#cbd5e1", bg="#11131a", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 6))

        c_wrap = tk.Frame(right, bg="#0d0f14", highlightthickness=1, highlightbackground="#282d3e")
        c_wrap.pack(fill=tk.BOTH, expand=True)

        self.v_scroll = ttk.Scrollbar(c_wrap, orient=tk.VERTICAL)
        self.h_scroll = ttk.Scrollbar(c_wrap, orient=tk.HORIZONTAL)
        self.scroll_canvas = tk.Canvas(
            c_wrap,
            bg="#0d0f14",
            highlightthickness=0,
            yscrollcommand=self.v_scroll.set,
            xscrollcommand=self.h_scroll.set
        )
        self.v_scroll.config(command=self.scroll_canvas.yview)
        self.h_scroll.config(command=self.scroll_canvas.xview)

        self.v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.scroll_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scroll_canvas.bind("<Motion>", self._on_canvas_hover)

        self.lbl_telemetry = tk.Label(
            right,
            text="Hover over any 16×16 glyph in the scroll above to inspect its cryptographic telemetry...",
            font=("Consolas", 9),
            fg="#6ee7b7",
            bg="#11131a",
            width=1,
            height=1,
            anchor=tk.W,
            padx=10,
            pady=8
        )
        self.lbl_telemetry.pack(fill=tk.X, pady=(8, 0))

    def _set_zoom(self, delta: int):
        self.zoom_scale = max(1, min(4, self.zoom_scale + delta))
        self._redraw_scroll_canvas()

    def encrypt_text_action(self) -> bool:
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return False
        text = self._read_tk_text_exact(self.txt_plain)
        if not text:
            messagebox.showwarning("Empty Input", "Please enter some text or code to encrypt.")
            return False

        raw_bytes = text.encode("utf-8")
        if SafetyConfig.ENABLE_SAFETY_GUARDS:
            if len(text) > SafetyConfig.MAX_TEXT_INPUT_CHARS or len(raw_bytes) > SafetyConfig.MAX_FILE_BYTES_FOR_PNG:
                messagebox.showerror(
                    "Safety Guardrail Refusal",
                    f"Text input is {len(text):,} chars ({len(raw_bytes):,} UTF-8 bytes), which exceeds "
                    f"the safe text studio limit of {SafetyConfig.MAX_TEXT_INPUT_CHARS:,} chars / "
                    f"{SafetyConfig.MAX_FILE_BYTES_FOR_PNG // 1024} KB."
                )
                return False

        layout = self.cmb_layout.get()
        chaff_idx = self.cmb_chaff.current()
        chaff_rate = [5, 7, 11][chaff_idx if chaff_idx >= 0 else 1]

        try:
            self.current_packet = self.engine.encrypt_bytes(
                raw_bytes,
                pwd,
                chaff_interval=chaff_rate,
                rotor_interval=16,
                layout_mode=layout,
                for_png_output=True
            )
        except SafetyLimitExceeded as e:
            messagebox.showerror("Safety Guardrail Triggered", str(e))
            return False
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return False

        self.txt_codenames.delete("1.0", tk.END)
        cnames = self.current_packet["codenames"]
        if len(cnames) > 25000:
            preview_str = cnames[:25000] + "\n... [Display truncated for GUI speed; full stream in memory]"
            self._codenames_preview_snapshot = preview_str
            self.codenames_truncated = True
            self.txt_codenames.insert("1.0", preview_str)
        else:
            self._codenames_preview_snapshot = None
            self.codenames_truncated = False
            self.txt_codenames.insert("1.0", cnames)

        self._redraw_scroll_canvas()
        self._refresh_sbox_preview()

        seq_len = len(self.current_packet["sequence"])
        cols = self.current_packet["grid_cols"]
        rows = self.current_packet["grid_rows"]
        self._last_hover_idx = None
        self.lbl_telemetry.config(
            text=(
                f"✓ Encrypted {len(text):,} chars → {seq_len:,} Glyphs "
                f"({cols}×{rows} Grid = {cols*16}×{rows*16} px • 128-Bit Nonce + 256-Bit HMAC + 32-Bit Seal)."
            )
        )
        return True

    def _redraw_scroll_canvas(self):
        if not self.current_packet:
            return
        cols = self.current_packet["grid_cols"]
        rows = self.current_packet["grid_rows"]
        seq = self.current_packet["sequence"]

        w, h, rgba = self.engine.render_sequence_to_rgba(seq, cols, rows)
        png_bytes = PurePNG.encode_rgba_bytes(w, h, rgba)
        base_photo = tk.PhotoImage(data=base64.b64encode(png_bytes).decode("ascii"))

        # Clamp zoom scale if zoomed image would exceed MAX_TK_PREVIEW_DIM_PX
        eff_zoom = self.zoom_scale
        while eff_zoom > 1 and (w * eff_zoom > SafetyConfig.MAX_TK_PREVIEW_DIM_PX or h * eff_zoom > SafetyConfig.MAX_TK_PREVIEW_DIM_PX):
            eff_zoom -= 1
        self.effective_zoom = eff_zoom

        if eff_zoom > 1:
            base_photo = base_photo.zoom(eff_zoom, eff_zoom)
        self.scroll_photo = base_photo

        self.scroll_canvas.delete("all")
        pad = 16
        self.scroll_canvas.create_image(pad, pad, anchor=tk.NW, image=self.scroll_photo)

        tile_px = 16 * eff_zoom
        if self.show_xray.get() and len(seq) <= SafetyConfig.MAX_XRAY_RECT_OVERLAYS:
            for item in self.current_packet["telemetry"]:
                idx = item["pos"]
                gx = pad + (idx % cols) * tile_px
                gy = pad + (idx // cols) * tile_px
                color = self.ROLE_COLORS.get(item["type"], "#6366f1")
                self.scroll_canvas.create_rectangle(
                    gx, gy, gx + tile_px - 1, gy + tile_px - 1,
                    outline=color, width=1
                )

        total_w = pad * 2 + cols * tile_px
        total_h = pad * 2 + rows * tile_px
        self.scroll_canvas.config(scrollregion=(0, 0, total_w, total_h))

    def _on_canvas_hover(self, event):
        if not self.current_packet:
            return
        cx = self.scroll_canvas.canvasx(event.x) - 16
        cy = self.scroll_canvas.canvasy(event.y) - 16
        tile_px = 16 * self.effective_zoom
        cols = self.current_packet["grid_cols"]
        rows = self.current_packet["grid_rows"]

        col = int(cx // tile_px)
        row = int(cy // tile_px)
        if 0 <= col < cols and 0 <= row < rows:
            idx = row * cols + col
            if getattr(self, "_last_hover_idx", None) == idx:
                return
            telem = self.current_packet["telemetry"]
            if idx < len(telem):
                self._last_hover_idx = idx
                t = telem[idx]
                self.lbl_telemetry.config(
                    text=(
                        f"[Tile #{idx:03d} at ({col},{row})]  File: {t['codename']}.png (#{t['glyph_id']:04d} • {t['family']})  |  "
                        f"Role: {t['type']}  |  {t['detail']}"
                    )
                )

    def decrypt_active_stream_action(self):
        if not self.current_packet:
            return
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        try:
            plain_bytes = self.engine.decrypt_sequence(self.current_packet["sequence"], pwd)
            recovered = plain_bytes.decode("utf-8", errors="replace")
            self.txt_plain.delete("1.0", tk.END)
            self.txt_plain.insert("1.0", recovered)
            messagebox.showinfo(
                "Cryptographic Verification Passed",
                f"✓ 8/8 Visual Checksum Seals (32-Bit) Verified\n"
                f"✓ Full 256-Bit HMAC-SHA256 Ciphertext Tag Verified (before decryption)\n"
                f"✓ Post-EOF Grid Padding & Chaff Schedule Verified\n\n"
                f"Recovered {len(plain_bytes):,} bytes 100% intact."
            )
        except Exception as e:
            messagebox.showerror("Cryptographic Authentication Failed", str(e))

    def copy_full_codenames_action(self):
        if not self.current_packet or not self.current_packet.get("codenames"):
            return
        full_str = self.current_packet["codenames"]
        if hasattr(self, "root") and self.root is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append(full_str)
        messagebox.showinfo(
            "Copied Full Codename Stream",
            f"Copied all {len(self.current_packet['sequence']):,} glyph codenames ({len(full_str):,} chars) to the clipboard."
        )

    def decode_from_codenames_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        raw_str = self._read_tk_text_exact(self.txt_codenames).strip()
        if not raw_str:
            return
        preview_snap = getattr(self, "_codenames_preview_snapshot", None)
        if (
            self.current_packet
            and isinstance(self.current_packet.get("codenames"), str)
            and self.current_packet["codenames"]
            and preview_snap is not None
            and raw_str == preview_snap.strip()
        ):
            raw_str = self.current_packet["codenames"]
        elif "[Display truncated" in raw_str or "..." in raw_str:
            messagebox.showerror(
                "Truncated Codename Preview",
                "The codename preview was truncated at 25,000 characters for GUI speed and cannot be partially edited in-place.\n\n"
                "Use 'Decrypt Active Stream' or click 'Copy Full Stream' to work with the complete codename sequence."
            )
            return
        names = [t.strip().lower() for t in raw_str.replace("\n", "-").split("-") if t.strip()]
        try:
            seq = []
            for n in names:
                if n not in self.engine.name_to_id:
                    raise ValueError(f"Unknown 4-letter glyph codename: '{n}'")
                seq.append(self.engine.name_to_id[n])
            plain_bytes = self.engine.decrypt_sequence(seq, pwd)
            self.txt_plain.delete("1.0", tk.END)
            self.txt_plain.insert("1.0", plain_bytes.decode("utf-8", errors="replace"))
            messagebox.showinfo("Codename Stream Decoded", f"Successfully decrypted {len(plain_bytes):,} bytes from {len(seq):,} codenames!")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def export_scroll_png_action(self):
        if not self.encrypt_text_action():
            return
        path = filedialog.asksaveasfilename(
            title="Save Encrypted Visual Glyph Scroll PNG",
            defaultextension=".png",
            initialfile="encrypted_scroll.png",
            filetypes=[("PNG Image", "*.png")]
        )
        if not path:
            return
        try:
            cols = self.current_packet["grid_cols"]
            rows = self.current_packet["grid_rows"]
            w, h, rgba = self.engine.render_sequence_to_rgba(self.current_packet["sequence"], cols, rows)
            PurePNG.write_rgba(path, w, h, rgba)
            messagebox.showinfo(
                "Encrypted PNG Scroll Saved",
                f"Saved {w}×{h} px ({cols}×{rows} glyphs) visual ciphertext scroll to:\n{path}\n\n"
                f"Anyone with this PNG + {self.engine.legend_path.name} + your Passphrase can optically decode it."
            )
        except SafetyLimitExceeded as e:
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def import_scroll_png_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        path = filedialog.askopenfilename(
            title="Select Encrypted Glyph Scroll PNG to Optically Decode",
            filetypes=[("PNG Image", "*.png")]
        )
        if not path:
            return
        try:
            plain_bytes = self.engine.decode_from_png(path, pwd)
            text = plain_bytes.decode("utf-8", errors="replace")
            self.txt_plain.delete("1.0", tk.END)
            self.txt_plain.insert("1.0", text)
            messagebox.showinfo(
                "Optical PNG Decryption Succeeded",
                f"✓ Exact 16×16 RGBA Single-Pixel Verification Passed\n"
                f"✓ Verified PNG Geometry, 32-Bit Seal & 256-Bit HMAC-SHA256\n"
                f"✓ Recovered {len(plain_bytes):,} plaintext bytes!"
            )
        except SafetyLimitExceeded as e:
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("Optical PNG Decryption Failed", str(e))

    def tamper_test_action(self):
        if not self.current_packet or len(self.current_packet["sequence"]) < 20:
            return
        target_pos = min(18, len(self.current_packet["sequence"]) - 10)
        old_gid = self.current_packet["sequence"][target_pos]
        new_gid = (old_gid + 1) % 1024
        self.current_packet["sequence"][target_pos] = new_gid
        if target_pos < len(self.current_packet["telemetry"]):
            self.current_packet["telemetry"][target_pos]["type"] = "EOF_SIGIL"
            self.current_packet["telemetry"][target_pos]["detail"] = (
                f"TAMPERED TILE! Changed #{old_gid:04d} ({self.engine.glyphs[old_gid]['name']}) → #{new_gid:04d} ({self.engine.glyphs[new_gid]['name']})"
            )
        self._redraw_scroll_canvas()
        self._last_hover_idx = None
        self.lbl_telemetry.config(
            text=f"⚠ TAMPER INJECTED at Tile #{target_pos}! Now click 'Decrypt Active Stream' to verify authentication rejection."
        )

    def avalanche_test_action(self):
        old_seq = list(self.current_packet["sequence"]) if self.current_packet else []
        cur_text = self._read_tk_text_exact(self.txt_plain)
        if not cur_text:
            return
        flipped_first = chr(((ord(cur_text[0]) - 32 + 1) % 90) + 32)
        new_text = flipped_first + cur_text[1:]
        self.txt_plain.delete("1.0", tk.END)
        self.txt_plain.insert("1.0", new_text)
        if not self.encrypt_text_action():
            return
        new_seq = self.current_packet["sequence"]

        if old_seq:
            n = min(len(old_seq), len(new_seq))
            changed = sum(1 for i in range(n) if old_seq[i] != new_seq[i])
            pct = (changed / max(1, n)) * 100.0
            self._last_hover_idx = None
            self.lbl_telemetry.config(
                text=(
                    f"🌊 Per-Message Nonce + 1-Char Edit: {changed}/{n} glyphs ({pct:.1f}%) changed "
                    f"(fresh 128-bit session nonce re-permutes all 1,024 role pools)."
                )
            )

    # -------------------------------------------------------------------------
    # TAB 2: BINARY FILE VAULT (.PNG SCROLL OR .CIPH PACKET)
    # -------------------------------------------------------------------------

    def _build_tab2_files(self):
        wrap = tk.Frame(self.tab_files, bg="#161922", padx=24, pady=24, highlightthickness=1, highlightbackground="#282d3e")
        wrap.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        tk.Label(wrap, text="Binary File Encryption & Optical PNG Vault (With Pre-Flight Safety Guards)", font=("Segoe UI", 14, "bold"), fg="#f8fafc", bg="#161922").pack(anchor=tk.W)
        tk.Label(
            wrap,
            text=(
                f"• Visual PNG Matrix Limit: Up to {SafetyConfig.MAX_FILE_BYTES_FOR_PNG // 1024} KB raw input / "
                f"{SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px max output canvas (blocks video/audio/large archives).\n"
                f"• Compact .CIPH Vault Limit: Up to {SafetyConfig.MAX_FILE_BYTES_FOR_CIPH // 1024} KB raw input "
                f"({SafetyConfig.MAX_CIPH_GLYPHS:,} max glyphs; developers can customize limits in SafetyConfig)."
            ),
            font=("Segoe UI", 9),
            fg="#9ca3af",
            bg="#161922",
            justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(6, 18))

        btn_grid = tk.Frame(wrap, bg="#161922")
        btn_grid.pack(fill=tk.X, pady=8)

        tk.Button(
            btn_grid,
            text=f"1. Encrypt File → Visual Glyph Matrix .PNG (Max {SafetyConfig.MAX_FILE_BYTES_FOR_PNG // 1024} KB)",
            bg="#6366f1",
            fg="#fff",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=12,
            command=self.encrypt_file_to_png_action
        ).grid(row=0, column=0, padx=(0, 10), pady=6, sticky="ew")

        tk.Button(
            btn_grid,
            text="2. Optically Decode Glyph Matrix (.PNG) → Original File",
            bg="#10b981",
            fg="#fff",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=12,
            command=self.decrypt_file_from_png_action
        ).grid(row=0, column=1, padx=(10, 0), pady=6, sticky="ew")

        tk.Button(
            btn_grid,
            text=f"3. Encrypt File → Compact Vault .CIPH (Max {SafetyConfig.MAX_FILE_BYTES_FOR_CIPH // 1024} KB)",
            bg="#f59e0b",
            fg="#111318",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=12,
            command=self.encrypt_file_to_ciph_action
        ).grid(row=1, column=0, padx=(0, 10), pady=6, sticky="ew")

        tk.Button(
            btn_grid,
            text="4. Decrypt Compact Vault (.CIPH) → Original File",
            bg="#222634",
            fg="#f3f4f6",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=12,
            command=self.decrypt_file_from_ciph_action
        ).grid(row=1, column=1, padx=(10, 0), pady=6, sticky="ew")

        btn_grid.columnconfigure(0, weight=1)
        btn_grid.columnconfigure(1, weight=1)

        self.txt_file_log = tk.Text(wrap, height=14, font=("Consolas", 10), bg="#0d0f14", fg="#6ee7b7", relief=tk.FLAT, highlightthickness=1, highlightbackground="#282d3e")
        self.txt_file_log.pack(fill=tk.BOTH, expand=True, pady=(16, 0))
        self.txt_file_log.insert(
            "1.0",
            "Ready for Binary File Operations (Pre-Flight Safety Guards Active).\n"
            f"• Max Output PNG Canvas : {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px ({SafetyConfig.MAX_PNG_TILES:,} glyph tiles)\n"
            f"• Max .CIPH Stream Size : {SafetyConfig.MAX_CIPH_GLYPHS:,} glyphs ({SafetyConfig.MAX_FILE_BYTES_FOR_CIPH // 1024} KB raw input)\n"
            f"• Blocked Media Formats : {', '.join(sorted(list(SafetyConfig.BLOCKED_PNG_MEDIA_EXTENSIONS))[:12])} ...\n"
        )

    def _log_file(self, msg: str):
        self.txt_file_log.insert(tk.END, msg + "\n")
        self.txt_file_log.see(tk.END)

    def encrypt_file_to_png_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        in_path = filedialog.askopenfilename(title="Select File to Encrypt into a Visual Glyph PNG")
        if not in_path:
            return
        try:
            # 1. Pre-flight check BEFORE reading the file into memory!
            self.engine.validate_file_before_encryption(in_path, for_png_output=True)
            raw = Path(in_path).read_bytes()
            envelope = self.engine.pack_file_envelope(Path(in_path).name, raw)

            # 2. Encrypt in memory first to verify exact resulting PNG dimensions <= 4096x4096
            pkt = self.engine.encrypt_payload_with_options(envelope, pwd, layout_mode="square_block")
            out_w = pkt["grid_cols"] * 16
            out_h = pkt["grid_rows"] * 16

            out_path = filedialog.asksaveasfilename(
                title=f"Save {out_w}×{out_h} px Encrypted Glyph PNG As",
                defaultextension=".png",
                initialfile=f"{Path(in_path).name}.glyphs.png",
                filetypes=[("PNG Image", "*.png")]
            )
            if not out_path:
                return

            w, h, rgba = self.engine.render_sequence_to_rgba(pkt["sequence"], pkt["grid_cols"], pkt["grid_rows"])
            PurePNG.write_rgba(out_path, w, h, rgba)

            self._log_file(
                f"[ENCRYPT → PNG] '{Path(in_path).name}' ({len(raw):,} bytes) → "
                f"{pkt['grid_cols']}×{pkt['grid_rows']} Square Glyph Matrix ({w}×{h} px) saved to {out_path}"
            )
            messagebox.showinfo(
                "File Encrypted to PNG",
                f"Saved {w}×{h} px ({len(pkt['sequence']):,} tiles) optical glyph matrix PNG:\n{out_path}"
            )
        except SafetyLimitExceeded as e:
            self._log_file(f"[SAFETY REFUSAL] {Path(in_path).name}: {str(e).splitlines()[0]}")
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_file_from_png_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        in_path = filedialog.askopenfilename(title="Select Encrypted Glyph Matrix .PNG", filetypes=[("PNG Image", "*.png")])
        if not in_path:
            return
        try:
            env_bytes = self.engine.decode_from_png(in_path, pwd)
            safe_filename, raw = self.engine.unpack_file_envelope(env_bytes)

            out_path = filedialog.asksaveasfilename(
                title="Save Restored File As",
                initialfile=safe_filename
            )
            if not out_path:
                return
            Path(out_path).write_bytes(raw)
            self._log_file(f"[DECRYPT ← PNG] Restored '{safe_filename}' ({len(raw):,} bytes, SHA-256 + 256-b HMAC verified) to {out_path}")
            messagebox.showinfo("File Restored", f"Successfully restored '{safe_filename}' ({len(raw):,} bytes)!")
        except SafetyLimitExceeded as e:
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("File Decryption Failed", str(e))

    def encrypt_file_to_ciph_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        in_path = filedialog.askopenfilename(title="Select File to Encrypt into .CIPH Vault")
        if not in_path:
            return
        try:
            self.engine.validate_file_before_encryption(in_path, for_png_output=False)
            raw = Path(in_path).read_bytes()
            envelope = self.engine.pack_file_envelope(Path(in_path).name, raw)

            pkt = self.engine.encrypt_bytes(envelope, pwd, for_png_output=False)
            out_path = filedialog.asksaveasfilename(
                title="Save Encrypted .CIPH Vault As",
                defaultextension=".ciph",
                initialfile=f"{Path(in_path).name}.ciph",
                filetypes=[("Cipher Vault", "*.ciph"), ("All Files", "*.*")]
            )
            if not out_path:
                return
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "schema": pkt["schema"],
                    "protocol_version": pkt["protocol_version"],
                    "legend_id": pkt["legend_id"],
                    "sequence": pkt["sequence"]
                }, f)
            self._log_file(f"[ENCRYPT → .CIPH] '{Path(in_path).name}' ({len(raw):,} bytes) → {len(pkt['sequence']):,} glyphs saved to {out_path}")
            messagebox.showinfo("Saved .CIPH Vault", f"Encrypted file saved to:\n{out_path}")
        except SafetyLimitExceeded as e:
            self._log_file(f"[SAFETY REFUSAL] {Path(in_path).name}: {str(e).splitlines()[0]}")
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_file_from_ciph_action(self):
        pwd = self._get_validated_passphrase()
        if pwd is None:
            return
        in_path = filedialog.askopenfilename(title="Select .CIPH Vault File", filetypes=[("Cipher Vault", "*.ciph"), ("All Files", "*.*")])
        if not in_path:
            return
        try:
            p = Path(in_path)
            if SafetyConfig.ENABLE_SAFETY_GUARDS and p.stat().st_size > SafetyConfig.MAX_IMPORT_PNG_FILE_SIZE:
                raise SafetyLimitExceeded(f"Safety Refusal: .CIPH file '{p.name}' exceeds safe import size limit.")
            with open(p, "r", encoding="utf-8") as f:
                pkt = json.load(f)
            env_bytes = self.engine.decrypt_ciph_packet(pkt, pwd)
            safe_filename, raw = self.engine.unpack_file_envelope(env_bytes)

            out_path = filedialog.asksaveasfilename(title="Save Restored File As", initialfile=safe_filename)
            if not out_path:
                return
            Path(out_path).write_bytes(raw)
            self._log_file(f"[DECRYPT ← .CIPH] Restored '{safe_filename}' ({len(raw):,} bytes) to {out_path}")
            messagebox.showinfo("File Restored", f"Restored '{safe_filename}' ({len(raw):,} bytes)!")
        except SafetyLimitExceeded as e:
            messagebox.showerror("Safety Guardrail Triggered", str(e))
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))

    # -------------------------------------------------------------------------
    # TAB 3: TWO-FACTOR LEGEND KEYFILE MANAGER & SAFETY GUARDRAILS OVERVIEW
    # -------------------------------------------------------------------------

    def _build_tab3_legend(self):
        pane = tk.Frame(self.tab_legend, bg="#161922", padx=20, pady=20, highlightthickness=1, highlightbackground="#282d3e")
        pane.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        top = tk.Frame(pane, bg="#161922")
        top.pack(fill=tk.X, pady=(0, 12))

        tk.Button(
            top,
            text="🎲 Generate Brand-New Randomized .legend.json Keyfile",
            bg="#f59e0b",
            fg="#111318",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            command=self.generate_new_legend_action
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            top,
            text="📂 Load Existing .legend.json Keyfile",
            bg="#6366f1",
            fg="#fff",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            command=self.load_legend_action
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            top,
            text="🛠 Write Any Missing White Glyph PNGs to Disk",
            bg="#222634",
            fg="#e5e7eb",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=8,
            command=self.repair_disk_glyphs_action
        ).pack(side=tk.RIGHT)

        self.txt_legend_info = tk.Text(pane, height=24, font=("Consolas", 10), bg="#0d0f14", fg="#e2e8f0", relief=tk.FLAT, highlightthickness=1, highlightbackground="#282d3e")
        self.txt_legend_info.pack(fill=tk.BOTH, expand=True)
        self._refresh_sbox_preview()

    def _refresh_sbox_preview(self):
        if not hasattr(self, "txt_legend_info"):
            return
        leg = self.engine.legend
        pools = leg["pools"]
        chaff_names = [f"{self.engine.glyphs[g]['name']}(#{g})" for g in pools["poly_null_chaff_16"][:8]]
        rotor_names = [f"{self.engine.glyphs[g]['name']}(#{g})" for g in pools["rotor_mutators_16"][:8]]
        chk_names   = [f"{self.engine.glyphs[g]['name']}(#{g})" for g in pools["tamper_checksum_16"][:8]]
        eof_id      = pools.get("eof_sigil", self.engine.EOF_GLYPH_ID)

        lines = [
            "=== ACTIVE SAFETY GUARDRAILS (SafetyConfig) ===",
            f"• Max Output/Input PNG Size  : {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px ({SafetyConfig.MAX_PNG_TILES:,} glyph tiles max)",
            f"• Max File Size for PNG Mode : {SafetyConfig.MAX_FILE_BYTES_FOR_PNG // 1024} KB (Pre-flight refusal + blocks video/audio/archives)",
            f"• Max File Size for .CIPH    : {SafetyConfig.MAX_FILE_BYTES_FOR_CIPH // 1024} KB ({SafetyConfig.MAX_CIPH_GLYPHS:,} glyphs max under default schedules)",
            f"• Max Text Studio Input      : {SafetyConfig.MAX_TEXT_INPUT_CHARS:,} characters",
            "",
            "=== ACTIVE TWO-SECRET GENESIS LEGEND KEYFILE (PROTOCOL V5 / LEGEND V3) ===",
            f"Keyfile Path         : {self.engine.legend_path}",
            f"Legend Schema & ID   : {leg.get('schema')} • {leg['legend_id']}",
            f"Genesis 256-Bit Salt : {leg['genesis_salt'][:64]}",
            f"PBKDF2 Iterations    : {leg['pbkdf2_iterations']:,} (HMAC-SHA512 → 512-bit Master-Key Output)",
            "Key Separation       : Master output split into labeled subkeys (genesis table, nonce mask, session root)",
            "Session Nonce & Keys : Independently samples a 128-bit CSPRNG nonce per message → separate enc / MAC / layout keys",
            "1,024! Arrangements  : Stores 1 permutation chosen from 1,024! ≈ 5.42 × 10^2,639 possible arrangements",
            "960! Data Sub-Space  : 960! ≈ 8.87 × 10^2,447 possible data-homophone arrangements (arrangement count, not proven security)",
            "Role Mutation Model  : All 1,024 glyphs permute per session; rotors mutate the 1,007-slot body table every 16 bytes.",
            "Encrypt-then-MAC     : SHAKE-256 keystream, then 256-Bit HMAC-SHA256 over the ciphertext — verified before decryption",
            "Optical Pixel Check  : Default strict mode requires each decoded 16×16 RGBA tile to match the loaded glyph library",
            "Digest Verification  : Tag, seal, padding, and body-schedule comparisons use hmac.compare_digest.",
            "Security Model Note  : Two-secret security requires keeping BOTH your .legend.json keyfile and Passphrase",
            "                       private. If a Legend file is shared publicly, security relies on Passphrase strength.",
            "",
            "=== BASELINE LEGEND ROLE POOLS (FURTHER PERMUTED PER-SESSION BY NONCE & KEY) ===",
            f"• Poly-Null Chaff (16) : {', '.join(chaff_names)} ...",
            f"• Rotor Mutators  (16) : {', '.join(rotor_names)} ...",
            f"• Tamper Checksum (16) : {', '.join(chk_names)} ...",
            f"• Baseline EOF    (1)  : {self.engine.glyphs[eof_id]['name']}.png (#{eof_id:04d})",
            "",
            "=== SAMPLE HOMOPHONIC BYTE MAPPINGS (BASELINE LEGEND S-BOX STATE) ==="
        ]
        sbox = leg["genesis_sbox_960"]
        for b_val in [ord('A'), ord('B'), ord('E'), ord('T'), ord('a'), ord('e'), ord('0'), ord('$')]:
            base, count = self.engine._byte_to_homophone_range(b_val)
            gids = sbox[base:base + count]
            g_str = ", ".join(f"{self.engine.glyphs[g]['name']}.png (#{g:04d})" for g in gids)
            lines.append(f"  Byte 0x{b_val:02X} ('{chr(b_val)}') → {count} Homophones: [{g_str}]")

        self.txt_legend_info.delete("1.0", tk.END)
        self.txt_legend_info.insert("1.0", "\n".join(lines))

        self.lbl_status.config(
            text=(
                f"✓ Folder Glyphs Loaded: {self.engine.disk_loaded_count}/1,024 White PNGs • "
                f"Safety Guard: Max {SafetyConfig.MAX_PNG_WIDTH_PX}×{SafetyConfig.MAX_PNG_HEIGHT_PX} px • "
                f"Active Legend: {self.engine.legend_path.name}"
            )
        )

    def generate_new_legend_action(self):
        if not messagebox.askyesno(
            "Create a New Legend Keyfile?",
            "A new Legend creates a completely new set of secret keys.\n\n"
            "Anything already encrypted with your CURRENT Legend can only be decrypted with that "
            "current Legend file — make sure it is backed up before switching.\n\n"
            "Continue and create a new Legend?"
        ):
            return
        path = filedialog.asksaveasfilename(
            title="Save New Randomized .legend.json Keyfile",
            defaultextension=".legend.json",
            initialfile="custom_vault.legend.json",
            filetypes=[("Legend Keyfile", "*.legend.json"), ("JSON", "*.json")]
        )
        if not path:
            return
        self.engine.generate_new_legend(path)
        self._refresh_sbox_preview()
        self._maybe_reencrypt()
        messagebox.showwarning(
            "Back Up Your New Legend",
            f"Generated & activated a new Legend keyfile:\n{path}\n\n"
            "Back this file up somewhere safe now. If it is lost, deleted, or replaced, anything encrypted "
            "with it can NEVER be recovered — even with the correct passphrase.\n\n"
            "Never share it publicly or include it in a release."
        )

    def load_legend_action(self):
        path = filedialog.askopenfilename(
            title="Select .legend.json Keyfile",
            filetypes=[("Legend Keyfile", "*.json")]
        )
        if not path:
            return
        try:
            self.engine.load_legend(path)
            self._refresh_sbox_preview()
            self._maybe_reencrypt()
            messagebox.showinfo("Legend Loaded", f"Loaded Legend Keyfile:\n{path}")
        except Exception as e:
            messagebox.showerror("Invalid Legend File", str(e))

    def repair_disk_glyphs_action(self):
        written = 0
        root_resolved = self.engine.root_dir.resolve()
        for gid, g in self.engine.glyphs.items():
            safe_p = self.engine._assert_within_root(g["path"])
            if safe_p.parent.name not in VALID_ARCHETYPE_FAMILIES or safe_p.parent.parent != root_resolved:
                raise ValueError(f"Refusing to write glyph asset outside canonical archetype directory: {safe_p}")
            if not safe_p.exists():
                safe_p.parent.mkdir(parents=True, exist_ok=True)
                PurePNG.write_rgba(safe_p, 16, 16, g["rgba"])
                written += 1
        self.engine.discover_and_load_glyphs()
        self._refresh_sbox_preview()
        messagebox.showinfo("Folder Check Complete", f"Verified all 1,024 glyph PNGs on disk (wrote {written} missing files).")


if __name__ == "__main__":
    if tk is None:
        print("Tkinter GUI not available; import CipherEngine1024 in Python to use headless.")
        sys.exit(1)
    root = tk.Tk()
    root.withdraw()  # Stay hidden until a Legend keyfile is confirmed
    try:
        app = CipherWorkbenchApp(root)
    except SystemExit:
        root.destroy()
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Cipher Engine 1024 — Startup Error", str(e), parent=root)
        root.destroy()
        sys.exit(1)
    root.deiconify()
    root.mainloop()