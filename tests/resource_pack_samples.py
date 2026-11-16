#!/usr/bin/env python3
"""Generate deterministic game resource-pack samples and malformed variants.

The output directory contains one valid pack with texture/mesh/audio entries,
plus malformed packs used by the ZIP reader hardening tests.  Everything is
derived from fixed byte patterns so hashes are stable across runs.
"""

import hashlib
import json
import math
import os
import struct
import zlib


OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_pack_samples")


def make_texture():
    width = height = 64
    out = bytearray()
    for y in range(height):
        for x in range(width):
            checker = 255 if ((x // 8) ^ (y // 8)) & 1 else 32
            out += bytes((checker, (x * 4) & 0xFF, (y * 4) & 0xFF, 255))
    return bytes(out)


def make_mesh():
    vertices = []
    for i in range(96):
        angle = i * math.tau / 96.0
        vertices.append(
            struct.pack(
                "<8f",
                math.cos(angle),
                math.sin(angle),
                0.25 * math.sin(angle * 3.0),
                math.cos(angle),
                math.sin(angle),
                0.0,
                i / 96.0,
                (i * 7 % 96) / 96.0,
            )
        )
    indices = b"".join(struct.pack("<3H", i, i + 1, i + 2) for i in range(0, 96, 3))
    return b"MESH" + struct.pack("<II", 96, 96) + b"".join(vertices) + indices


def make_audio():
    sample_rate = 22050
    samples = 4096
    pcm = bytearray()
    for i in range(samples):
        value = int(12000 * math.sin(math.tau * 440.0 * i / sample_rate))
        pcm += struct.pack("<h", value)
    header = b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
    header += b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, sample_rate, sample_rate * 2, 2, 16)
    header += b"data" + struct.pack("<I", len(pcm))
    return header + bytes(pcm)


def deflate(data, level=6):
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def build_zip(entries):
    """entries: dicts with name, method, comp, data, comp_field, uncomp_field,
    central_extra, local_extra."""
    body = bytearray()
    central = bytearray()
    offsets = {}

    for entry in entries:
        name = entry["name"].encode("utf-8")
        comp = entry["comp"]
        data = entry["data"]
        method = entry["method"]
        local_extra = entry.get("local_extra", b"")
        central_extra = entry.get("central_extra", b"")
        comp_field = entry.get("comp_field", len(comp))
        uncomp_field = entry.get("uncomp_field", len(data))
        flags = entry.get("flags", 0)
        crc = entry.get("crc", zlib.crc32(data) & 0xFFFFFFFF)
        local_ofs = len(body)
        offsets[entry["name"]] = local_ofs

        body += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            45,
            flags,
            method,
            0,
            0,
            crc,
            comp_field,
            uncomp_field,
            len(name),
            len(local_extra),
        )
        body += name + local_extra + comp

        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            45,
            45,
            flags,
            method,
            0,
            0,
            crc,
            comp_field,
            uncomp_field,
            len(name),
            len(central_extra),
            0,
            0,
            0,
            0,
            local_ofs,
        )
        central += name + central_extra

    central_ofs = len(body)
    body += central
    body += struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        central_ofs,
        0,
    )
    return bytes(body), offsets, central_ofs


def zip64_extra(uncomp=None, comp=None, local_ofs=None):
    payload = bytearray()
    if uncomp is None and comp is None and local_ofs is None:
        return b""
    if uncomp is not None:
        payload += struct.pack("<Q", uncomp)
    if comp is not None:
        payload += struct.pack("<Q", comp)
    if local_ofs is not None:
        payload += struct.pack("<Q", local_ofs)
    return struct.pack("<HH", 1, len(payload)) + bytes(payload)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    texture = make_texture()
    mesh = make_mesh()
    audio = make_audio()
    resources = [
        ("textures/checker.rgba", texture, 6),
        ("meshes/hero.mesh", mesh, 9),
        ("audio/beep.wav", audio, 6),
    ]

    valid_entries = []
    manifest_entries = []
    for name, data, level in resources:
        comp = deflate(data, level)
        valid_entries.append(
            {"name": name, "method": 8, "data": data, "comp": comp}
        )
        manifest_entries.append(
            {
                "name": name,
                "uncompressed_size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    valid, offsets, central_ofs = build_zip(valid_entries)
    valid_path = os.path.join(OUT_DIR, "valid_resources.zip")
    with open(valid_path, "wb") as f:
        f.write(valid)

    malformed = []

    tex_comp = valid_entries[0]["comp"]
    truncated = tex_comp[: max(1, len(tex_comp) * 3 // 5)]
    bad_tex, _, bad_tex_cdir = build_zip(
        [
            {
                "name": "textures/truncated.rgba",
                "method": 8,
                "data": texture,
                "comp": truncated,
                "crc": zlib.crc32(texture) & 0xFFFFFFFF,
            }
        ]
    )
    path = os.path.join(OUT_DIR, "texture_truncated_deflate.zip")
    with open(path, "wb") as f:
        f.write(bad_tex)
    malformed.append(
        {
            "path": os.path.basename(path),
            "category": "texture",
            "mutation": "deflate stream truncated",
            "expected_error": "MZ_ZIP_DECOMPRESSION_FAILED",
            "expected_error_code": 11,
            "expected_entry_index": 0,
            "expected_entry_offset": bad_tex_cdir,
        }
    )

    mesh_comp = bytearray(valid_entries[1]["comp"])
    mesh_comp[0] = 0xFF
    mesh_comp[1] = 0xFF
    bad_mesh, _, bad_mesh_cdir = build_zip(
        [
            {
                "name": "meshes/corrupt.mesh",
                "method": 8,
                "data": mesh,
                "comp": bytes(mesh_comp),
                "crc": zlib.crc32(mesh) & 0xFFFFFFFF,
            }
        ]
    )
    path = os.path.join(OUT_DIR, "mesh_corrupt_deflate.zip")
    with open(path, "wb") as f:
        f.write(bad_mesh)
    malformed.append(
        {
            "path": os.path.basename(path),
            "category": "mesh",
            "mutation": "invalid deflate block header",
            "expected_error": "MZ_ZIP_DECOMPRESSION_FAILED",
            "expected_error_code": 11,
            "expected_entry_index": 0,
            "expected_entry_offset": bad_mesh_cdir,
        }
    )

    audio_ofs = offsets["audio/beep.wav"]
    audio_name_len = len("audio/beep.wav")
    audio_cdh = central_ofs
    for name, data, level in resources:
        if name == "audio/beep.wav":
            break
        audio_cdh += 46 + len(name.encode("utf-8")) + 0
    bad_audio = bytearray(valid)
    struct.pack_into("<H", bad_audio, audio_cdh + 28, 0xFFFF)
    path = os.path.join(OUT_DIR, "audio_bad_central_dir.zip")
    with open(path, "wb") as f:
        f.write(bad_audio)
    malformed.append(
        {
            "path": os.path.basename(path),
            "category": "audio",
            "mutation": "central-directory filename length overruns directory",
            "expected_error": "MZ_ZIP_INVALID_HEADER_OR_CORRUPTED",
            "expected_error_code": 9,
            "expected_entry_index": None,
            "expected_entry_offset": None,
        }
    )

    bomb, _, bomb_cdir = build_zip(
        [
            {
                "name": "textures/zip64_bomb.rgba",
                "method": 8,
                "data": b"",
                "comp": b"\x03\x00",
                "comp_field": 2,
                "uncomp_field": 0xFFFFFFFF,
                "central_extra": zip64_extra(uncomp=0xFFFFFFFFFFFFFFFF),
                "local_extra": b"",
            }
        ]
    )
    path = os.path.join(OUT_DIR, "texture_zip64_uncompressed_bomb.zip")
    with open(path, "wb") as f:
        f.write(bomb)
    malformed.append(
        {
            "path": os.path.basename(path),
            "category": "texture",
            "mutation": "zip64 uncompressed size UINT64_MAX",
            "expected_error": "MZ_ZIP_INVALID_HEADER_OR_CORRUPTED",
            "expected_error_code": 9,
            "expected_entry_index": 0,
            "expected_entry_offset": bomb_cdir,
        }
    )

    overflow, _, overflow_cdir = build_zip(
        [
            {
                "name": "meshes/zip64_overflow.mesh",
                "method": 8,
                "data": b"",
                "comp": b"\x03\x00",
                "comp_field": 0xFFFFFFFF,
                "uncomp_field": 0,
                "central_extra": zip64_extra(comp=0xFFFFFFFFFFFFFFFF),
                "local_extra": b"",
            }
        ]
    )
    path = os.path.join(OUT_DIR, "mesh_zip64_compressed_overflow.zip")
    with open(path, "wb") as f:
        f.write(overflow)
    malformed.append(
        {
            "path": os.path.basename(path),
            "category": "mesh",
            "mutation": "zip64 compressed size UINT64_MAX wraps offset arithmetic",
            "expected_error": "MZ_ZIP_INVALID_HEADER_OR_CORRUPTED",
            "expected_error_code": 9,
            "expected_entry_index": 0,
            "expected_entry_offset": overflow_cdir,
        }
    )

    manifest = {
        "valid": {
            "path": os.path.basename(valid_path),
            "sha256": hashlib.sha256(valid).hexdigest(),
            "entries": manifest_entries,
        },
        "malformed": malformed,
    }
    with open(os.path.join(OUT_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("wrote samples to", OUT_DIR)
    print("valid pack sha256", manifest["valid"]["sha256"])


if __name__ == "__main__":
    main()
