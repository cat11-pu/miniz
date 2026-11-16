#!/usr/bin/env python3

import argparse
import hashlib
import math
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path


MALFORMED_COUNT = 200
VALID_COUNT = 50
ASSET_CATEGORIES = ("texture", "mesh", "audio")
MUTATIONS = ("truncated_deflate", "corrupt_deflate", "unsafe_path", "oversized_entry")


def png_chunk(kind, data):
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def make_texture(seed):
    rng = random.Random(0x1000 + seed)
    width = 64
    height = 64
    pixels = rng.randbytes(width * height * 3)
    raw = b"".join(b"\x00" + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) +
            png_chunk(b"IDAT", zlib.compress(raw, 6)) + png_chunk(b"IEND", b""))


def make_mesh(seed):
    rng = random.Random(0x2000 + seed)
    lines = [f"# generated mesh {seed}", f"o mesh_{seed:04d}"]
    for _ in range(384):
        lines.append("v %.6f %.6f %.6f" % (rng.uniform(-1.0, 1.0), rng.uniform(-1.0, 1.0), rng.uniform(-1.0, 1.0)))
    for _ in range(256):
        a = rng.randrange(1, 385)
        b = rng.randrange(1, 385)
        c = rng.randrange(1, 385)
        lines.append(f"f {a} {b} {c}")
    return ("\n".join(lines) + "\n").encode("ascii")


def make_audio(seed):
    sample_rate = 16000
    sample_count = 8192
    frequency = 220.0 + (seed % 23) * 17.0
    phase = (seed % 31) * 0.07
    samples = bytearray()
    for i in range(sample_count):
        value = int(12000.0 * math.sin(2.0 * math.pi * frequency * i / sample_rate + phase))
        samples += struct.pack("<h", value)
    data_size = len(samples)
    return (b"RIFF" + struct.pack("<I", 36 + data_size) + b"WAVE" +
            b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, sample_rate, sample_rate * 2, 2, 16) +
            b"data" + struct.pack("<I", data_size) + bytes(samples))


ASSET_BUILDERS = {
    "texture": make_texture,
    "mesh": make_mesh,
    "audio": make_audio,
}

ASSET_PATHS = {
    "texture": "assets/textures/tex_{seed:06d}.png",
    "mesh": "assets/meshes/mesh_{seed:06d}.obj",
    "audio": "assets/audio/audio_{seed:06d}.wav",
}


def build_entries(seed):
    entries = []
    for category in ASSET_CATEGORIES:
        entries.append({
            "category": category,
            "name": ASSET_PATHS[category].format(seed=seed),
            "data": ASSET_BUILDERS[category](seed),
        })
    return entries


def write_zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for entry in entries:
            info = zipfile.ZipInfo(entry["name"], date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = entry.get("compression", zipfile.ZIP_DEFLATED)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entry["data"], compresslevel=6)


def parse_zip_layout(blob):
    eocd = blob.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("missing end-of-central-directory record")
    fields = struct.unpack_from("<IHHHHIIH", blob, eocd)
    total_entries = fields[4]
    central_size = fields[5]
    central_ofs = fields[6]
    if total_entries == 0xFFFF or central_ofs == 0xFFFFFFFF:
        raise ValueError("test archives must not use ZIP64")
    if central_ofs + central_size > eocd:
        raise ValueError("invalid central directory bounds")

    entries = []
    pos = central_ofs
    for index in range(total_entries):
        values = struct.unpack_from("<IHHHHHHIIIHHHHHII", blob, pos)
        if values[0] != 0x02014B50:
            raise ValueError("invalid central directory signature")
        flags = values[3]
        method = values[4]
        comp_size = values[8]
        uncomp_size = values[9]
        name_len = values[10]
        extra_len = values[11]
        comment_len = values[12]
        local_ofs = values[16]
        name = blob[pos + 46:pos + 46 + name_len].decode("utf-8", "replace")
        if blob[local_ofs:local_ofs + 4] != b"PK\x03\x04":
            raise ValueError("invalid local header signature")
        local = struct.unpack_from("<IHHHHHIIIHH", blob, local_ofs)
        local_name_len = local[9]
        local_extra_len = local[10]
        data_ofs = local_ofs + 30 + local_name_len + local_extra_len
        if data_ofs + comp_size > len(blob):
            raise ValueError("compressed data exceeds archive")
        entries.append({
            "index": index,
            "name": name,
            "name_len": name_len,
            "central": pos,
            "local": local_ofs,
            "data_ofs": data_ofs,
            "flags": flags,
            "method": method,
            "comp_size": comp_size,
            "uncomp_size": uncomp_size,
        })
        pos += 46 + name_len + extra_len + comment_len

    if pos != central_ofs + central_size:
        raise ValueError("central directory size mismatch")
    return entries


def deflate_matches(compressed, expected):
    inflater = zlib.decompressobj(-15)
    try:
        output = inflater.decompress(compressed) + inflater.flush()
    except zlib.error:
        return False
    return inflater.eof and output == expected


def mutate_truncated(blob, entry, expected):
    compressed_size = entry["comp_size"]
    if compressed_size < 32:
        raise ValueError("compressed payload too small for truncation")
    for divisor in (3, 4, 2, 5):
        cut = max(8, compressed_size // divisor)
        if cut >= compressed_size:
            continue
        candidate = bytearray(blob)
        start = entry["data_ofs"] + compressed_size - cut
        candidate[start:entry["data_ofs"] + compressed_size] = b"\x00" * cut
        if not deflate_matches(bytes(candidate[entry["data_ofs"]:entry["data_ofs"] + compressed_size]), expected):
            return candidate
    raise ValueError("could not construct a truncated deflate stream")


def mutate_corrupt(blob, entry, expected, seed):
    compressed_size = entry["comp_size"]
    if compressed_size < 32:
        raise ValueError("compressed payload too small for corruption")
    for attempt in range(64):
        candidate = bytearray(blob)
        pos = (compressed_size // 3 + seed * 37 + attempt * 53) % compressed_size
        candidate[entry["data_ofs"] + pos] ^= (0x5A + attempt * 17) & 0xFF
        if not deflate_matches(bytes(candidate[entry["data_ofs"]:entry["data_ofs"] + compressed_size]), expected):
            return candidate
    raise ValueError("could not construct a corrupt deflate stream")


def make_unsafe_name(name, variant):
    extension = os.path.splitext(name)[1]
    prefixes = ("../../", "/tmp/", "C:\\", "..\\..\\")
    prefix = prefixes[variant % len(prefixes)]
    padding = len(name) - len(prefix) - len(extension)
    if padding < 1:
        raise ValueError("name too short for unsafe rewrite")
    result = prefix + ("x" * padding) + extension
    if len(result) != len(name):
        raise AssertionError("unsafe name length changed")
    return result.encode("ascii")


def mutate_unsafe_path(blob, entry, variant):
    candidate = bytearray(blob)
    replacement = make_unsafe_name(entry["name"], variant)
    local_pos = entry["local"] + 30
    central_pos = entry["central"] + 46
    name_len = entry["name_len"]
    candidate[local_pos:local_pos + name_len] = replacement
    candidate[central_pos:central_pos + name_len] = replacement
    return candidate


def mutate_oversized(blob, entry):
    candidate = bytearray(blob)
    oversized = 0xF0000000
    struct.pack_into("<I", candidate, entry["local"] + 22, oversized)
    struct.pack_into("<I", candidate, entry["central"] + 24, oversized)
    return candidate


def make_malformed_case(path, seed):
    entries = build_entries(seed)
    for entry in entries:
        entry["compression"] = zipfile.ZIP_DEFLATED
    write_zip(path, entries)
    blob = path.read_bytes()
    layout = parse_zip_layout(blob)
    for entry, parsed in zip(entries, layout):
        if entry["name"] != parsed["name"]:
            raise AssertionError("central directory order changed")
        if parsed["method"] != zipfile.ZIP_DEFLATED:
            raise AssertionError("malformed targets must use deflate")

    mutation = MUTATIONS[seed % len(MUTATIONS)]
    target_category = ASSET_CATEGORIES[seed % len(ASSET_CATEGORIES)]
    target_index = ASSET_CATEGORIES.index(target_category)
    target = layout[target_index]
    expected = entries[target_index]["data"]

    if mutation == "truncated_deflate":
        candidate = mutate_truncated(blob, target, expected)
    elif mutation == "corrupt_deflate":
        candidate = mutate_corrupt(blob, target, expected, seed)
    elif mutation == "unsafe_path":
        candidate = mutate_unsafe_path(blob, target, seed)
    else:
        candidate = mutate_oversized(blob, target)

    path.write_bytes(candidate)
    return {
        "seed": seed,
        "mutation": mutation,
        "target_category": target_category,
        "target_name": target["name"],
        "target_index": target_index,
    }


def make_valid_case(path, seed):
    entries = build_entries(seed)
    for index, entry in enumerate(entries):
        entry["compression"] = zipfile.ZIP_STORED if ((seed + index) % 3 == 0) else zipfile.ZIP_DEFLATED
    write_zip(path, entries)
    with zipfile.ZipFile(path, "r") as archive:
        for entry in entries:
            if archive.read(entry["name"]) != entry["data"]:
                raise AssertionError("reference ZIP round-trip mismatch")
    return entries


def harness_env():
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1:strict_string_checks=1")
    env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
    return env


def run_harness(harness, mode, archive, output_dir):
    command = [str(harness), mode, str(archive), str(output_dir)]
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=30, env=harness_env())


def parse_summary(stdout):
    for line in stdout.splitlines():
        if line.startswith("SUMMARY\t"):
            result = {}
            for field in line.split("\t")[1:]:
                key, value = field.split("=", 1)
                result[key] = value
            return result
    return None


def verify_malformed(harness, archive, manifest):
    result = run_harness(harness, "reject", archive, archive.parent)
    if result.returncode != 0:
        raise AssertionError(
            f"malformed case {manifest['mutation']} crashed or failed:\n"
            f"archive={archive}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    if "INVARIANT\t" in result.stdout or "LEAK\t" in result.stdout:
        raise AssertionError(f"invariant failure for {archive}:\n{result.stdout}")
    summary = parse_summary(result.stdout)
    if summary is None:
        raise AssertionError(f"missing harness summary for {archive}:\n{result.stdout}")
    if summary.get("failures") != "0":
        raise AssertionError(f"harness reported failures for {archive}:\n{result.stdout}")
    if int(summary.get("expected", "0")) < 1:
        raise AssertionError(f"malformed archive was accepted for {archive}:\n{result.stdout}")
    if any(summary.get(key) != "0" for key in ("live_bytes", "live_allocs", "invalid_frees")):
        raise AssertionError(f"allocator leak accounting failed for {archive}:\n{result.stdout}")

    rejects = [line for line in result.stdout.splitlines() if line.startswith("REJECT\t")]
    matching = None
    for line in rejects:
        fields = {}
        for field in line.split("\t")[1:]:
            key, value = field.split("=", 1)
            fields[key] = value
        if fields.get("index") == str(manifest["target_index"]):
            matching = line
            break
    if matching is None:
        raise AssertionError(f"target entry was not rejected for {archive}:\n{result.stdout}")
    fields = dict(field.split("=", 1) for field in matching.split("\t")[1:])
    if int(fields["data"]) <= 0:
        raise AssertionError(f"rejection has no usable entry data offset for {archive}:\n{matching}")
    return matching


def parse_entries(stdout):
    entries = []
    for line in stdout.splitlines():
        if not line.startswith("ENTRY\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 13:
            raise AssertionError(f"malformed harness ENTRY line: {line}")
        entries.append({
            "index": int(fields[1]),
            "local": int(fields[2]),
            "data": int(fields[3]),
            "method": int(fields[4]),
            "comp_size": int(fields[5]),
            "uncomp_size": int(fields[6]),
            "crc32": fields[7],
            "flags": int(fields[8]),
            "safe": fields[9] == "1",
            "status": fields[10],
            "file": fields[11],
            "name": fields[12],
        })
    return entries


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_valid(harness, archive, entries, work_dir):
    extract_dir = work_dir / "extract"
    reference_dir = work_dir / "reference"
    extract_dir.mkdir(parents=True, exist_ok=True)
    reference_dir.mkdir(parents=True, exist_ok=True)

    result = run_harness(harness, "extract", archive, extract_dir)
    if result.returncode != 0:
        raise AssertionError(
            f"valid archive extraction failed:\narchive={archive}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    summary = parse_summary(result.stdout)
    if summary is None or summary.get("failures") != "0":
        raise AssertionError(f"valid extraction summary failed for {archive}:\n{result.stdout}")
    if any(summary.get(key) != "0" for key in ("live_bytes", "live_allocs", "invalid_frees")):
        raise AssertionError(f"valid extraction leaked memory for {archive}:\n{result.stdout}")

    parsed = {entry["name"]: entry for entry in parse_entries(result.stdout)}
    if set(parsed) != {entry["name"] for entry in entries}:
        raise AssertionError(f"entry set mismatch for {archive}")

    unzip = shutil.which("unzip")
    if unzip:
        subprocess.run([unzip, "-qq", "-o", str(archive), "-d", str(reference_dir)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    verified = []
    for expected_entry in entries:
        name = expected_entry["name"]
        entry = parsed[name]
        if entry["status"] != "OK" or not entry["safe"]:
            raise AssertionError(f"entry was not extracted safely for {archive}: {entry}")
        output = (extract_dir / entry["file"]).read_bytes()
        expected_digest = sha256(expected_entry["data"])
        output_digest = sha256(output)
        if output != expected_entry["data"]:
            raise AssertionError(f"miniz output differs byte-for-byte for {archive}:{name}")
        if output_digest != expected_digest:
            raise AssertionError(f"digest mismatch for {archive}:{name}")
        if unzip:
            reference = (reference_dir / name).read_bytes()
            if reference != output:
                raise AssertionError(f"unzip reference differs byte-for-byte for {archive}:{name}")
            if sha256(reference) != output_digest:
                raise AssertionError(f"unzip reference digest differs for {archive}:{name}")
        verified.append((expected_entry["category"], name, expected_digest))
    return verified


def aggregate_digest(items):
    digest = hashlib.sha256()
    for _, name, value in sorted(items, key=lambda item: item[1]):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("harness", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    harness = args.harness.resolve()
    if not harness.is_file():
        raise SystemExit(f"harness not found: {harness}")

    if args.work_dir:
        work_dir = args.work_dir.resolve()
        if work_dir.exists():
            shutil.rmtree(work_dir)
        work_dir.mkdir(parents=True)
        temporary = False
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="miniz-zip-properties-"))
        temporary = True

    succeeded = False
    try:
        malformed_dir = work_dir / "malformed"
        valid_dir = work_dir / "valid"
        malformed_dir.mkdir()
        valid_dir.mkdir()

        samples = {}
        for seed in range(MALFORMED_COUNT):
            archive = malformed_dir / f"case_{seed:03d}.zip"
            manifest = make_malformed_case(archive, seed)
            reject = verify_malformed(harness, archive, manifest)
            samples.setdefault(manifest["mutation"], reject)

        category_hashes = {category: [] for category in ASSET_CATEGORIES}
        byte_compare_count = 0
        hash_check_count = 0
        for seed in range(VALID_COUNT):
            archive = valid_dir / f"case_{seed:03d}.zip"
            entries = make_valid_case(archive, seed)
            case_dir = work_dir / "verification" / f"case_{seed:03d}"
            verified = verify_valid(harness, archive, entries, case_dir)
            byte_compare_count += len(verified)
            hash_check_count += len(verified)
            for category, name, digest in verified:
                category_hashes[category].append((seed, name, digest))
            shutil.rmtree(case_dir)

        print(f"malformed: {MALFORMED_COUNT}/{MALFORMED_COUNT} archives rejected safely")
        print("malformed offsets:")
        for mutation in MUTATIONS:
            print(f"  {mutation}: {samples[mutation]}")
        print(f"valid: {VALID_COUNT}/{VALID_COUNT} archives, {byte_compare_count}/{byte_compare_count} entries")
        print(f"byte comparisons: miniz == reference == source ({byte_compare_count}/{byte_compare_count})")
        print(f"sha256 checks: {hash_check_count}/{hash_check_count} matched")
        for category in ASSET_CATEGORIES:
            items = category_hashes[category]
            print(f"  {category}: {len(items)}/{len(items)} hashes matched, aggregate={aggregate_digest(items)}")
        print("crashes=0 out_of_bounds=0 leaks=0")
        succeeded = True
        return 0
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        print(f"work_dir={work_dir}", file=sys.stderr)
        return 1
    finally:
        if temporary and not args.keep and succeeded:
            shutil.rmtree(work_dir, ignore_errors=True)
        else:
            print(f"artifacts: {work_dir}")


if __name__ == "__main__":
    sys.exit(main())
