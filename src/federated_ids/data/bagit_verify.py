"""Verify a BagIt tar archive against its manifest-md5.txt and optionally extract it.

Designed for the GridStratLLM RADAR/KIT bag (10.35097-bx5337kcykte438h.tar, 6.5 GB). The tar
is streamed once: every payload member is hashed with MD5 while (optionally) being written
to the destination directory, so the archive is read only one time. Inner .zip files can be
unpacked afterwards, each into its own folder, with path-traversal checks (archive contents
are untrusted input).

Nothing in the source archive is modified.

Usage:
    python -m federated_ids.data.bagit_verify TAR --dest DIR [--extract] [--unzip]
        [--skip-extract PATTERN ...] [--output JSON]
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

BLOCK = 1 << 20


def _safe_relpath(name: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe member path in archive: {name!r}")
    return p


def read_manifest(text: str) -> dict[str, str]:
    """Parse 'md5  relative/path' lines into {relative/path: md5}."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        digest, path = line.split(maxsplit=1)
        out[path.strip()] = digest.lower()
    return out


def verify_tar(tar_path: Path, dest: Path | None, skip_extract: list[str]) -> dict:
    """Stream the tar once; hash payload files; extract unless the name matches skip_extract."""
    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    extracted: list[str] = []
    manifest_text = None
    bag_root = None
    with tarfile.open(tar_path, mode="r|") as tf:  # stream mode: sequential, low memory
        for m in tf:
            rel = _safe_relpath(m.name)
            if bag_root is None:
                bag_root = rel.parts[0]
            if not m.isfile():
                continue
            inner = PurePosixPath(*rel.parts[1:]).as_posix()  # path relative to bag root
            fh = tf.extractfile(m)
            md5 = hashlib.md5()
            do_extract = dest is not None and not any(fnmatch.fnmatch(inner, pat) for pat in skip_extract)
            out_fh = None
            if do_extract:
                out_path = dest / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_fh = open(out_path, "wb")
            try:
                buf = b"" if inner == "manifest-md5.txt" else None
                while chunk := fh.read(BLOCK):
                    md5.update(chunk)
                    if out_fh:
                        out_fh.write(chunk)
                    if buf is not None:
                        buf += chunk
            finally:
                if out_fh:
                    out_fh.close()
            if buf is not None:
                manifest_text = buf.decode("utf-8")
            hashes[inner] = md5.hexdigest()
            sizes[inner] = m.size
            if do_extract:
                extracted.append(inner)
    if manifest_text is None:
        raise ValueError("manifest-md5.txt not found in bag")
    manifest = read_manifest(manifest_text)
    results = []
    for path, expected in sorted(manifest.items()):
        got = hashes.get(path)
        results.append({"path": path, "bytes": sizes.get(path), "md5_expected": expected,
                        "md5_actual": got, "ok": got == expected})
    return {
        "bag_root": bag_root,
        "payload_files_in_manifest": len(manifest),
        "all_payload_md5_ok": all(r["ok"] for r in results),
        "files": results,
        "extracted": extracted,
    }


def unzip_safely(zip_path: Path, out_dir: Path) -> dict:
    """Extract one zip into out_dir, verifying each member's CRC; refuses unsafe paths."""
    members = []
    with zipfile.ZipFile(zip_path) as zf:
        bad = zf.testzip()  # CRC check of every member
        for info in zf.infolist():
            _safe_relpath(info.filename)
        zf.extractall(out_dir)
        for info in zf.infolist():
            if not info.is_dir():
                members.append({"name": info.filename, "bytes": info.file_size, "crc32": f"{info.CRC:08x}"})
    return {"zip": zip_path.name, "out_dir": str(out_dir), "crc_ok": bad is None, "first_bad_member": bad,
            "members": members}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("tar")
    p.add_argument("--dest", required=True, help="extraction root (outside the repository)")
    p.add_argument("--extract", action="store_true", help="write payload files while verifying")
    p.add_argument("--skip-extract", nargs="*", default=[], help="glob(s), relative to bag root, not to extract")
    p.add_argument("--unzip", action="store_true", help="unpack every data/dataset/*.zip into its own folder")
    p.add_argument("--output", default=None, help="JSON report path (default: DEST/bagit_verification.json)")
    a = p.parse_args(argv)

    tar_path, dest = Path(a.tar), Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    report = {"created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "archive": str(tar_path), "archive_bytes": tar_path.stat().st_size,
              "skip_extract": a.skip_extract}
    report.update(verify_tar(tar_path, dest if a.extract else None, a.skip_extract))
    if a.unzip:
        ds_dir = dest / report["bag_root"] / "data" / "dataset"
        report["unzipped"] = [unzip_safely(z, ds_dir / "unzipped" / z.stem) for z in sorted(ds_dir.glob("*.zip"))]
    out = Path(a.output) if a.output else dest / "bagit_verification.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for r in report["files"]:
        print(f"{'OK ' if r['ok'] else 'BAD'} {r['path']} ({r['bytes']} bytes)")
    print(f"all payload md5 ok: {report['all_payload_md5_ok']}; report: {out}")
    for u in report.get("unzipped", []):
        print(f"unzipped {u['zip']}: {len(u['members'])} files, crc_ok={u['crc_ok']}")
    return 0 if report["all_payload_md5_ok"] and all(u["crc_ok"] for u in report.get("unzipped", [])) else 1


if __name__ == "__main__":
    sys.exit(main())
