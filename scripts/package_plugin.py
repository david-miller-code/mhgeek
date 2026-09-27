#!/usr/bin/env python3
"""Package the standalone MHGeek plugin."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "mhgeek"
PRIVATE_KEY = re.compile(
    br"-----BEGIN (?:RSA |OPENSSH |EC |ENCRYPTED )?PRIVATE KEY-----"
)
MAX_PACKAGE_BYTES = 64 * 1024 * 1024


def regular_files(base):
    for path in sorted(base.rglob("*")):
        if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if path.is_symlink():
            raise ValueError(f"source symlink is not allowed: {path}")
        if path.is_file():
            yield path


def content(path):
    data = path.read_bytes()
    if PRIVATE_KEY.search(data):
        raise ValueError(f"private key material found: {path}")
    return data


def archive_bytes(files):
    with tempfile.TemporaryFile() as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0,
                           compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w",
                              format=tarfile.USTAR_FORMAT) as archive:
                directories = set()
                for name, _ in files:
                    parent = name.parent
                    while parent != Path("."):
                        directories.add(parent)
                        parent = parent.parent
                for name in sorted(directories):
                    info = tarfile.TarInfo(name.as_posix())
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.mtime = 0
                    archive.addfile(info)
                for name, source in sorted(files):
                    data = content(source)
                    info = tarfile.TarInfo(name.as_posix())
                    info.size = len(data)
                    info.mode = 0o755 if name.name == "mhgeek.app" or source.stat().st_mode & 0o111 else 0o644
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))
        output.seek(0)
        return output.read()


def write_artifact(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    checksum = hashlib.sha256(data).hexdigest()
    path.with_name(path.name + ".sha256").write_text(
        f"{checksum}  {path.name}\n", encoding="ascii"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, default=ROOT / "build/mhgeek.app")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "releases")
    args = parser.parse_args()
    manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
    if manifest.get("id") != "mhgeek" or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", str(manifest.get("version", ""))
    ):
        raise ValueError("plugin id or version is invalid")
    version = manifest["version"]
    if not args.backend.is_file() or args.backend.is_symlink():
        raise ValueError(f"backend missing: {args.backend}")

    plugin_files = [
        (Path("mhgeek") / path.relative_to(PLUGIN), path)
        for path in regular_files(PLUGIN)
    ]
    plugin_files.append((Path("mhgeek/LICENSE"), ROOT / "LICENSE"))
    plugin_files.append((Path("mhgeek/mhgeek.app"), args.backend))
    package = archive_bytes(plugin_files)
    if not 0 < len(package) <= MAX_PACKAGE_BYTES:
        raise ValueError("plugin package exceeds the 64 MiB limit")
    package_path = args.output_dir / f"mhgeek-{version}.plugin"
    write_artifact(package_path, package)

    print(package_path)


if __name__ == "__main__":
    main()
