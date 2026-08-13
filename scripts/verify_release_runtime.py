"""Verify the hash-locked release verifier environment before secrets exist.

The CNB job creates a repository-local virtual environment from
``requirements-release-ci.txt`` with pip's ``--require-hashes`` mode.  This
module then verifies every installed file recorded by each wheel's RECORD,
including the Python and native modules that perform signature validation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path


EXPECTED_PACKAGES = {
    "cryptography": "49.0.0",
    "cffi": "2.1.1",
    "pycparser": "3.0",
}
EXPECTED_CRYPTOGRAPHY = EXPECTED_PACKAGES["cryptography"]
HASH_TOKEN = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
MODULE_PREFIXES = {
    "cryptography": ("cryptography/",),
    "cffi": ("cffi/", "_cffi_backend"),
    "pycparser": ("pycparser/",),
}
CRITICAL_MODULE_SUFFIXES = (".py", ".so", ".pyd", ".dll", ".dylib")


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _locked_requirements(path: Path) -> dict[str, set[str]]:
    """Return the exact pinned closure and reject any unhashed requirement."""

    logical: list[str] = []
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        if continued:
            line = line[:-1].rstrip()
        pending = f"{pending} {line}".strip()
        if not continued:
            logical.append(pending)
            pending = ""
    if pending:
        raise ValueError("release_runtime_requirement_continuation_invalid")

    locked: dict[str, set[str]] = {}
    for requirement in logical:
        tokens = shlex.split(requirement, posix=True)
        if not tokens or "==" not in tokens[0]:
            raise ValueError("release_runtime_requirement_not_exact")
        name, version = tokens[0].split("==", 1)
        normalized = name.lower().replace("_", "-")
        if not name or not version or normalized in locked:
            raise ValueError("release_runtime_requirement_invalid")
        hashes: set[str] = set()
        for token in tokens[1:]:
            match = HASH_TOKEN.fullmatch(token)
            if match is None:
                raise ValueError("release_runtime_requirement_option_invalid")
            hashes.add(match.group(1))
        if not hashes:
            raise ValueError("release_runtime_requirement_hash_missing")
        expected = EXPECTED_PACKAGES.get(normalized)
        if expected != version:
            raise ValueError("release_runtime_requirement_drift")
        locked[normalized] = hashes
    if set(locked) != set(EXPECTED_PACKAGES):
        raise ValueError("release_runtime_requirement_closure_invalid")
    return locked


def _record_receipt(name: str, environment: Path) -> dict[str, object]:
    distribution = importlib.metadata.distribution(name)
    files = distribution.files
    if not files:
        raise ValueError(f"release_runtime_record_missing:{name}")

    module_prefixes = MODULE_PREFIXES[name]
    verified_files = 0
    verified_modules = 0
    record_path: Path | None = None
    for entry in files:
        normalized = str(entry).replace("\\", "/")
        located = Path(distribution.locate_file(entry))
        if located.is_symlink():
            raise ValueError(f"release_runtime_symlink_rejected:{name}:{normalized}")
        resolved = located.resolve(strict=True)
        if not _within(resolved, environment):
            raise ValueError(f"release_runtime_file_outside_environment:{name}:{normalized}")
        if normalized.endswith(".dist-info/RECORD"):
            record_path = resolved
            continue

        is_module = normalized.startswith(module_prefixes) and normalized.endswith(
            CRITICAL_MODULE_SUFFIXES
        )
        if entry.hash is None:
            if is_module:
                raise ValueError(f"release_runtime_module_unhashed:{name}:{normalized}")
            continue
        if entry.hash.mode != "sha256":
            raise ValueError(f"release_runtime_record_hash_algorithm_invalid:{name}")
        digest = hashlib.sha256()
        size = 0
        with resolved.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        observed = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
        if observed != entry.hash.value:
            raise ValueError(f"release_runtime_record_hash_mismatch:{name}:{normalized}")
        if entry.size is not None and size != entry.size:
            raise ValueError(f"release_runtime_record_size_mismatch:{name}:{normalized}")
        verified_files += 1
        if is_module:
            verified_modules += 1

    if record_path is None or verified_modules == 0:
        raise ValueError(f"release_runtime_module_record_incomplete:{name}")
    record_sha256 = hashlib.sha256(record_path.read_bytes()).hexdigest()
    return {
        "version": distribution.version,
        "record_sha256": record_sha256,
        "verified_files": verified_files,
        "verified_modules": verified_modules,
    }


def verify(root: Path, *, require_venv: bool = False) -> dict:
    locked = _locked_requirements(root / "requirements-release-ci.txt")
    environment = Path(sys.prefix).resolve()
    if require_venv:
        expected_environment = (root / ".release-ci-venv").resolve()
        if sys.prefix == sys.base_prefix or environment != expected_environment:
            raise ValueError("release_runtime_not_repository_venv")

    packages: dict[str, dict[str, object]] = {}
    origins: dict[str, str] = {}
    for name, expected_version in EXPECTED_PACKAGES.items():
        if importlib.metadata.version(name) != expected_version:
            raise ValueError(f"release_runtime_package_version_mismatch:{name}")
        spec = importlib.util.find_spec(name)
        origin = Path(str(spec.origin or "")).resolve() if spec is not None else None
        if origin is None or not _within(origin, environment):
            raise ValueError(f"release_runtime_import_outside_environment:{name}")
        origins[name] = str(origin)
        packages[name] = _record_receipt(name, environment)

    return {
        "schema": "dustmirror.release-runtime/v2",
        "python": ".".join(map(str, sys.version_info[:3])),
        "environment": str(environment),
        "hash_counts": {name: len(hashes) for name, hashes in locked.items()},
        "packages": packages,
        "origins": origins,
        "cryptography": EXPECTED_CRYPTOGRAPHY,
        "cryptography_origin": origins["cryptography"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-venv", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = verify(Path(__file__).resolve().parents[1], require_venv=args.require_venv)
        print(json.dumps({"verified": True, **result}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
