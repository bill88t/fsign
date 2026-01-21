#!/usr/bin/env python3

import os, sys, struct, hashlib, subprocess, tempfile, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional, Iterator, NamedTuple
from pathlib import Path
import fnmatch
import json

MAGIC = b"FSIG1\0"  # 6 bytes
VERSION = 1  # 1 byte
FLAGS = 0  # 1 byte reserved
HEADER_LEN = 8  # MAGIC(6)+VER(1)+FLAGS(1)

CHUNK = 1 << 20  # 1MB
EXCLUDE_BASENAMES = {b".fsign", b".fsignignore"}


# A structure to hold parsed GPG status information.
class GpgStatus(NamedTuple):
    valid_signature: bool
    fingerprint: str | None
    primary_key_id: str | None
    user_id: str | None
    summary: str


# A structure to hold a file entry's data.
class FileEntry(NamedTuple):
    path: bytes
    type: int
    length: int
    digest: bytes


# ----- pattern matching helpers -----
def load_ignore_patterns(root: str) -> List[str]:
    """Load ignore patterns from .fsignignore file."""
    ignore_file = Path(root) / ".fsignignore"
    patterns = []
    
    if ignore_file.exists():
        try:
            with open(ignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except (IOError, OSError):
            pass  # If we can't read it, just continue without patterns
    
    return patterns


def should_exclude(path: bytes, root: bytes, patterns: List[str]) -> bool:
    """Check if path matches any exclusion pattern."""
    if not patterns:
        return False
    
    # Get relative path as string
    try:
        rel_path = relpath_bytes(path, root).decode("utf-8", errors="ignore")
    except (ValueError, AttributeError):
        return False
    
    # Normalize path separators for pattern matching
    rel_path = rel_path.replace(os.sep, "/")
    
    for pattern in patterns:
        # Support both glob-style and directory patterns
        if pattern.endswith("/"):
            # Directory pattern - match if path starts with it
            if rel_path.startswith(pattern) or (rel_path + "/").startswith(pattern):
                return True
        else:
            # File pattern - use fnmatch for glob-style matching
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            # Also check if any parent directory matches
            if "/" in rel_path:
                parts = rel_path.split("/")
                for i in range(len(parts)):
                    partial = "/".join(parts[:i+1])
                    if fnmatch.fnmatch(partial, pattern):
                        return True
    
    return False


# ----- filesystem helpers (bytewise) -----
def walk_bytes(root: bytes, patterns: Optional[List[str]] = None) -> Iterator[bytes]:
    """Yield absolute byte paths for files under root (no symlink-follow)."""
    if patterns is None:
        patterns = []
    
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Filter out excluded directories
        dirnames[:] = [
            d for d in dirnames 
            if d not in EXCLUDE_BASENAMES and 
            not should_exclude(os.path.join(dirpath, d), root, patterns)
        ]
        
        for fn in filenames:
            if fn in EXCLUDE_BASENAMES:
                continue
            
            full_path = os.path.join(dirpath, fn)
            if not should_exclude(full_path, root, patterns):
                yield full_path


def relpath_bytes(path: bytes, root: bytes) -> bytes:
    """os.path.relpath with bytes, ensuring result is bytes."""
    rel = os.path.relpath(path, root)
    return os.fsencode(rel) if isinstance(rel, str) else rel


# ----- hashing -----
def hash_entry(path: bytes) -> FileEntry:
    """
    Return FileEntry(relpath_bytes, type, content_len, sha256_digest)
    type: 0=file, 1=symlink
    """
    try:
        st = os.lstat(path)
    except OSError as e:
        raise RuntimeError(f"cannot stat {path!r}: {e}")

    if os.path.islink(path):
        try:
            target = os.readlink(path)
            target_b = os.fsencode(target)
        except OSError as e:
            raise RuntimeError(f"cannot readlink {path!r}: {e}")
        h = hashlib.sha256(target_b)
        return FileEntry(path, 1, len(target_b), h.digest())

    if os.path.isfile(path):
        h = hashlib.sha256()
        tot = 0
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    tot += len(chunk)
                    h.update(chunk)
        except OSError as e:
            raise RuntimeError(f"cannot read file {path!r}: {e}")
        return FileEntry(path, 0, tot, h.digest())

    raise RuntimeError(f"unsupported file type (not regular file or symlink): {path!r}")


# ----- manifest serialization / parsing -----
def build_manifest(root: bytes, entries: List[FileEntry]) -> bytes:
    """
    MANIFEST format:
      entry_count:u64
      For each entry (sorted by relpath bytes):
        path_len:u32 | path_bytes | type:u8 | content_len:u64 | sha256:32
    """
    items = [(relpath_bytes(e.path, root), e.type, e.length, e.digest) for e in entries]
    items.sort(key=lambda x: x[0])

    out = bytearray()
    out += struct.pack("!Q", len(items))
    for rel, t, length, digest in items:
        out += struct.pack("!I", len(rel))
        out += rel
        out += struct.pack("!B", t)
        out += struct.pack("!Q", length)
        assert len(digest) == 32
        out += digest
    return bytes(out)


def parse_manifest(manifest: bytes) -> List[Tuple[bytes, int, int, bytes]]:
    """Parses manifest bytes into a list of entry tuples."""
    p = 0
    if len(manifest) < 8:
        raise ValueError("Manifest too short for entry count.")
    n_entries = struct.unpack_from("!Q", manifest, p)[0]
    p += 8
    parsed = []
    for _ in range(n_entries):
        if p + 4 > len(manifest):
            raise ValueError("Manifest truncated at path length.")
        path_len = struct.unpack_from("!I", manifest, p)[0]
        p += 4
        if p + path_len > len(manifest):
            raise ValueError("Manifest truncated at path.")
        path = manifest[p : p + path_len]
        p += path_len
        if p + 1 > len(manifest):
            raise ValueError("Manifest truncated at type.")
        t = struct.unpack_from("!B", manifest, p)[0]
        p += 1
        if p + 8 > len(manifest):
            raise ValueError("Manifest truncated at content length.")
        length = struct.unpack_from("!Q", manifest, p)[0]
        p += 8
        if p + 32 > len(manifest):
            raise ValueError("Manifest truncated at digest.")
        digest = manifest[p : p + 32]
        p += 32
        parsed.append((path, t, length, digest))
    if p != len(manifest):
        print(
            f"Warning: {len(manifest) - p} trailing bytes in manifest.", file=sys.stderr
        )
    return parsed


# ----- gpg helpers -----
def gpg_detach_sign_bytes(manifest_bytes: bytes, key_id: str | None) -> bytes:
    """Signs bytes with GPG, returning a binary detached signature. Retries up to 3 times on failure."""
    cmd = ["gpg", "--batch", "--yes", "--detach-sign", "--output", "-"]
    if key_id:
        cmd += ["--local-user", key_id]
    
    max_retries = 3
    last_error = None
    
    for attempt in range(max_retries):
        proc = subprocess.run(cmd, input=manifest_bytes, capture_output=True)
        if proc.returncode == 0:
            return proc.stdout
        
        # Store error for potential reporting
        stderr = proc.stderr.decode(errors="ignore").strip()
        last_error = stderr
        
        # If not the last attempt, we'll retry
        if attempt < max_retries - 1:
            import time
            time.sleep(0.5)  # Brief delay before retry
    
    # All retries exhausted
    raise RuntimeError(f"gpg sign failed after {max_retries} attempts: {last_error}")


def get_primary_key_id(fingerprint: str) -> str | None:
    if not fingerprint:
        return None

    # Query GPG for key information using the fingerprint
    cmd = ["gpg", "--with-colons", "--list-keys", fingerprint]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")

    if proc.returncode != 0:
        return None

    # Parse the output to find the primary key (pub line)
    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if parts[0] == "pub":
            # We want the last 16 characters of the fingerprint for the key ID
            if len(parts) > 4 and parts[4]:
                return parts[4]

    if len(fingerprint) >= 16:
        return fingerprint[-16:].upper()

    return None


def gpg_verify_sig(manifest_bytes: bytes, sig_bytes: bytes) -> GpgStatus:
    """Verifies a GPG signature, returning detailed status."""
    with tempfile.NamedTemporaryFile(
        prefix="fsign-m-"
    ) as mf, tempfile.NamedTemporaryFile(prefix="fsign-s-") as sf:
        mf.write(manifest_bytes)
        mf.flush()
        sf.write(sig_bytes)
        sf.flush()

        cmd = ["gpg", "--status-fd=1", "--verify", sf.name, mf.name]
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")

        output = proc.stdout + proc.stderr
        valid = False
        fpr, uid, summary = None, None, "Verification failed."
        primary_key_id = None

        for line in output.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                fpr = parts[2]
                uid_parts = parts[11:]
                uid = " ".join(uid_parts) if uid_parts else None
                valid = True
                summary = "Signature is valid."
                # Get the primary key ID from the fingerprint
                primary_key_id = get_primary_key_id(fpr)
                break

        if not valid:
            summary = output or "GPG verification failed with no output."

        return GpgStatus(valid, fpr, primary_key_id, uid, summary)


# ----- file format write / read -----
def write_fsign(path_fsign: str, manifest_bytes: bytes, sig_bytes: bytes):
    """Writes the .fsign file with header, manifest, and signature."""
    with open(path_fsign, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("!BB", VERSION, FLAGS))
        f.write(struct.pack("!Q", len(manifest_bytes)))
        f.write(manifest_bytes)
        f.write(struct.pack("!I", len(sig_bytes)))
        f.write(sig_bytes)


def read_fsign(path_fsign: str) -> Tuple[bytes, bytes]:
    """Reads manifest and signature from an .fsign file."""
    with open(path_fsign, "rb") as f:
        hdr = f.read(HEADER_LEN)
        if len(hdr) != HEADER_LEN or hdr[:6] != MAGIC:
            raise RuntimeError("Bad header or magic in .fsign file")
        ver, _ = struct.unpack_from("!BB", hdr, 6)
        if ver != VERSION:
            raise RuntimeError(f"Unsupported version: {ver}")

        len_bytes = f.read(8)
        if len(len_bytes) != 8:
            raise RuntimeError("Truncated fsign (manifest length)")
        manifest_len = struct.unpack("!Q", len_bytes)[0]
        manifest = f.read(manifest_len)
        if len(manifest) != manifest_len:
            raise RuntimeError("Truncated fsign (manifest data)")

        len_bytes = f.read(4)
        if len(len_bytes) != 4:
            raise RuntimeError("Truncated fsign (signature length)")
        sig_len = struct.unpack("!I", len_bytes)[0]
        sig = f.read(sig_len)
        if len(sig) != sig_len:
            raise RuntimeError("Truncated fsign (signature data)")

        return manifest, sig


def _show_progress(futures: dict, quiet: bool):
    """Simple text-based progress bar."""
    if quiet or not sys.stdout.isatty():
        return
    total = len(futures)
    for i, _ in enumerate(as_completed(futures)):
        done = i + 1
        pct = (done / total) * 100
        bar = "█" * int(pct / 2)
        print(
            f"\rHashing.. [{bar:<50}] {done}/{total} ({pct:.1f}%)",
            end="",
            file=sys.stdout,
        )
    print("\n", end="")


# ----- create / verify logic -----
def create_fsign(
    root: str,
    quiet: bool,
    out_name: str = ".fsign",
    gpg_key_id: str | None = None,
    workers: int | None = None,
):
    root_b = os.fsencode(os.path.abspath(root))
    
    # Load ignore patterns
    patterns = load_ignore_patterns(root)
    if patterns and not quiet:
        print(f"Loaded {len(patterns)} exclusion pattern(s) from .fsignignore")
    
    if not quiet:
        print("Collecting files...")
    files = list(walk_bytes(root_b, patterns))

    if workers is None:
        workers = os.cpu_count() or 1

    entries: List[FileEntry] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(hash_entry, p): p for p in files}
        _show_progress(futures, quiet)
        for fut in as_completed(futures):
            try:
                entries.append(fut.result())
            except Exception as e:
                raise SystemExit(f"Error processing file: {e}")

    if not quiet:
        print("Building manifest...")
    manifest = build_manifest(root_b, entries)

    if not quiet:
        print("Signing manifest with GPG...")
    try:
        sig = gpg_detach_sign_bytes(manifest, gpg_key_id)
    except Exception as e:
        raise SystemExit(f"GPG signing failed: {e}")

    out_path = os.path.join(root, out_name)
    write_fsign(out_path, manifest, sig)
    if not quiet:
        print(f"Success! Wrote signature to {out_path}")


def verify_fsign(
    root: str,
    quiet: bool,
    fsign_path: str | None = None,
    trusted_key_id: str | None = None,
    workers: int | None = None,
    json_output: bool = False,
) -> bool:
    root_b = os.fsencode(os.path.abspath(root))
    if fsign_path is None:
        fsign_path = os.path.join(root, ".fsign")

    # Load ignore patterns
    patterns = load_ignore_patterns(root)
    if patterns and not quiet:
        print(f"Loaded {len(patterns)} exclusion pattern(s) from .fsignignore")

    try:
        manifest, sig = read_fsign(fsign_path)
    except Exception as e:
        if json_output:
            print(json.dumps({
                "valid": False,
                "error": f"Failed reading {fsign_path}: {e}"
            }))
        else:
            print(f"Error: Failed reading {fsign_path}: {e}", file=sys.stderr)
        return False

    status = gpg_verify_sig(manifest, sig)
    if not status.valid_signature:
        if json_output:
            print(json.dumps({
                "valid": False,
                "signature_valid": False,
                "error": "GPG signature is INVALID",
                "details": status.summary
            }))
        else:
            print(
                f"Error: GPG signature is INVALID.  Details:\n{status.summary}",
                file=sys.stderr,
            )
        return False

    if not quiet and not json_output:
        print("OK: GPG signature is valid.")
        if status.user_id:
            print(f"  Signed by:      {status.user_id}")
        if status.fingerprint:
            print(f"  Fingerprint:    {status.fingerprint}")

    if trusted_key_id:
        if not status.primary_key_id:
            err_msg = "Signature is valid, but primary key ID could not be extracted to verify against the trusted key."
            if json_output:
                print(json.dumps({
                    "valid": False,
                    "signature_valid": True,
                    "key_check_failed": True,
                    "error": err_msg
                }))
            else:
                print(f"Error: {err_msg}", file=sys.stderr)
            return False

        normalized_trusted = trusted_key_id.replace(" ", "").upper()
        normalized_primary = status.primary_key_id.replace(" ", "").upper()

        if normalized_trusted.endswith(
            normalized_primary
        ) or normalized_primary.endswith(normalized_trusted):
            if not quiet and not json_output:
                print("OK: Primary key ID matches the trusted key.")
        else:
            if json_output:
                print(json.dumps({
                    "valid": False,
                    "signature_valid": True,
                    "key_mismatch": True,
                    "expected_key": normalized_trusted,
                    "got_key": normalized_primary
                }))
            else:
                print(f"Error: Primary key ID mismatch!", file=sys.stderr)
                print(f"  Expected: {normalized_trusted}", file=sys.stderr)
                sps = abs(len(normalized_trusted) - len(normalized_primary)) * " "
                print(
                    f"  Got:      {sps}{normalized_primary}",
                    file=sys.stderr,
                )
            return False

    try:
        parsed = parse_manifest(manifest)
    except ValueError as e:
        if json_output:
            print(json.dumps({
                "valid": False,
                "error": f"Failed to parse manifest: {e}"
            }))
        else:
            print(f"Error: Failed to parse manifest: {e}", file=sys.stderr)
        return False

    if not quiet and not json_output:
        print("Re-calculating filesystem state for verification...")
    files = list(walk_bytes(root_b, patterns))

    if workers is None:
        workers = os.cpu_count() or 1

    entries: List[FileEntry] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(hash_entry, p): p for p in files}
        _show_progress(futures, quiet or json_output)
        for fut in as_completed(futures):
            try:
                entries.append(fut.result())
            except Exception as e:
                if json_output:
                    print(json.dumps({
                        "valid": False,
                        "error": f"Error hashing file during verify: {e}"
                    }))
                else:
                    print(f"\nError hashing file during verify: {e}", file=sys.stderr)
                return False

    rebuilt_manifest = build_manifest(root_b, entries)

    if rebuilt_manifest == manifest:
        if json_output:
            result = {
                "valid": True,
                "signature_valid": True,
                "filesystem_matches": True,
                "fingerprint": status.fingerprint,
                "signer": status.user_id
            }
            if status.primary_key_id:
                result["key_id"] = status.primary_key_id
            print(json.dumps(result, indent=2))
        elif not quiet:
            print("\nVALIDATION:  OK.  Filesystem state matches the signature.")
        return True

    # Validation failed - collect differences
    disk_map = {
        relpath_bytes(e.path, root_b): (e.type, e.length, e.digest) for e in entries
    }
    man_map = {entry[0]: entry[1:] for entry in parsed}

    missing_files = man_map.keys() - disk_map.keys()
    extra_files = disk_map.keys() - man_map.keys()
    common_files = man_map.keys() & disk_map.keys()

    mismatches = []
    for k in sorted(common_files):
        m_t, m_l, m_d = man_map[k]
        d_t, d_l, d_d = disk_map[k]
        diffs = []
        if m_t != d_t:
            diffs.append({"field": "type", "manifest": m_t, "disk": d_t})
        if m_l != d_l:
            diffs.append({"field": "length", "manifest": m_l, "disk": d_l})
        if m_d != d_d:
            diffs.append({"field": "hash", "manifest": m_d.hex(), "disk": d_d.hex()})
        if diffs:
            mismatches.append({
                "file": k.decode(errors='replace'),
                "differences": diffs
            })

    if json_output:
        print(json.dumps({
            "valid": False,
            "signature_valid": True,
            "filesystem_matches": False,
            "missing_files": [f.decode(errors='replace') for f in sorted(missing_files)],
            "extra_files": [f.decode(errors='replace') for f in sorted(extra_files)],
            "mismatched_files": mismatches
        }, indent=2))
    else:
        print(
            "\nVALIDATION:  FAILED. Filesystem state does not match the signature.",
            file=sys.stderr,
        )
        for f in sorted(missing_files):
            print(f"  MISSING: {f.decode(errors='replace')}", file=sys.stderr)
        for f in sorted(extra_files):
            print(f"  EXTRA:   {f.decode(errors='replace')}", file=sys.stderr)
        for item in mismatches:
            diff_strs = []
            for d in item["differences"]:
                if d["field"] == "hash":
                    diff_strs.append("content hash")
                else:
                    diff_strs.append(f"{d['field']} (manifest:{d['manifest']}, disk:{d['disk']})")
            print(
                f"  MISMATCH: {item['file']} ({', '.join(diff_strs)})",
                file=sys.stderr,
            )

    return False


def list_fsign(fsign_path: str, json_output: bool = False) -> bool:
    """Display information about a .fsign file without verification."""
    try:
        manifest, sig = read_fsign(fsign_path)
    except Exception as e:
        if json_output:
            print(json.dumps({"error": f"Failed reading {fsign_path}: {e}"}))
        else:
            print(f"Error: Failed reading {fsign_path}: {e}", file=sys.stderr)
        return False
    
    # Parse manifest
    try:
        parsed = parse_manifest(manifest)
    except ValueError as e:
        if json_output:
            print(json.dumps({"error": f"Failed to parse manifest: {e}"}))
        else:
            print(f"Error: Failed to parse manifest: {e}", file=sys.stderr)
        return False
    
    # Get GPG signature info (without full verification)
    status = gpg_verify_sig(manifest, sig)
    
    if json_output:
        files_info = []
        for path, typ, length, digest in parsed:
            files_info.append({
                "path": path.decode(errors='replace'),
                "type": "file" if typ == 0 else "symlink",
                "size": length,
                "sha256": digest.hex()
            })
        
        output = {
            "file_count": len(parsed),
            "signature_valid": status.valid_signature,
            "files": files_info
        }
        
        if status.fingerprint:
            output["fingerprint"] = status.fingerprint
        if status.user_id:
            output["signer"] = status.user_id
        if status.primary_key_id:
            output["key_id"] = status.primary_key_id
        
        print(json.dumps(output, indent=2))
    else:
        print(f"Signature file: {fsign_path}")
        print(f"File count: {len(parsed)}")
        print(f"Signature valid: {'Yes' if status.valid_signature else 'No'}")
        
        if status.valid_signature:
            if status.user_id:
                print(f"Signed by: {status.user_id}")
            if status.fingerprint:
                print(f"Fingerprint: {status.fingerprint}")
            if status.primary_key_id:
                print(f"Key ID: {status.primary_key_id}")
        
        print(f"\nFiles in manifest:")
        for path, typ, length, digest in parsed:
            type_str = "file" if typ == 0 else "symlink"
            path_str = path.decode(errors='replace')
            print(f"  [{type_str}] {path_str} ({length} bytes)")
    
    return True


# ----- CLI -----
def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="Create and verify GPG-signed filesystem signatures.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Directory to create/verify signature for (default: current directory)",
    )

    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--create",
        action="store_true",
        help="Create a .fsign file in the root directory",
    )
    group.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="Verify the .fsign file in the root directory",
    )
    group.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List contents and signature info of a .fsign file",
    )

    ap.add_argument(
        "-k",
        "--key-id",
        metavar="KEYID",
        help="GPG Key ID (or email, name) to sign with (for --create)",
    )
    ap.add_argument(
        "-t",
        "--trust-key",
        metavar="KEYID",
        help="GPG primary key ID to require for a valid signature (for --verify)\n"
        "Accepts short (8-char) or long (16-char) key IDs",
    )
    ap.add_argument(
        "-f",
        "--fsign-path",
        metavar="PATH",
        help="Path to .fsign file (default: <root>/.fsign)",
    )
    ap.add_argument(
        "-w",
        "--workers",
        type=int,
        metavar="N",
        help="Number of parallel hashing workers (default: CPU count)",
    )
    ap.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress and informational output",
    )
    ap.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results in JSON format (for --verify and --list)",
    )

    args = ap.parse_args()

    try:
        if args.create:
            create_fsign(
                args.root, args.quiet, gpg_key_id=args.key_id, workers=args.workers
            )
        elif args.list:
            # For list command, use fsign_path if provided, otherwise default
            fsign_path = args.fsign_path if args.fsign_path else os.path.join(args.root, ".fsign")
            ok = list_fsign(fsign_path, json_output=args.json)
            sys.exit(0 if ok else 1)
        else:
            ok = verify_fsign(
                args.root,
                args.quiet,
                fsign_path=args.fsign_path,
                trusted_key_id=args.trust_key,
                workers=args.workers,
                json_output=args.json,
            )
            sys.exit(0 if ok else 1)
    except (RuntimeError, SystemExit, KeyboardInterrupt) as e:
        if isinstance(e, KeyboardInterrupt):
            print("\nOperation cancelled by user.", file=sys.stderr)
            sys.exit(130)
        if e.args:
            if isinstance(e, SystemExit):
                if str(e) != "0":
                    print(f"Error: {e}", file=sys.stderr)
                else:
                    sys.exit(0)
            else:
                print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
