#!/usr/bin/env python3
"""
Comprehensive test suite for fsign.
"""

import os
import sys
import tempfile
import shutil
import subprocess
import struct
import json
from pathlib import Path

import pytest

# Import the fsign module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fsign


class TestBasicOperations:
    """Test basic fsign operations."""

    def test_walk_bytes_excludes_fsign(self, tmp_path):
        """Test that walk_bytes excludes .fsign files."""
        # Create test structure
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        (tmp_path / ".fsign").write_text("signature")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("content3")
        (subdir / ".fsign").write_text("signature2")

        root_b = os.fsencode(str(tmp_path))
        files = list(fsign.walk_bytes(root_b))
        
        # Should find 3 files, excluding both .fsign files
        assert len(files) == 3
        filenames = [os.path.basename(f) for f in files]
        assert b".fsign" not in filenames

    def test_hash_entry_regular_file(self, tmp_path):
        """Test hashing a regular file."""
        test_file = tmp_path / "test.txt"
        content = b"Hello, World!"
        test_file.write_bytes(content)

        entry = fsign.hash_entry(os.fsencode(str(test_file)))
        
        assert entry.type == 0  # regular file
        assert entry.length == len(content)
        assert len(entry.digest) == 32  # SHA-256

    def test_hash_entry_symlink(self, tmp_path):
        """Test hashing a symlink."""
        target = tmp_path / "target.txt"
        target.write_text("target content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        entry = fsign.hash_entry(os.fsencode(str(link)))
        
        assert entry.type == 1  # symlink
        assert entry.length > 0
        assert len(entry.digest) == 32

    def test_relpath_bytes(self, tmp_path):
        """Test relpath_bytes function."""
        root = tmp_path / "root"
        root.mkdir()
        subfile = root / "sub" / "file.txt"
        subfile.parent.mkdir(parents=True)
        subfile.write_text("content")

        root_b = os.fsencode(str(root))
        path_b = os.fsencode(str(subfile))
        
        rel = fsign.relpath_bytes(path_b, root_b)
        assert b"sub" in rel
        assert b"file.txt" in rel


class TestManifestOperations:
    """Test manifest building and parsing."""

    def test_build_and_parse_manifest_roundtrip(self, tmp_path):
        """Test that building and parsing a manifest works correctly."""
        # Create test files
        (tmp_path / "file1.txt").write_bytes(b"content1")
        (tmp_path / "file2.txt").write_bytes(b"content2")

        root_b = os.fsencode(str(tmp_path))
        files = list(fsign.walk_bytes(root_b))
        entries = [fsign.hash_entry(f) for f in files]
        
        # Build manifest
        manifest = fsign.build_manifest(root_b, entries)
        
        # Parse it back
        parsed = fsign.parse_manifest(manifest)
        
        assert len(parsed) == len(entries)
        # Check that parsing returns correct structure
        for path, typ, length, digest in parsed:
            assert isinstance(path, bytes)
            assert isinstance(typ, int)
            assert isinstance(length, int)
            assert len(digest) == 32

    def test_manifest_sorted_by_path(self, tmp_path):
        """Test that manifest entries are sorted by path."""
        (tmp_path / "zebra.txt").write_bytes(b"z")
        (tmp_path / "alpha.txt").write_bytes(b"a")
        (tmp_path / "beta.txt").write_bytes(b"b")

        root_b = os.fsencode(str(tmp_path))
        files = list(fsign.walk_bytes(root_b))
        entries = [fsign.hash_entry(f) for f in files]
        
        manifest = fsign.build_manifest(root_b, entries)
        parsed = fsign.parse_manifest(manifest)
        
        paths = [p[0] for p in parsed]
        assert paths == sorted(paths)

    def test_parse_manifest_invalid_short(self):
        """Test that parsing invalid manifest raises error."""
        with pytest.raises(ValueError, match="too short"):
            fsign.parse_manifest(b"short")

    def test_parse_manifest_truncated(self):
        """Test parsing truncated manifest."""
        # Create valid header with 1 entry but incomplete data
        manifest = struct.pack("!Q", 1) + struct.pack("!I", 100)  # Missing rest
        with pytest.raises(ValueError, match="truncated"):
            fsign.parse_manifest(manifest)


class TestFileFormat:
    """Test .fsign file format operations."""

    def test_write_and_read_fsign(self, tmp_path):
        """Test writing and reading .fsign file."""
        fsign_path = tmp_path / "test.fsign"
        manifest = b"test manifest content"
        signature = b"test signature"

        fsign.write_fsign(str(fsign_path), manifest, signature)
        
        read_manifest, read_sig = fsign.read_fsign(str(fsign_path))
        
        assert read_manifest == manifest
        assert read_sig == signature

    def test_read_fsign_bad_magic(self, tmp_path):
        """Test reading file with bad magic."""
        bad_file = tmp_path / "bad.fsign"
        bad_file.write_bytes(b"WRONG!" + struct.pack("!BB", 1, 0))
        
        with pytest.raises(RuntimeError, match="Bad header or magic"):
            fsign.read_fsign(str(bad_file))

    def test_read_fsign_wrong_version(self, tmp_path):
        """Test reading file with unsupported version."""
        bad_file = tmp_path / "bad.fsign"
        bad_file.write_bytes(fsign.MAGIC + struct.pack("!BB", 99, 0))
        
        with pytest.raises(RuntimeError, match="Unsupported version"):
            fsign.read_fsign(str(bad_file))


class TestGPGOperations:
    """Test GPG signing and verification operations."""

    @pytest.fixture
    def gpg_available(self):
        """Check if GPG is available."""
        try:
            result = subprocess.run(
                ["gpg", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pytest.skip("GPG not available")

    @pytest.fixture
    def test_gpg_key(self, gpg_available, tmp_path):
        """Create a test GPG key."""
        gpg_home = tmp_path / "gpg_home"
        gpg_home.mkdir(mode=0o700)
        
        # Create a batch file for key generation
        batch_content = """
            %no-protection
            Key-Type: RSA
            Key-Length: 2048
            Name-Real: Test User
            Name-Email: test@example.com
            Expire-Date: 0
            %commit
        """
        
        batch_file = tmp_path / "keygen_batch"
        batch_file.write_text(batch_content)
        
        try:
            subprocess.run(
                ["gpg", "--homedir", str(gpg_home), "--batch", "--gen-key", str(batch_file)],
                capture_output=True,
                timeout=30,
                check=True
            )
            
            # Get the key ID
            result = subprocess.run(
                ["gpg", "--homedir", str(gpg_home), "--list-keys", "--with-colons"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            key_id = None
            for line in result.stdout.splitlines():
                if line.startswith("fpr:"):
                    key_id = line.split(":")[9]
                    break
            
            return str(gpg_home), key_id
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pytest.skip("Could not generate test GPG key")

    def test_get_primary_key_id_invalid(self):
        """Test get_primary_key_id with invalid fingerprint."""
        result = fsign.get_primary_key_id("INVALID_FINGERPRINT_12345")
        # Should return None or extracted ID
        assert result is None or len(result) == 16


class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.fixture
    def test_directory(self, tmp_path):
        """Create a test directory structure."""
        root = tmp_path / "test_root"
        root.mkdir()
        
        # Create various files
        (root / "file1.txt").write_text("Content of file 1")
        (root / "file2.txt").write_text("Content of file 2")
        
        subdir = root / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("Content of file 3")
        
        # Create a symlink
        link = root / "link.txt"
        link.symlink_to(root / "file1.txt")
        
        return root

    def test_create_and_verify_mock(self, test_directory, monkeypatch):
        """Test create and verify with mocked GPG operations."""
        # Mock GPG signing to avoid needing actual GPG setup
        def mock_sign(manifest, key_id):
            return b"MOCK_SIGNATURE_" + manifest[:10]
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test User <test@example.com>",
                summary="Signature is valid."
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(test_directory), quiet=True)
        
        # Verify it exists
        fsign_file = test_directory / ".fsign"
        assert fsign_file.exists()
        
        # Verify the signature
        result = fsign.verify_fsign(str(test_directory), quiet=True)
        assert result is True

    def test_verify_detects_modified_file(self, test_directory, monkeypatch):
        """Test that verify detects when a file is modified."""
        def mock_sign(manifest, key_id):
            return b"MOCK_SIGNATURE"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(test_directory), quiet=True)
        
        # Modify a file
        (test_directory / "file1.txt").write_text("MODIFIED CONTENT")
        
        # Verify should fail
        result = fsign.verify_fsign(str(test_directory), quiet=True)
        assert result is False

    def test_verify_detects_missing_file(self, test_directory, monkeypatch):
        """Test that verify detects when a file is missing."""
        def mock_sign(manifest, key_id):
            return b"MOCK_SIGNATURE"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(test_directory), quiet=True)
        
        # Remove a file
        (test_directory / "file1.txt").unlink()
        
        # Verify should fail
        result = fsign.verify_fsign(str(test_directory), quiet=True)
        assert result is False

    def test_verify_detects_extra_file(self, test_directory, monkeypatch):
        """Test that verify detects when an extra file is added."""
        def mock_sign(manifest, key_id):
            return b"MOCK_SIGNATURE"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(test_directory), quiet=True)
        
        # Add a new file
        (test_directory / "new_file.txt").write_text("NEW CONTENT")
        
        # Verify should fail
        result = fsign.verify_fsign(str(test_directory), quiet=True)
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestIgnorePatterns:
    """Test .fsignignore pattern matching."""

    def test_load_ignore_patterns(self, tmp_path):
        """Test loading patterns from .fsignignore file."""
        ignore_file = tmp_path / ".fsignignore"
        ignore_file.write_text("*.log\n__pycache__/\n# comment\n\n.git/")
        
        patterns = fsign.load_ignore_patterns(str(tmp_path))
        
        assert "*.log" in patterns
        assert "__pycache__/" in patterns
        assert ".git/" in patterns
        assert "# comment" not in patterns
        assert "" not in patterns

    def test_should_exclude_glob_pattern(self, tmp_path):
        """Test glob pattern exclusion."""
        root_b = os.fsencode(str(tmp_path))
        test_file = tmp_path / "test.log"
        test_file.write_text("log")
        
        patterns = ["*.log"]
        assert fsign.should_exclude(os.fsencode(str(test_file)), root_b, patterns)

    def test_should_exclude_directory_pattern(self, tmp_path):
        """Test directory pattern exclusion."""
        root_b = os.fsencode(str(tmp_path))
        subdir = tmp_path / "__pycache__"
        subdir.mkdir()
        test_file = subdir / "cache.pyc"
        test_file.write_text("cache")
        
        patterns = ["__pycache__/"]
        assert fsign.should_exclude(os.fsencode(str(test_file)), root_b, patterns)

    def test_walk_bytes_with_patterns(self, tmp_path):
        """Test that walk_bytes respects ignore patterns."""
        # Create test structure
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.log").write_text("log content")
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "cache.pyc").write_text("cache")
        
        # Create ignore file
        ignore_file = tmp_path / ".fsignignore"
        ignore_file.write_text("*.log\n__pycache__/")
        
        patterns = fsign.load_ignore_patterns(str(tmp_path))
        root_b = os.fsencode(str(tmp_path))
        files = list(fsign.walk_bytes(root_b, patterns))
        
        # Should only find file1.txt (not .log, not cache.pyc)
        filenames = [os.path.basename(f).decode() for f in files]
        assert "file1.txt" in filenames
        assert "file2.log" not in filenames
        assert "cache.pyc" not in filenames

    def test_create_with_ignore_patterns(self, tmp_path, monkeypatch):
        """Test creating signature with .fsignignore."""
        # Setup
        (tmp_path / "include.txt").write_text("include this")
        (tmp_path / "exclude.log").write_text("exclude this")
        ignore_file = tmp_path / ".fsignignore"
        ignore_file.write_text("*.log")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # Read and verify manifest doesn't include .log file
        manifest, _ = fsign.read_fsign(str(tmp_path / ".fsign"))
        parsed = fsign.parse_manifest(manifest)
        
        paths = [p[0].decode() for p in parsed]
        assert any("include.txt" in p for p in paths)
        assert not any("exclude.log" in p for p in paths)


class TestJSONOutput:
    """Test JSON output format."""

    def test_verify_json_success(self, tmp_path, monkeypatch):
        """Test JSON output for successful verification."""
        # Setup
        (tmp_path / "test.txt").write_text("test content")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test User <test@example.com>",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # Capture JSON output
        import io
        import contextlib
        
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = fsign.verify_fsign(
                str(tmp_path), 
                quiet=True, 
                json_output=True
            )
        
        assert result is True
        json_str = output.getvalue()
        data = json.loads(json_str)
        
        assert data["valid"] is True
        assert data["signature_valid"] is True
        assert data["filesystem_matches"] is True
        assert "fingerprint" in data
        assert "signer" in data

    def test_verify_json_modified_file(self, tmp_path, monkeypatch):
        """Test JSON output when file is modified."""
        # Setup
        (tmp_path / "test.txt").write_text("original")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # Modify file
        (tmp_path / "test.txt").write_text("modified")
        
        # Verify with JSON
        import io
        import contextlib
        
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = fsign.verify_fsign(
                str(tmp_path),
                quiet=True,
                json_output=True
            )
        
        assert result is False
        data = json.loads(output.getvalue())
        
        assert data["valid"] is False
        assert data["signature_valid"] is True
        assert data["filesystem_matches"] is False
        assert "mismatched_files" in data
        assert len(data["mismatched_files"]) == 1

    def test_verify_json_invalid_signature(self, tmp_path, monkeypatch):
        """Test JSON output with invalid signature."""
        # Setup
        (tmp_path / "test.txt").write_text("content")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        def mock_verify_fail(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=False,
                fingerprint=None,
                primary_key_id=None,
                user_id=None,
                summary="Signature verification failed"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # Mock to fail verification
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify_fail)
        
        # Verify with JSON
        import io
        import contextlib
        
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = fsign.verify_fsign(
                str(tmp_path),
                quiet=True,
                json_output=True
            )
        
        assert result is False
        data = json.loads(output.getvalue())
        
        assert data["valid"] is False
        assert data["signature_valid"] is False
        assert "error" in data


class TestGPGRetry:
    """Test GPG signing retry logic."""

    def test_gpg_sign_succeeds_on_first_attempt(self, monkeypatch):
        """Test that signing succeeds on first attempt."""
        call_count = 0
        
        def mock_run(cmd, input, capture_output):
            nonlocal call_count
            call_count += 1
            
            class MockProc:
                returncode = 0
                stdout = b"SIGNATURE_DATA"
                stderr = b""
            
            return MockProc()
        
        monkeypatch.setattr(subprocess, "run", mock_run)
        
        result = fsign.gpg_detach_sign_bytes(b"test_data", None)
        
        assert result == b"SIGNATURE_DATA"
        assert call_count == 1

    def test_gpg_sign_retries_on_failure(self, monkeypatch):
        """Test that signing retries up to 3 times."""
        call_count = 0
        
        def mock_run(cmd, input, capture_output):
            nonlocal call_count
            call_count += 1
            
            class MockProc:
                returncode = 1
                stdout = b""
                stderr = b"GPG error"
            
            return MockProc()
        
        # Mock time.sleep to avoid actual delays in tests
        monkeypatch.setattr("time.sleep", lambda x: None)
        monkeypatch.setattr(subprocess, "run", mock_run)
        
        with pytest.raises(RuntimeError, match="failed after 3 attempts"):
            fsign.gpg_detach_sign_bytes(b"test_data", None)
        
        assert call_count == 3

    def test_gpg_sign_succeeds_on_retry(self, monkeypatch):
        """Test that signing succeeds on second attempt."""
        call_count = 0
        
        def mock_run(cmd, input, capture_output):
            nonlocal call_count
            call_count += 1
            
            class MockProc:
                if call_count == 1:
                    returncode = 1
                    stdout = b""
                    stderr = b"Temporary error"
                else:
                    returncode = 0
                    stdout = b"SIGNATURE_DATA"
                    stderr = b""
            
            return MockProc()
        
        monkeypatch.setattr("time.sleep", lambda x: None)
        monkeypatch.setattr(subprocess, "run", mock_run)
        
        result = fsign.gpg_detach_sign_bytes(b"test_data", None)
        
        assert result == b"SIGNATURE_DATA"
        assert call_count == 2  # Failed once, succeeded on second try


class TestListCommand:
    """Test the list/info command."""

    def test_list_basic(self, tmp_path, monkeypatch):
        """Test listing signature file contents."""
        # Setup
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test User <test@example.com>",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # List it
        fsign_path = str(tmp_path / ".fsign")
        result = fsign.list_fsign(fsign_path, json_output=False)
        assert result is True

    def test_list_json_output(self, tmp_path, monkeypatch):
        """Test JSON output for list command."""
        # Setup
        (tmp_path / "test.txt").write_text("test")
        
        def mock_sign(manifest, key_id):
            return b"MOCK_SIG"
        
        def mock_verify(manifest, sig):
            return fsign.GpgStatus(
                valid_signature=True,
                fingerprint="ABCD1234",
                primary_key_id="ABCD1234",
                user_id="Test User",
                summary="Valid"
            )
        
        monkeypatch.setattr(fsign, "gpg_detach_sign_bytes", mock_sign)
        monkeypatch.setattr(fsign, "gpg_verify_sig", mock_verify)
        
        # Create signature
        fsign.create_fsign(str(tmp_path), quiet=True)
        
        # List with JSON output
        import io
        import contextlib
        
        output = io.StringIO()
        fsign_path = str(tmp_path / ".fsign")
        
        with contextlib.redirect_stdout(output):
            result = fsign.list_fsign(fsign_path, json_output=True)
        
        assert result is True
        data = json.loads(output.getvalue())
        
        assert "file_count" in data
        assert data["file_count"] > 0
        assert "files" in data
        assert data["signature_valid"] is True
        assert "fingerprint" in data

    def test_list_invalid_file(self, tmp_path):
        """Test listing non-existent file."""
        result = fsign.list_fsign(str(tmp_path / "nonexistent.fsign"), json_output=False)
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

