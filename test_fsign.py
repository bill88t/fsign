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
