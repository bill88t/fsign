# FSIGN

A utility for signing a folder/filesystem with an OpenPGP GPG key.

## Features

- **GPG-based signatures**: Uses OpenPGP GPG for cryptographic signing and verification
- **Parallel hashing**: Multi-threaded file hashing for fast performance
- **Pattern-based exclusions**: `.fsignignore` file support (similar to `.gitignore`)
- **JSON output**: Machine-readable output for scripting / automation
- **List/info command**: View signature details without full verification
- **Symlink support**: Handles both regular files and symbolic links
- **Detailed verification**: Reports missing, extra, and modified files

## Installation

```bash
# Clone repository
git clone https://github.com/bill88t/fsign
cd fsign

# Make executable
chmod +x fsign.py

# Optional: Install to system
sudo cp fsign.py /usr/bin/fsign
```

## Usage

### Create a signature

```bash
# Sign current directory
fsign.py -c

# Sign specific directory
fsign.py -c /path/to/directory

# Sign with specific GPG key
fsign.py -c -k user@example.com

# Quiet mode (suppress progress output)
fsign.py -c -q
```

### Verify a signature

```bash
# Verify current directory
fsign.py -v

# Verify specific directory
fsign.py -v /path/to/directory

# Require specific GPG key
fsign.py -v -t KEYID

# JSON output (for automation/CI)
fsign.py -v -j
```

### List signature contents

```bash
# Show signature info and file list
fsign.py -l

# List with JSON output
fsign.py -l -j

# List specific .fsign file
fsign.py -l -f /path/to/.fsign
```

## Pattern-based Exclusions

Create a `.fsignignore` file in the root directory to exclude files from signing:

```
# Comments start with #
*.log
*.tmp
__pycache__/
.git/
node_modules/
*.pyc
cache/
build/
dist/
```

**Security Note**: The `.fsignignore` file itself is **included** in the signature to prevent tampering. If an attacker modifies or adds a `.fsignignore` file after signing, verification will fail.

Patterns support:
- Glob patterns: `*.log`, `*.tmp`
- Directory patterns: `__pycache__/`, `.git/`
- Path patterns: `build/*`, `cache/**`

## JSON Output Format

### Successful verification:
```json
{
  "valid": true,
  "signature_valid": true,
  "filesystem_matches": true,
  "fingerprint": "ABCD1234...",
  "signer": "User Name <email@example.com>",
  "key_id": "ABCD1234"
}
```

### Failed verification:
```json
{
  "valid": false,
  "signature_valid": true,
  "filesystem_matches": false,
  "missing_files": ["path/to/missing.txt"],
  "extra_files": ["path/to/extra.txt"],
  "mismatched_files": [
    {
      "file": "path/to/modified.txt",
      "differences": [
        {"field": "hash", "manifest": "abc123...", "disk": "def456..."}
      ]
    }
  ]
}
```

## Advanced Options

```bash
# Custom number of worker threads
fsign.py -c -w 8

# Custom .fsign file location
fsign.py -c -f /tmp/my-signature.fsign

# Combine options
fsign.py -v -t KEYID -j -q
```

## Exit Codes

- `0`: Success
- `1`: Verification failed or error occurred
- `130`: Operation cancelled by user (Ctrl+C)

## File Format

The `.fsign` file format:
- Binary format with magic header `FSIG1\0`
- Contains SHA-256 hashes of all files
- Includes GPG detached signature
- Version 1 format (extensible for future versions)

## Security Features

- **Automatic GPG retry**: 3 automatic retry attempts for transient GPG failures
- **Key verification**: Optional trusted key ID checking
- **Cryptographic hashing**: SHA-256 for file integrity
- **Detached signatures**: GPG signature separate from manifest data

## Development

### Running Tests

```bash
# Install development dependencies
pip3 install -r requirements-dev.txt

# Run tests
pytest test_fsign.py -v

# Run with coverage
pytest test_fsign.py --cov=fsign --cov-report=html
```

## License

See LICENSE file for details.

