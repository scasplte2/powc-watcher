# PoWC-Watcher (Proof-of-Work-Content Watcher)

Automated file monitoring and blockchain notarization using the Digital Evidence Metagraph. When files are saved, PoWC-Watcher automatically computes cryptographic fingerprints (SHA-512), signs them using SECP256k1, and submits them to the Digital Evidence API for immutable timestamping on the Constellation Network.

## Features

- **Automatic File Watching**: Uses `inotifywait` to detect file saves (`CLOSE_WRITE` events)
- **Cryptographic Signing**: SECP256K1_RFC8785_V1 algorithm with RFC 8785 JSON canonicalization
- **SHA-512 File Hashing**: Enhanced security with larger hash domain
- **Blockchain Notarization**: Timestamped, immutable proofs stored on Constellation Network
- **Sidecar Proof Files**: Each file gets a `.proof.json` with full audit trail
- **Key Management**: Auto-generate or reuse secp256k1 private keys
- **API Integration**: Direct submission to Digital Evidence Metagraph

## Architecture

```
File Save → inotify (CLOSE_WRITE) → SHA512 Hash → Sign (Python) → API Submit → .proof.json Sidecar
```

### What Triggers inotify?

- ✅ **CLOSE_WRITE**: File opened for writing is closed (Photoshop, editors, etc.)
- ✅ **Application saves**: Any program that writes and closes files
- ❌ **Background OS operations**: atime updates, metadata changes
- ❌ **Partial writes**: Only fires when file is fully written and closed

## Installation

### 1. Install System Dependencies

```bash
# Ubuntu/Debian/Pop!_OS
sudo apt-get update
sudo apt-get install inotify-tools jq curl python3 python3-pip python3-venv

# Verify installation
inotifywait --version
jq --version
python3 --version
```

### 2. Install Python Dependencies

**Option A: Virtual Environment (Recommended)**

```bash
# Create and activate venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate
deactivate
```

**Option B: Global Installation**

```bash
pip install ecdsa rfc8785
```

**Note:** The watcher script automatically detects and uses `./venv/bin/python3` if present, otherwise falls back to global `python3`.

### 3. Clone and Configure

```bash
cd /home/scas/git/powc-watcher

# Run setup script (handles dependencies and config)
./setup.sh

# Or manually:
# Copy example config
cp config/powc.conf.example config/powc.conf

# Edit configuration with your credentials
nano config/powc.conf
```

### 4. Configure Your Credentials

Edit `config/powc.conf`:

```bash
# Required: Get these from Constellation Network
ORG_ID=550e8400-e29b-41d4-a716-446655440000
TENANT_ID=123e4567-e89b-12d3-a456-426614174000
API_KEY=your-api-key-here

# Optional: Reuse an existing secp256k1 private key
# PRIVATE_KEY=<64-character-hex-string>

# Paths to watch (comma-separated)
WATCH_PATHS=./watched_files

# API endpoint
API_BASE_URL=https://de-api.constellationnetwork.io/v1
```

## Usage

### Start the Watcher

```bash
# The script auto-detects venv if present
./powc-watcher.sh
```

Output:
```
[INFO] PoWC-Watcher - Proof-of-Work-Content File Notarization
[INFO] Using existing private key from ./config/private_key.txt
[INFO] Starting PoWC-Watcher...
[INFO] Organization: 550e8400-e29b-41d4-a716-446655440000
[INFO] Tenant: 123e4567-e89b-12d3-a456-426614174000
[INFO] Watching: ./watched_files
[SUCCESS] Watcher is running. Press Ctrl+C to stop.
```

### Test It

```bash
# In another terminal, create/edit a file
echo "Hello, blockchain!" > watched_files/test.txt

# The watcher will automatically:
# 1. Detect the file save
# 2. Hash the content (SHA-512)
# 3. Sign the fingerprint
# 4. Submit to API
# 5. Create test.txt.proof.json
```

### View Proof Sidecar

```bash
cat watched_files/test.txt.proof.json | jq
```

Example output:
```json
{
  "version": "1.0",
  "file": "test.txt",
  "entries": [
    {
      "index": 0,
      "timestamp": "2025-10-01T22:30:45.123Z",
      "documentId": "watched_files/test.txt",
      "documentRef": "abc123...def456",
      "fingerprintHash": "789abc...012def",
      "attestation": {
        "content": { /* FingerprintValue */ },
        "proofs": [{
          "id": "public-key-hex",
          "signature": "signature-der-hex",
          "algorithm": "SECP256K1_RFC8785_V1"
        }]
      },
      "apiReceipt": { /* API response */ },
      "prev": null,
      "status": "success"
    }
  ]
}
```

## How It Works

### 1. File Monitoring

Uses `inotifywait` in monitor mode (`-m`) watching for `close_write` events:

```bash
inotifywait -m -e close_write -r ./watched_files
```

Only fires when applications **save and close** files (not on partial writes).

### 2. Cryptographic Signing

Follows the **SECP256K1_RFC8785_V1** algorithm:

1. Hash file content with **SHA-512** → `documentRef`
2. Create `FingerprintValue` JSON (orgId, tenantId, eventId, documentRef, timestamp, etc.)
3. Canonicalize JSON using RFC 8785
4. SHA-256 hash of canonical JSON
5. Convert hash to hex string, then to UTF-8 bytes
6. SHA-512 of hex bytes, truncate to 32 bytes
7. Sign with ECDSA/secp256k1 (DER encoded)

See `src/powc_signer.py:_compute_signature()` for implementation.

### 3. Key Management

**On first run:**
- Generates new secp256k1 private key
- Saves to `config/private_key.txt` (chmod 600)
- Prints key to console for adding to config

**To reuse key:**
- Add `PRIVATE_KEY=<hex>` to `config/powc.conf`
- Or keep `config/private_key.txt` (auto-loaded)

### 4. Sidecar Files

Each monitored file gets a `.proof.json` sidecar:

- **Append-only**: New entries added to `entries[]` array
- **Chain structure**: Each entry links to previous via `prev` hash
- **Full audit trail**: Contains attestation + API receipt
- **Portable**: Can be verified offline or via API

### 5. API Submission

```bash
POST https://de-api.constellationnetwork.io/v1/fingerprints
Headers:
  X-API-Key: <your-api-key>
  Content-Type: application/json
Body:
  {
    "attestation": { /* SignedFingerprint */ },
    "metadata": { "hash": "...", "tags": {...} }
  }
```

Response includes fingerprint status:
- `NEW`: Just submitted
- `PENDING_COMMITMENT`: Being processed
- `FINALIZED_COMMITMENT`: On blockchain

View in explorer: `https://digitalevidence.constellationnetwork.io/fingerprint/<hash>`

## Directory Structure

```
powc-watcher/
├── powc-watcher.sh          # Main bash orchestrator
├── src/
│   └── powc_signer.py       # Python signing helper
├── config/
│   ├── powc.conf.example    # Template configuration
│   ├── powc.conf            # Your config (gitignored)
│   └── private_key.txt      # Auto-generated key (gitignored)
├── watched_files/           # Default watch directory
│   ├── example.txt
│   └── example.txt.proof.json
├── logs/
│   └── powc-watcher.log
└── README.md
```

## Configuration Options

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ORG_ID` | ✅ | - | Constellation organization UUID |
| `TENANT_ID` | ✅ | - | Tenant UUID |
| `API_KEY` | ✅ | - | Digital Evidence API key |
| `PRIVATE_KEY` | ❌ | Auto-generated | secp256k1 private key (64 hex chars) |
| `API_BASE_URL` | ❌ | `https://de-api...` | API endpoint |
| `WATCH_PATHS` | ❌ | `./watched_files` | Comma-separated paths |
| `DEBOUNCE_DELAY` | ❌ | `2` | Seconds to wait after file change |
| `LOG_FILE` | ❌ | `./logs/powc-watcher.log` | Log file path |
| `VERBOSE` | ❌ | `false` | Verbose logging |

## Advanced Usage

### Watch Multiple Directories

```bash
# In config/powc.conf
WATCH_PATHS=./docs,./images,./contracts,/home/user/projects
```

### Using Virtual Environment

The watcher automatically detects `venv/` or `.venv/`:

```bash
# Setup venv (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Run watcher (auto-uses venv)
./powc-watcher.sh
```

To switch back to global Python, remove venv:
```bash
rm -rf venv .venv
```

### Run as Background Service

```bash
# Start in background
nohup ./powc-watcher.sh > /dev/null 2>&1 &

# Or use systemd (create /etc/systemd/system/powc-watcher.service)
```

### Verify a Proof

```bash
# Extract fingerprint hash from sidecar
HASH=$(jq -r '.entries[0].fingerprintHash' file.txt.proof.json)

# Query API
curl "https://de-api.constellationnetwork.io/v1/fingerprints/$HASH"

# Or view in explorer
xdg-open "https://digitalevidence.constellationnetwork.io/fingerprint/$HASH"
```

## Troubleshooting

### inotify not found

```bash
sudo apt-get install inotify-tools
```

### Python dependencies missing

```bash
pip install ecdsa rfc8785
```

### API submission fails (401)

Check your `API_KEY` in `config/powc.conf`

### API submission fails (422)

Invalid signature - check `ORG_ID` and `TENANT_ID` match your API key

### File changes not detected

- Check `WATCH_PATHS` includes the file/directory
- Verify file is being saved (not just modified in memory)
- Check logs: `tail -f logs/powc-watcher.log`

## Security Notes

- **Private key security**: `config/private_key.txt` has chmod 600
- **Never commit**: `config/powc.conf` is gitignored (contains secrets)
- **API key**: Treat as sensitive credential
- **Sidecar files**: Can be safely committed (no secrets)

## Roadmap

- [ ] Format-specific canonicalization (PNG IDAT, PDF streams, SVG)
- [ ] Retry queue with exponential backoff
- [ ] Merkle batching for high-volume scenarios
- [ ] Verifier CLI tool
- [ ] Desktop notifications
- [ ] Web dashboard

## References

- [Digital Evidence Metagraph Docs](https://docs.constellationnetwork.io)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [SECP256k1 - Elliptic Curve Cryptography](https://en.bitcoin.it/wiki/Secp256k1)
- [inotify - Linux File System Events](https://man7.org/linux/man-pages/man7/inotify.7.html)

## License

MIT

## Contributing

Issues and PRs welcome at `/home/scas/git/powc-watcher`
