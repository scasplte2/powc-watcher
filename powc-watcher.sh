#!/usr/bin/env bash
#
# PoWC-Watcher (Proof-of-Work-Content Watcher)
# Monitors files/directories and notarizes content changes to Digital Evidence Metagraph
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/powc.conf"
KEY_FILE="${SCRIPT_DIR}/config/private_key.txt"
SIGNER_SCRIPT="${SCRIPT_DIR}/src/powc_signer.py"

# Detect Python (prefer venv if available)
if [[ -f "${SCRIPT_DIR}/venv/bin/python3" ]]; then
    PYTHON="${SCRIPT_DIR}/venv/bin/python3"
elif [[ -f "${SCRIPT_DIR}/.venv/bin/python3" ]]; then
    PYTHON="${SCRIPT_DIR}/.venv/bin/python3"
else
    PYTHON="python3"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    if [[ "${VERBOSE:-false}" == "true" ]] && [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "$LOG_FILE"
    fi
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $*" >> "$LOG_FILE"
    fi
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "$LOG_FILE"
    fi
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "$LOG_FILE"
    fi
}

# Load configuration
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_error "Copy config/powc.conf.example to config/powc.conf and configure it"
        exit 1
    fi

    # Source config file
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"

    # Validate required variables
    if [[ -z "${ORG_ID:-}" ]] || [[ -z "${TENANT_ID:-}" ]] || [[ -z "${API_KEY:-}" ]]; then
        log_error "Missing required configuration: ORG_ID, TENANT_ID, and API_KEY must be set"
        exit 1
    fi

    # Set defaults
    API_BASE_URL="${API_BASE_URL:-https://de-api.constellationnetwork.io/v1}"
    WATCH_PATHS="${WATCH_PATHS:-./watched_files}"
    DEBOUNCE_DELAY="${DEBOUNCE_DELAY:-2}"
    LOG_FILE="${LOG_FILE:-./logs/powc-watcher.log}"
    VERBOSE="${VERBOSE:-false}"

    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    if ! command -v inotifywait &> /dev/null; then
        missing_deps+=("inotify-tools")
    fi

    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi

    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if ! command -v getfattr &> /dev/null || ! command -v setfattr &> /dev/null; then
        missing_deps+=("attr")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Install with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi

    # Check Python dependencies
    if ! $PYTHON -c "import ecdsa, rfc8785" 2>/dev/null; then
        log_error "Missing Python dependencies"
        log_error "Install with: pip install ecdsa rfc8785"
        exit 1
    fi
}

# Initialize or load private key
init_key() {
    if [[ -n "${PRIVATE_KEY:-}" ]]; then
        # Use key from config
        log_info "Using private key from config"
        echo "$PRIVATE_KEY" > "$KEY_FILE"
        chmod 600 "$KEY_FILE"
    elif [[ -f "$KEY_FILE" ]]; then
        # Use existing key file
        log_info "Using existing private key from $KEY_FILE"
        PRIVATE_KEY=$(cat "$KEY_FILE")
    else
        # Generate new key
        log_info "Generating new secp256k1 private key..."

        # Generate key using Python signer
        local temp_output
        temp_output=$($PYTHON "$SIGNER_SCRIPT" \
            --file /dev/null \
            --event-id "00000000-0000-0000-0000-000000000000" \
            --document-id "init" \
            --org-id "$ORG_ID" \
            --tenant-id "$TENANT_ID" \
            --output-key 2>&1 >/dev/null || true)

        PRIVATE_KEY=$(echo "$temp_output" | grep "PRIVATE_KEY=" | cut -d= -f2)

        if [[ -z "$PRIVATE_KEY" ]]; then
            log_error "Failed to generate private key"
            exit 1
        fi

        echo "$PRIVATE_KEY" > "$KEY_FILE"
        chmod 600 "$KEY_FILE"

        log_success "Generated new private key: $KEY_FILE"
        log_warn "IMPORTANT: Add this to your config to reuse the same key:"
        log_warn "PRIVATE_KEY=$PRIVATE_KEY"
    fi
}

# Generate UUID v4
generate_uuid() {
    $PYTHON -c "import uuid; print(str(uuid.uuid4()))"
}

# Process a file change
process_file() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")

    log_info "Processing file: $filepath"

    # Hash the file first to check for duplicates
    local current_hash
    current_hash=$(sha256sum "$filepath" | cut -d' ' -f1)

    # Check if this content was already submitted (duplicate detection via xattr)
    local last_proof
    last_proof=$(getfattr -n user.powc.proof --only-values "$filepath" 2>/dev/null || echo "")

    if [[ -n "$last_proof" ]]; then
        log_info "Read xattr successfully, length: ${#last_proof}"
    else
        log_info "xattr is empty or missing"
    fi

    # Declare parent_hash and iteration before if/else to maintain scope
    local parent_hash="genesis"
    local iteration=0

    if [[ -n "$last_proof" ]]; then
        local last_hash
        last_hash=$(echo "$last_proof" | jq -r '.attestation.content.documentRef // ""')
        if [[ "$current_hash" == "$last_hash" ]]; then
            log_info "Skipping duplicate - content unchanged (hash: ${current_hash:0:16}...)"
            return 0
        fi

        # Get parent fingerprint hash for chaining
        parent_hash=$(echo "$last_proof" | jq -r '.fingerprintHash // ""')

        # Get iteration from previous proof and increment
        local prev_iteration
        prev_iteration=$(echo "$last_proof" | jq -r '.iteration // 0')
        iteration=$((prev_iteration + 1))

        log_info "Found previous proof, parent: ${parent_hash:0:16}..., iteration: $iteration"
    else
        log_info "No previous proof found, using genesis, iteration: 0"
    fi

    # Generate event ID
    local event_id
    event_id=$(generate_uuid)

    # Use parent fingerprint hash + iteration as document ID for public chain traversal
    # Example: "parent:abc123...:ordinal:5" or "parent:genesis:ordinal:0" for first submission
    local document_id="parent:${parent_hash}:ordinal:${iteration}"
    log_info "Document ID: $document_id"

    # Collect metadata for tags (max 6 tags, 32 chars each)
    local file_size
    file_size=$(stat -c%s "$filepath" 2>/dev/null || stat -f%z "$filepath" 2>/dev/null)
    local os_user
    os_user="${USER:-unknown}"
    local hostname
    hostname=$(hostname -s 2>/dev/null | cut -c1-32)
    local file_ext="${filename##*.}"
    [[ "$file_ext" == "$filename" ]] && file_ext=""  # No extension

    # Sign the file with metadata
    log_info "Signing fingerprint..."
    local submission
    if ! submission=$($PYTHON "$SIGNER_SCRIPT" \
        --file "$filepath" \
        --event-id "$event_id" \
        --document-id "$document_id" \
        --filename "$filename" \
        --file-size "$file_size" \
        --user "$os_user" \
        --hostname "$hostname" \
        --file-ext "$file_ext" \
        --org-id "$ORG_ID" \
        --tenant-id "$TENANT_ID" \
        --private-key "$PRIVATE_KEY" 2>/dev/null); then
        log_error "Failed to sign fingerprint for $filepath"
        return 1
    fi

    # Extract key values
    local fingerprint_hash
    fingerprint_hash=$(echo "$submission" | jq -r '.metadata.hash')
    local document_ref
    document_ref=$(echo "$submission" | jq -r '.attestation.content.documentRef')

    # Submit to API (wrap in array - API expects list)
    log_info "Submitting to Digital Evidence API..."
    local api_response
    local http_code
    local submission_array
    submission_array=$(echo "$submission" | jq -c '[.]')

    api_response=$(curl -s -w "\n%{http_code}" \
        -X POST "${API_BASE_URL}/fingerprints" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$submission_array")

    http_code=$(echo "$api_response" | tail -n1)
    api_response=$(echo "$api_response" | head -n-1)

    # Process API response and store proof in xattr
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "201" ]]; then
        # Build proof object with minimal data needed for chaining
        local proof
        proof=$(jq -n \
            --arg ts "$timestamp" \
            --arg fphash "$fingerprint_hash" \
            --arg iter "$iteration" \
            --argjson attest "$(echo "$submission" | jq '.attestation')" \
            --argjson receipt "$api_response" \
            '{
                timestamp: $ts,
                fingerprintHash: $fphash,
                iteration: ($iter | tonumber),
                attestation: $attest,
                apiReceipt: $receipt,
                status: "success"
            }')

        # Store proof in extended attribute and cache for atomic saves
        if setfattr -n user.powc.proof -v "$proof" "$filepath" 2>/dev/null; then
            log_success "Notarized: $filename (hash: ${fingerprint_hash:0:16}...)"
            log_info "Proof stored in xattr (parent: ${parent_hash:0:16}...)"

            # Cache proof for restoration after atomic saves
            # Note: proof_cache_dir is set in watch_files function
            if [[ -n "${proof_cache_dir:-}" ]]; then
                local cache_file
                cache_file="$proof_cache_dir/$(echo "$filepath" | sha256sum | cut -d' ' -f1)"
                echo "$proof" > "$cache_file"
            fi
        else
            log_warn "Could not store xattr - filesystem may not support it"
            log_success "Notarized: $filename (hash: ${fingerprint_hash:0:16}...)"
        fi
    else
        log_error "API submission failed (HTTP $http_code): $filename"
        log_error "Error: $api_response"
    fi
}

# Watch files using inotify
watch_files() {
    log_info "Starting PoWC-Watcher..."
    log_info "Organization: $ORG_ID"
    log_info "Tenant: $TENANT_ID"
    log_info "Watching: $WATCH_PATHS"
    log_info "Debounce delay: ${DEBOUNCE_DELAY}s"
    log_info ""
    log_success "Watcher is running. Press Ctrl+C to stop."
    log_info ""

    # Create temporary directory for tracking proofs across atomic saves
    local proof_cache_dir="/tmp/powc-watcher-$$"
    mkdir -p "$proof_cache_dir"
    trap "rm -rf $proof_cache_dir" EXIT

    # Convert comma-separated paths to array
    IFS=',' read -ra PATHS <<< "$WATCH_PATHS"

    # Build inotifywait command
    local watch_args=()
    for path in "${PATHS[@]}"; do
        # Trim whitespace
        path=$(echo "$path" | xargs)

        if [[ ! -e "$path" ]]; then
            log_warn "Path does not exist: $path (creating it)"
            mkdir -p "$path"
        fi

        if [[ -d "$path" ]]; then
            watch_args+=("-r" "$path")
        else
            watch_args+=("$path")
        fi
    done

    # Watch for file changes
    # Using close_write and moved_to to catch saves and atomic renames
    inotifywait -m -e close_write -e moved_to "${watch_args[@]}" --format '%e %w%f' 2>/dev/null | while read -r event filepath; do
        # Skip .proof.json files and temporary files
        if [[ "$filepath" == *.proof.json ]] || [[ "$filepath" == *~ ]] || [[ "$filepath" == */.*~ ]]; then
            continue
        fi

        # Handle moved_to events (atomic save from editors)
        # Don't process MOVED_TO events separately - just skip them
        # The subsequent CLOSE_WRITE will handle it
        if [[ "$event" == "MOVED_TO" ]]; then
            continue
        fi

        # Debounce first to ensure file operations are complete
        sleep "$DEBOUNCE_DELAY"

        # Before processing, check if xattr is missing but we have it cached
        # This handles atomic saves where the file was replaced
        local cache_file
        cache_file="$proof_cache_dir/$(echo "$filepath" | sha256sum | cut -d' ' -f1)"

        # Check if xattr is missing
        if ! getfattr -n user.powc.proof "$filepath" &>/dev/null; then
            log_info "xattr missing, checking cache for: $(basename "$filepath")"
            # Try to restore from cache
            if [[ -f "$cache_file" ]]; then
                local cached_proof
                cached_proof=$(cat "$cache_file")
                if [[ -n "$cached_proof" ]]; then
                    if setfattr -n user.powc.proof -v "$cached_proof" "$filepath" 2>/dev/null; then
                        log_info "Restored xattr from cache for: $(basename "$filepath")"
                    else
                        log_warn "Failed to restore xattr for: $(basename "$filepath")"
                    fi
                else
                    log_warn "Cache file empty for: $(basename "$filepath")"
                fi
            else
                log_info "No cache file found for: $(basename "$filepath")"
            fi
        fi

        # Process the file
        if [[ -f "$filepath" ]]; then
            process_file "$filepath"
        fi
    done
}

# Main function
main() {
    log_info "PoWC-Watcher - Proof-of-Work-Content File Notarization"
    log_info ""

    # Load configuration
    load_config

    # Check dependencies
    check_dependencies

    # Initialize key
    init_key

    # Start watching
    watch_files
}

# Run main
main "$@"
