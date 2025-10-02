#!/usr/bin/env bash
#
# PoWC Proof Verifier
# View and verify proof chains stored in file extended attributes
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_usage() {
    echo "Usage: $0 <file> [options]"
    echo ""
    echo "View the proof chain for a file stored in extended attributes"
    echo ""
    echo "Options:"
    echo "  --json      Show raw JSON of current proof"
    echo "  --chain     Traverse full chain via API"
    echo "  --help      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 document.pdf          # Show current proof"
    echo "  $0 document.pdf --json   # Show raw JSON"
    echo "  $0 document.pdf --chain  # Show full chain history"
    exit 1
}

if [[ $# -lt 1 ]]; then
    show_usage
fi

FILE="$1"
JSON_MODE=false
CHAIN_MODE=false
API_BASE_URL="https://de-api.constellationnetwork.io/v1"

if [[ "${2:-}" == "--json" ]]; then
    JSON_MODE=true
elif [[ "${2:-}" == "--chain" ]]; then
    CHAIN_MODE=true
elif [[ "${2:-}" == "--help" ]]; then
    show_usage
fi

if [[ ! -f "$FILE" ]]; then
    echo "Error: File not found: $FILE"
    exit 1
fi

# Get proof from xattr
PROOF=$(getfattr -n user.powc.proof --only-values "$FILE" 2>/dev/null || echo "")

if [[ -z "$PROOF" ]]; then
    echo "No proof found in file extended attributes"
    echo "File has not been notarized yet."
    exit 0
fi

if [[ "$JSON_MODE" == "true" ]]; then
    echo "$PROOF" | jq .
    exit 0
fi

# Extract current proof info
FINGERPRINT_HASH=$(echo "$PROOF" | jq -r '.fingerprintHash')
TIMESTAMP=$(echo "$PROOF" | jq -r '.timestamp')
DOCUMENT_ID=$(echo "$PROOF" | jq -r '.attestation.content.documentId')
DOCUMENT_REF=$(echo "$PROOF" | jq -r '.attestation.content.documentRef')
ITERATION=$(echo "$PROOF" | jq -r '.iteration // 0')

# Parse parent from documentId (format: "parent:hash:ordinal:N")
PARENT=$(echo "$DOCUMENT_ID" | cut -d: -f2)
ORDINAL=$(echo "$DOCUMENT_ID" | cut -d: -f4)

if [[ "$CHAIN_MODE" == "true" ]]; then
    echo -e "${BLUE}=== Full Proof Chain for: $(basename "$FILE") ===${NC}"
    echo ""

    # Build chain by traversing backwards via API
    declare -a CHAIN_HASHES=("$FINGERPRINT_HASH")
    current_parent="$PARENT"

    # Walk backwards until genesis
    while [[ "$current_parent" != "genesis" ]] && [[ -n "$current_parent" ]]; do
        # Fetch parent from API
        parent_data=$(curl -s "${API_BASE_URL}/fingerprints/${current_parent}" 2>/dev/null || echo "")

        if [[ -z "$parent_data" ]] || [[ "$parent_data" == *"error"* ]]; then
            echo -e "${YELLOW}⚠ Could not fetch parent: $current_parent${NC}"
            break
        fi

        CHAIN_HASHES+=("$current_parent")

        # Get next parent
        parent_doc_id=$(echo "$parent_data" | jq -r '.data.documentId // ""')
        current_parent=$(echo "$parent_doc_id" | cut -d: -f2)

        # Safety: max 100 iterations
        if [[ ${#CHAIN_HASHES[@]} -gt 100 ]]; then
            echo -e "${YELLOW}⚠ Chain too long, stopping at 100${NC}"
            break
        fi
    done

    # Display chain from oldest to newest
    echo -e "${CYAN}Chain length: ${#CHAIN_HASHES[@]} fingerprints${NC}"
    echo ""

    for ((i=${#CHAIN_HASHES[@]}-1; i>=0; i--)); do
        hash="${CHAIN_HASHES[$i]}"
        marker=""

        if [[ $i -eq 0 ]]; then
            marker="${GREEN}◉${NC} (current)"
        elif [[ $i -eq $((${#CHAIN_HASHES[@]}-1)) ]]; then
            marker="${BLUE}◎${NC} (genesis)"
        else
            marker="${CYAN}○${NC}"
        fi

        ordinal=$((${#CHAIN_HASHES[@]} - 1 - i))
        echo -e "  $marker Ordinal $ordinal: ${hash:0:16}..."
        echo "     https://digitalevidence.constellationnetwork.io/fingerprint/$hash"
    done

    exit 0
fi

# Pretty print current proof
echo -e "${BLUE}=== Current Proof for: $(basename "$FILE") ===${NC}"
echo ""

echo -e "${GREEN}Fingerprint Hash:${NC} $FINGERPRINT_HASH"
echo -e "${GREEN}Timestamp:${NC} $TIMESTAMP"
echo -e "${GREEN}Content Hash:${NC} $DOCUMENT_REF"
echo -e "${GREEN}Parent Hash:${NC} $PARENT"
echo -e "${GREEN}Ordinal:${NC} $ORDINAL (iteration: $ITERATION)"
echo ""

# Show API receipt
ACCEPTED=$(echo "$PROOF" | jq -r '.apiReceipt[0].accepted // false')
if [[ "$ACCEPTED" == "true" ]]; then
    echo -e "${GREEN}✓ Accepted by Digital Evidence API${NC}"
    echo ""
    echo "View on explorer:"
    echo "  https://digitalevidence.constellationnetwork.io/fingerprint/$FINGERPRINT_HASH"
    echo ""
    if [[ "$PARENT" != "genesis" ]]; then
        echo "View parent:"
        echo "  https://digitalevidence.constellationnetwork.io/fingerprint/$PARENT"
    fi
else
    echo -e "${YELLOW}⚠ Not yet accepted${NC}"
fi

echo ""
echo "Commands:"
echo "  $0 \"$FILE\" --json   # Show raw JSON"
echo "  $0 \"$FILE\" --chain  # Show full chain history"
