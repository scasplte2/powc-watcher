#!/usr/bin/env python3
"""
PoWC Signer - Proof-of-Work-Content Cryptographic Signer
Adapted from DED Python SDK for file fingerprinting and notarization
"""

import argparse
import hashlib
import json
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Tuple

try:
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.util import sigencode_der
    import rfc8785
except ImportError as e:
    print(f"Error: Missing required library - {e}", file=sys.stderr)
    print("Please run: pip install ecdsa rfc8785", file=sys.stderr)
    sys.exit(1)


class PoWCSigner:
    """
    Generates and signs digital evidence fingerprints using SECP256k1 cryptography
    Follows SECP256K1_RFC8785_V1 algorithm from Digital Evidence Metagraph
    """

    def __init__(self, org_id: str, tenant_id: str, private_key_hex: str = None):
        """
        Initialize the signer with organization credentials

        Args:
            org_id: Organization UUID (required)
            tenant_id: Tenant UUID (required)
            private_key_hex: Optional hex-encoded private key (generates new if not provided)
        """
        self.org_id = org_id
        self.tenant_id = tenant_id

        # Initialize or generate key pair
        if private_key_hex:
            try:
                self.private_key = SigningKey.from_string(
                    bytes.fromhex(private_key_hex),
                    curve=SECP256k1
                )
            except Exception as e:
                print(f"Error loading private key: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            self.private_key = SigningKey.generate(curve=SECP256k1)

        self.public_key = self.private_key.get_verifying_key()
        # Get public key in raw format (64 bytes, no 0x04 prefix)
        self.public_key_hex = self.public_key.to_string().hex()

    def get_private_key_hex(self) -> str:
        """Get the private key as hex string for config storage"""
        return self.private_key.to_string().hex()

    def _canonicalize_json(self, obj: Dict) -> str:
        """
        Canonicalize JSON according to RFC 8785 (JSON Canonicalization Scheme)
        """
        return rfc8785.dumps(obj)

    def _compute_signature(self, fingerprint_value: Dict) -> Tuple[str, str]:
        """
        Compute the cryptographic signature for a fingerprint value
        Following SECP256K1_RFC8785_V1 algorithm:
        1. Canonicalize JSON (RFC 8785)
        2. SHA-256 hash of UTF-8 bytes
        3. Convert hash to hex string
        4. SHA-512 of hex string bytes
        5. Truncate to 32 bytes
        6. Sign with ECDSA/secp256k1

        Returns:
            Tuple of (signature_hex, content_hash_hex)
        """
        # Step 1: Canonicalize JSON (returns bytes or string)
        canonical_json = self._canonicalize_json(fingerprint_value)

        # Step 2: Compute SHA-256 of UTF-8 bytes
        if isinstance(canonical_json, str):
            utf8_bytes = canonical_json.encode('utf-8')
        else:
            utf8_bytes = canonical_json  # Already bytes from rfc8785

        hash_bytes = hashlib.sha256(utf8_bytes).digest()
        hash_hex = hash_bytes.hex()

        # Step 3-5: Double hash process for signing
        # Critical: convert hex to UTF-8 bytes, then SHA-512, then truncate
        hash_bytes_for_signing = hash_hex.encode('utf-8')
        sha512_hash = hashlib.sha512(hash_bytes_for_signing).digest()
        truncated_hash = sha512_hash[:32]  # Take first 32 bytes

        # Step 6: Sign with ECDSA (DER format)
        signature = self.private_key.sign_digest(truncated_hash, sigencode=sigencode_der)

        return signature.hex(), hash_hex

    def hash_file(self, file_path: str) -> str:
        """
        Compute SHA-512 hash of file content

        Args:
            file_path: Path to file to hash

        Returns:
            Hex string of SHA-512 hash
        """
        sha512 = hashlib.sha512()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha512.update(chunk)
            return sha512.hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}", file=sys.stderr)
            sys.exit(1)

    def create_fingerprint_value(
        self,
        event_id: str,
        document_id: str,
        document_ref: str,
        version: int = 1
    ) -> Dict:
        """
        Create a FingerprintValue object (matching exact SDK format)

        Args:
            event_id: UUID for this fingerprint event
            document_id: Logical document identifier (max 256 chars)
            document_ref: Content hash (SHA-512 of file, hex string)
            version: Version number (default 1)

        Returns:
            FingerprintValue dict
        """
        timestamp = datetime.now(timezone.utc)

        # Match exact SDK timestamp format
        return {
            "orgId": self.org_id,
            "tenantId": self.tenant_id,
            "eventId": event_id,
            "signerId": self.public_key_hex,
            "documentId": document_id,
            "documentRef": document_ref,
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "version": version
        }

    def sign_fingerprint(
        self,
        fingerprint_value: Dict,
        filename: str = None,
        file_size: str = None,
        user: str = None,
        hostname: str = None,
        file_ext: str = None
    ) -> Dict:
        """
        Create a signed fingerprint submission (matching exact SDK format)

        Args:
            fingerprint_value: FingerprintValue object
            filename: Optional filename to include in metadata tags
            file_size: File size in bytes
            user: OS user who saved the file
            hostname: Hostname where file was saved
            file_ext: File extension

        Returns:
            Complete submission with attestation
        """
        # Compute signature
        signature_hex, hash_hex = self._compute_signature(fingerprint_value)

        # Build the signed fingerprint structure (exact SDK format)
        signed_fingerprint = {
            "content": fingerprint_value,
            "proofs": [{
                "id": self.public_key_hex,
                "signature": signature_hex,
                "algorithm": "SECP256K1_RFC8785_V1"
            }]
        }

        # Build the submission with metadata
        # Max 6 tags, each key/value max 32 chars
        tags = {
            "generator": "PoWC-Watcher"
        }

        if filename:
            tags["filename"] = filename[-32:] if len(filename) > 32 else filename
        if file_size:
            tags["size"] = str(file_size)[:32]
        if user:
            tags["user"] = user[:32]
        if hostname:
            tags["host"] = hostname[:32]
        if file_ext:
            tags["ext"] = file_ext[:32]

        submission = {
            "attestation": signed_fingerprint,
            "metadata": {
                "hash": hash_hex,
                "tags": tags
            }
        }

        return submission


def main():
    """
    CLI entry point for signing files
    """
    parser = argparse.ArgumentParser(
        description="Sign file fingerprints for Digital Evidence notarization"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to file to fingerprint"
    )
    parser.add_argument(
        "--event-id",
        required=True,
        help="UUID for this fingerprint event"
    )
    parser.add_argument(
        "--document-id",
        required=True,
        help="Logical document identifier"
    )
    parser.add_argument(
        "--org-id",
        required=True,
        help="Organization UUID"
    )
    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Tenant UUID"
    )
    parser.add_argument(
        "--private-key",
        help="Hex-encoded private key (generates new if not provided)"
    )
    parser.add_argument(
        "--filename",
        help="Filename to include in metadata tags (optional, max 32 chars)"
    )
    parser.add_argument(
        "--file-size",
        help="File size in bytes"
    )
    parser.add_argument(
        "--user",
        help="OS user who saved the file"
    )
    parser.add_argument(
        "--hostname",
        help="Hostname where file was saved"
    )
    parser.add_argument(
        "--file-ext",
        help="File extension"
    )
    parser.add_argument(
        "--output-key",
        action="store_true",
        help="Output the private key (for saving to config)"
    )

    args = parser.parse_args()

    # Validate file exists
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Initialize signer
    signer = PoWCSigner(
        org_id=args.org_id,
        tenant_id=args.tenant_id,
        private_key_hex=args.private_key
    )

    # Hash the file (SHA-512)
    document_ref = signer.hash_file(args.file)

    # Create fingerprint value
    fingerprint_value = signer.create_fingerprint_value(
        event_id=args.event_id,
        document_id=args.document_id,
        document_ref=document_ref
    )

    # Sign and create submission with metadata
    submission = signer.sign_fingerprint(
        fingerprint_value,
        filename=args.filename,
        file_size=args.file_size,
        user=args.user,
        hostname=args.hostname,
        file_ext=args.file_ext
    )

    # Output JSON to stdout
    print(json.dumps(submission, indent=2))

    # Optionally output private key to stderr for config storage
    if args.output_key:
        print(f"\n# Private key for config:", file=sys.stderr)
        print(f"PRIVATE_KEY={signer.get_private_key_hex()}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
