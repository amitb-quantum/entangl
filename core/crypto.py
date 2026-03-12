"""
Entangl Crypto Core — Phase 1
============================
Post-quantum cryptographic primitives for the Entangl Protocol.

Algorithms (all NIST-standardized):
  - CRYSTALS-Kyber1024  (ML-KEM)  → NIST FIPS 203  — Key Encapsulation
  - CRYSTALS-Dilithium5 (ML-DSA)  → NIST FIPS 204  — Digital Signatures

These replace classical RSA/ECDH/ECDSA which are broken by Shor's algorithm
on a sufficiently large quantum computer.
"""

import os
import json
import hashlib
import hmac
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from kyber_py.kyber import Kyber1024
from dilithium_py.dilithium import Dilithium5


# ─────────────────────────────────────────────────────────────
# Key Containers
# ─────────────────────────────────────────────────────────────

@dataclass
class KEMKeyPair:
    """
    Kyber1024 Key Encapsulation Mechanism key pair.
    Used by an agent to receive encrypted shared secrets from other agents.

    Sizes (Kyber1024):
        public_key  : 1568 bytes
        secret_key  : 3168 bytes
        ciphertext  : 1568 bytes
        shared_key  :   32 bytes
    """
    public_key: bytes   # Share with other agents (safe to publish)
    secret_key: bytes   # NEVER share — used to decapsulate incoming keys

    def public_key_hex(self) -> str:
        return self.public_key.hex()


@dataclass
class SigningKeyPair:
    """
    Dilithium5 signing key pair.
    Used by an agent to sign every outgoing message — proving authorship.

    Sizes (Dilithium5):
        verify_key  : 2592 bytes
        signing_key : 4864 bytes
        signature   : 4595 bytes max
    """
    verify_key: bytes   # Share with other agents (safe to publish)
    signing_key: bytes  # NEVER share — used to sign messages

    def verify_key_hex(self) -> str:
        return self.verify_key.hex()


@dataclass
class AgentCryptoIdentity:
    """
    Full cryptographic identity of a Entangl agent.
    Bundles both key pairs under a single agent_id.
    """
    agent_id: str
    kem_keypair: KEMKeyPair
    signing_keypair: SigningKeyPair
    created_at: float = field(default_factory=time.time)

    def public_bundle(self) -> dict:
        """
        Returns only public keys — safe to publish to the registry.
        Other agents need this to send encrypted messages and verify signatures.
        """
        return {
            "agent_id":    self.agent_id,
            "kem_pk":      self.kem_keypair.public_key_hex(),
            "signing_vk":  self.signing_keypair.verify_key_hex(),
            "created_at":  self.created_at,
        }


# ─────────────────────────────────────────────────────────────
# Key Generation
# ─────────────────────────────────────────────────────────────

def generate_agent_identity(agent_id: str) -> AgentCryptoIdentity:
    """
    Generate a full post-quantum cryptographic identity for an agent.

    Called once at agent bootstrap. The secret keys must be stored
    securely (encrypted at rest) and never transmitted.

    Args:
        agent_id: Unique human-readable identifier for this agent.
                  e.g. "agent-alpha", "buyer-bot-7"

    Returns:
        AgentCryptoIdentity with fresh Kyber1024 + Dilithium5 key pairs.
    """
    # Kyber1024 key pair for receiving encrypted messages
    kem_pk, kem_sk = Kyber1024.keygen()

    # Dilithium5 key pair for signing outgoing messages
    dil_vk, dil_sk = Dilithium5.keygen()

    return AgentCryptoIdentity(
        agent_id=agent_id,
        kem_keypair=KEMKeyPair(public_key=kem_pk, secret_key=kem_sk),
        signing_keypair=SigningKeyPair(verify_key=dil_vk, signing_key=dil_sk),
    )


# ─────────────────────────────────────────────────────────────
# Key Encapsulation (Kyber1024)
# ─────────────────────────────────────────────────────────────

@dataclass
class EncapsulationResult:
    """
    Result of a Kyber1024 key encapsulation operation.

    The sender holds `shared_secret` (32 bytes) and sends `ciphertext`
    to the recipient. The recipient runs decapsulation to recover
    the same `shared_secret` without ever transmitting it.
    """
    shared_secret: bytes   # 32-byte symmetric key — use for AES-256-GCM
    ciphertext: bytes      # 1568 bytes — send this to recipient


def encapsulate_key(recipient_kem_pk: bytes) -> EncapsulationResult:
    """
    Sender-side: generate a shared secret and encapsulate it for the recipient.

    The shared_secret is used as a symmetric key (e.g., for AES-256-GCM).
    The ciphertext is transmitted to the recipient who decapsulates it.

    Args:
        recipient_kem_pk: Recipient's Kyber1024 public key (from their public bundle).

    Returns:
        EncapsulationResult with shared_secret (keep) and ciphertext (send).
    """
    shared_secret, ciphertext = Kyber1024.encaps(recipient_kem_pk)
    return EncapsulationResult(shared_secret=shared_secret, ciphertext=ciphertext)


def decapsulate_key(kem_sk: bytes, ciphertext: bytes) -> bytes:
    """
    Recipient-side: recover the shared secret from the ciphertext.

    Args:
        kem_sk:     Recipient's Kyber1024 secret key.
        ciphertext: Received from the sender's encapsulation step.

    Returns:
        32-byte shared secret (same as what sender holds).
    """
    return Kyber1024.decaps(kem_sk, ciphertext)


# ─────────────────────────────────────────────────────────────
# Symmetric Encryption (AES-256-GCM via shared secret)
# ─────────────────────────────────────────────────────────────

def _derive_aes_key(shared_secret: bytes, context: bytes = b"entangl-v1") -> bytes:
    """
    Derive a 32-byte AES-256 key from the Kyber shared secret using HKDF-SHA3-256.
    The context binds the key to the Entangl protocol version.
    """
    return hashlib.blake2b(shared_secret + context, digest_size=32).digest()


def encrypt_message(shared_secret: bytes, plaintext: bytes) -> dict:
    """
    Encrypt a message using AES-256-GCM with a key derived from the shared secret.
    Uses Python's built-in `cryptography` library (Fernet-style but with GCM).

    Returns a dict with: nonce, ciphertext, tag (all hex-encoded).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes_key = _derive_aes_key(shared_secret)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # GCM appends 16-byte auth tag to ciphertext
    return {
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext_with_tag[:-16].hex(),
        "tag":        ciphertext_with_tag[-16:].hex(),
    }


def decrypt_message(shared_secret: bytes, encrypted: dict) -> bytes:
    """
    Decrypt a message using AES-256-GCM.

    Args:
        shared_secret: Recovered via Kyber1024 decapsulation.
        encrypted:     Dict from encrypt_message() with nonce/ciphertext/tag.

    Returns:
        Original plaintext bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes_key = _derive_aes_key(shared_secret)
    nonce = bytes.fromhex(encrypted["nonce"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    tag = bytes.fromhex(encrypted["tag"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# ─────────────────────────────────────────────────────────────
# Digital Signatures (Dilithium5)
# ─────────────────────────────────────────────────────────────

@dataclass
class SignedMessage:
    """
    A message signed with Dilithium5.
    Recipients verify this before trusting any payload.
    """
    agent_id:  str    # Who signed this
    payload:   bytes  # Raw message content
    signature: bytes  # Dilithium5 signature over payload
    timestamp: float  # Unix timestamp (prevents replay attacks)

    def to_dict(self) -> dict:
        return {
            "agent_id":  self.agent_id,
            "payload":   self.payload.hex(),
            "signature": self.signature.hex(),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignedMessage":
        return cls(
            agent_id  = d["agent_id"],
            payload   = bytes.fromhex(d["payload"]),
            signature = bytes.fromhex(d["signature"]),
            timestamp = d["timestamp"],
        )


def sign_message(signing_key: bytes, agent_id: str, payload: bytes) -> SignedMessage:
    """
    Sign a payload with the agent's Dilithium5 signing key.

    The signature covers: agent_id + payload + timestamp.
    This binds the signature to the sender and prevents replay attacks.

    Args:
        signing_key: Agent's Dilithium5 secret signing key.
        agent_id:    Agent's identifier (included in signed material).
        payload:     Raw bytes to sign (e.g., serialized message body).

    Returns:
        SignedMessage ready to transmit.
    """
    timestamp = time.time()
    # Bind agent_id and timestamp into the signed material
    signed_material = (
        agent_id.encode() +
        b"||" +
        payload +
        b"||" +
        str(timestamp).encode()
    )
    signature = Dilithium5.sign(signing_key, signed_material)
    return SignedMessage(
        agent_id=agent_id,
        payload=payload,
        signature=signature,
        timestamp=timestamp,
    )


def verify_message(verify_key: bytes, signed_msg: SignedMessage,
                   max_age_seconds: float = 30.0) -> bool:
    """
    Verify a signed message from another agent.

    Checks:
      1. Dilithium5 signature is valid.
      2. Message is not older than max_age_seconds (replay protection).

    Args:
        verify_key:       Sender's Dilithium5 public verify key.
        signed_msg:       The SignedMessage received.
        max_age_seconds:  Reject messages older than this. Default 30s.

    Returns:
        True if valid and fresh, False otherwise.
    """
    # Replay attack check
    age = time.time() - signed_msg.timestamp
    if age > max_age_seconds or age < 0:
        return False

    # Reconstruct the exact signed material
    signed_material = (
        signed_msg.agent_id.encode() +
        b"||" +
        signed_msg.payload +
        b"||" +
        str(signed_msg.timestamp).encode()
    )

    return Dilithium5.verify(verify_key, signed_material, signed_msg.signature)


# ─────────────────────────────────────────────────────────────
# Fingerprinting
# ─────────────────────────────────────────────────────────────

def fingerprint(public_key: bytes) -> str:
    """
    SHA3-256 fingerprint of a public key — short, human-readable identifier.
    Displayed in logs and dashboards. Similar to SSH key fingerprints.
    """
    digest = hashlib.sha3_256(public_key).hexdigest()
    # Format as groups of 8 hex chars, like: a1b2c3d4:e5f6a7b8:...
    return ":".join(digest[i:i+8] for i in range(0, 32, 8))
