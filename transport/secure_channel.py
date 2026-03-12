"""
Entangl Secure Channel — Phase 3
================================
Encrypted, signed, authenticated agent-to-agent message transport.

Protocol handshake (per message, stateless):
  1. SENDER looks up RECIPIENT's KEM public key from registry
  2. SENDER encapsulates a fresh shared secret (Kyber1024)
  3. SENDER encrypts the payload with AES-256-GCM using derived key
  4. SENDER signs the entire envelope with Dilithium5
  5. RECIPIENT verifies signature (checks sender is who they claim)
  6. RECIPIENT decapsulates to recover shared secret
  7. RECIPIENT decrypts the payload

This is a "forward-secure" design — each message uses a fresh KEM,
so compromising one message's key doesn't expose past or future messages.
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

from entangl.core.crypto import (
    AgentCryptoIdentity,
    SignedMessage,
    encapsulate_key,
    decapsulate_key,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_message,
)
from entangl.registry.agent_registry import AgentRegistry


# ─────────────────────────────────────────────────────────────
# Message Types
# ─────────────────────────────────────────────────────────────

class MessageType:
    """Standard Entangl message types for agent-to-agent negotiation."""
    HANDSHAKE    = "HANDSHAKE"     # Establish identity
    PROPOSE      = "PROPOSE"       # Sender proposes a deal/action
    COUNTER      = "COUNTER"       # Recipient counters a proposal
    ACCEPT       = "ACCEPT"        # Accept a proposal
    REJECT       = "REJECT"        # Reject a proposal
    CONFIRM      = "CONFIRM"       # Final confirmation of agreed deal
    ACK          = "ACK"           # Acknowledge receipt
    ERROR        = "ERROR"         # Signal an error condition


# ─────────────────────────────────────────────────────────────
# Entangl Envelope
# ─────────────────────────────────────────────────────────────

@dataclass
class EntanglEnvelope:
    """
    The wire format of a Entangl message.

    Structure:
        header       — routing and protocol metadata (plaintext)
        kem_ct_hex   — Kyber1024 ciphertext (recipient uses this to recover shared secret)
        encrypted    — AES-256-GCM encrypted payload dict (nonce/ciphertext/tag)
        signature    — Dilithium5 SignedMessage over the entire envelope content

    The header is intentionally plaintext so routers can forward messages
    without decrypting them. Only the recipient can read the payload.
    """
    message_id:  str          # UUID — unique per message
    msg_type:    str          # MessageType constant
    sender_id:   str          # Sender's agent_id
    recipient_id:str          # Recipient's agent_id
    kem_ct_hex:  str          # Kyber1024 ciphertext (hex)
    encrypted:   dict         # {"nonce", "ciphertext", "tag"} — all hex
    signature:   dict         # SignedMessage.to_dict()
    sent_at:     float        # Unix timestamp

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "EntanglEnvelope":
        d = json.loads(raw)
        return cls(**d)

    def header_summary(self) -> str:
        t = time.strftime('%H:%M:%S', time.localtime(self.sent_at))
        return (f"[{t}] {self.msg_type:12s} "
                f"{self.sender_id} → {self.recipient_id} "
                f"(id: {self.message_id[:8]}...)")


# ─────────────────────────────────────────────────────────────
# Secure Channel
# ─────────────────────────────────────────────────────────────

class EntanglSecureChannel:
    """
    A secure, authenticated channel between Entangl agents.

    Each agent holds a EntanglSecureChannel that they use to:
        - send()   : Encrypt and sign messages to other agents
        - receive(): Verify and decrypt messages from other agents

    The channel is stateless — no session keys are maintained.
    Each send() generates a fresh Kyber1024 key encapsulation.
    This provides forward secrecy per message.

    Usage:
        channel = EntanglSecureChannel(identity=my_identity, registry=registry)
        envelope = channel.send(recipient_id="other-agent", msg_type=MessageType.PROPOSE, payload={"item": "compute", "price": 0.05})
        # ... transmit envelope.to_json() over any transport ...
        payload = channel.receive(envelope)
    """

    def __init__(self, identity: AgentCryptoIdentity, registry: AgentRegistry):
        """
        Args:
            identity: This agent's full crypto identity (Phase 1).
            registry: Shared registry for key lookup (Phase 2).
        """
        self.identity = identity
        self.registry = registry
        self._message_log: list[dict] = []

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    # ── Send ──────────────────────────────────────────────────

    def send(
        self,
        recipient_id: str,
        msg_type: str,
        payload: dict,
    ) -> EntanglEnvelope:
        """
        Encrypt, sign, and package a message for the recipient.

        Steps:
          1. Look up recipient's KEM public key from registry
          2. Encapsulate a fresh shared secret (Kyber1024)
          3. Encrypt payload with AES-256-GCM
          4. Sign the envelope content with Dilithium5

        Args:
            recipient_id: Target agent's ID (must be in registry).
            msg_type:     One of MessageType constants.
            payload:      Dict of message content (will be JSON-serialized).

        Returns:
            EntanglEnvelope ready to serialize and transmit.

        Raises:
            ValueError: If recipient is not found or is revoked.
        """
        # Step 1: Resolve recipient's public KEM key
        recipient_kem_pk = self.registry.get_kem_public_key(recipient_id)
        if not recipient_kem_pk:
            raise ValueError(
                f"Recipient '{recipient_id}' not found in registry or is revoked. "
                f"Cannot establish secure channel."
            )

        # Step 2: Fresh Kyber1024 key encapsulation
        kem_result = encapsulate_key(recipient_kem_pk)

        # Step 3: Encrypt payload with derived AES-256-GCM key
        payload_bytes = json.dumps(payload).encode()
        encrypted = encrypt_message(kem_result.shared_secret, payload_bytes)

        # Step 4: Sign the envelope content (binds sender identity to message)
        signed_material = (
            self.agent_id +
            recipient_id +
            msg_type +
            kem_result.ciphertext.hex() +
            encrypted["nonce"]
        ).encode()

        signed_msg = sign_message(
            signing_key=self.identity.signing_keypair.signing_key,
            agent_id=self.agent_id,
            payload=signed_material,
        )

        envelope = EntanglEnvelope(
            message_id   = str(uuid.uuid4()),
            msg_type     = msg_type,
            sender_id    = self.agent_id,
            recipient_id = recipient_id,
            kem_ct_hex   = kem_result.ciphertext.hex(),
            encrypted    = encrypted,
            signature    = signed_msg.to_dict(),
            sent_at      = time.time(),
        )

        self._message_log.append({
            "direction": "OUT",
            "summary": envelope.header_summary(),
        })
        return envelope

    # ── Receive ───────────────────────────────────────────────

    def receive(self, envelope: EntanglEnvelope) -> Optional[dict]:
        """
        Verify and decrypt an incoming message.

        Steps:
          1. Verify this agent is the intended recipient
          2. Look up sender's verify key from registry
          3. Verify Dilithium5 signature (reject if invalid or expired)
          4. Decapsulate Kyber1024 ciphertext to recover shared secret
          5. Decrypt payload with AES-256-GCM

        Args:
            envelope: EntanglEnvelope received from sender.

        Returns:
            Decrypted payload dict if valid. None if verification fails.
        """
        # Step 1: Check we are the intended recipient
        if envelope.recipient_id != self.agent_id:
            print(f"  ⚠ Envelope addressed to '{envelope.recipient_id}', "
                  f"we are '{self.agent_id}'. Discarding.")
            return None

        # Step 2: Get sender's verify key from registry
        sender_vk = self.registry.get_signing_verify_key(envelope.sender_id)
        if not sender_vk:
            print(f"  ✗ Sender '{envelope.sender_id}' not in registry or revoked.")
            return None

        # Step 3: Verify Dilithium5 signature
        signed_msg = SignedMessage.from_dict(envelope.signature)
        expected_material = (
            envelope.sender_id +
            envelope.recipient_id +
            envelope.msg_type +
            envelope.kem_ct_hex +
            envelope.encrypted["nonce"]
        ).encode()

        # Override payload with what we expect (don't trust what's in the sig dict)
        signed_msg.payload = expected_material

        if not verify_message(sender_vk, signed_msg):
            print(f"  ✗ Signature verification FAILED for message from "
                  f"'{envelope.sender_id}'. Message rejected.")
            return None

        # Step 4: Decapsulate to recover shared secret
        kem_ct = bytes.fromhex(envelope.kem_ct_hex)
        shared_secret = decapsulate_key(
            self.identity.kem_keypair.secret_key,
            kem_ct,
        )

        # Step 5: Decrypt payload
        plaintext = decrypt_message(shared_secret, envelope.encrypted)
        payload = json.loads(plaintext.decode())

        self._message_log.append({
            "direction": "IN",
            "summary": envelope.header_summary(),
        })
        return payload

    # ── Utils ─────────────────────────────────────────────────

    def message_log(self) -> list[dict]:
        return list(self._message_log)
