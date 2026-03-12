"""
Entangl Agent Registry — Phase 2
================================
Decentralized Identity (DID) style registry for Entangl agents.

Every agent that wants to participate in the Entangl network must:
  1. Generate a cryptographic identity (Phase 1)
  2. Register with a human owner tether (this module)
  3. Publish their public bundle so others can verify and encrypt to them

The registry stores ONLY public keys — no secrets ever touch it.

Design mirrors W3C DID (Decentralized Identifiers) but purpose-built
for agent-to-agent communication with post-quantum cryptography.
"""

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional

from entangl.core.crypto import (
    AgentCryptoIdentity,
    SigningKeyPair,
    KEMKeyPair,
    sign_message,
    verify_message,
    fingerprint,
)


# ─────────────────────────────────────────────────────────────
# Agent DID Document
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentDID:
    """
    A Entangl Decentralized Identifier document for an agent.

    Think of this like a business card published to the registry.
    Anyone can read it. It contains only public material.

    Fields:
        did         : "entangl:<agent_id>:<fingerprint>" — globally unique
        agent_id    : Human-readable name  (e.g. "buyer-bot-alpha")
        owner_id    : Human/org that controls this agent (accountability)
        kem_pk_hex  : Kyber1024 public key (hex) — others encrypt TO this agent
        signing_vk_hex: Dilithium5 verify key (hex) — others verify signatures FROM this agent
        kem_fp      : Short fingerprint of the KEM public key
        sig_fp      : Short fingerprint of the signing verify key
        registered_at: Unix timestamp of registration
        status      : "active" | "revoked" | "suspended"
    """
    did:            str
    agent_id:       str
    owner_id:       str
    kem_pk_hex:     str
    signing_vk_hex: str
    kem_fp:         str
    sig_fp:         str
    registered_at:  float
    status:         str = "active"
    metadata:       dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, d: dict) -> "AgentDID":
        return cls(**d)


def _build_did(agent_id: str, kem_pk: bytes) -> str:
    """
    Construct a Entangl DID string.
    Format: entangl:<agent_id>:<8-char key fingerprint>

    Example: entangl:buyer-bot-alpha:a1b2c3d4
    """
    fp_short = hashlib.sha3_256(kem_pk).hexdigest()[:8]
    return f"entangl:{agent_id}:{fp_short}"


# ─────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────

class AgentRegistry:
    """
    In-memory agent registry (Phase 1 local dev version).

    Production version would be backed by a distributed ledger
    or a Byzantine-fault-tolerant database for tamper evidence.

    Key operations:
        register()   — Add a new agent to the registry
        lookup()     — Find an agent by agent_id or DID
        revoke()     — Invalidate a compromised agent
        list_agents()— Enumerate all active agents
    """

    def __init__(self):
        # Primary store: agent_id → AgentDID
        self._agents: dict[str, AgentDID] = {}
        # Secondary index: did → agent_id
        self._did_index: dict[str, str] = {}
        # Audit log of all registry operations
        self._audit_log: list[dict] = []

    # ── Registration ──────────────────────────────────────────

    def register(
        self,
        identity: AgentCryptoIdentity,
        owner_id: str,
        metadata: Optional[dict] = None,
    ) -> AgentDID:
        """
        Register a new agent in the Entangl network.

        Args:
            identity: Full AgentCryptoIdentity from generate_agent_identity().
            owner_id: Human or organization that owns and is responsible for this agent.
                      This is the accountability tether — critical for enterprise adoption.
            metadata: Optional dict with agent capabilities, version, description, etc.

        Returns:
            AgentDID document (the public record of this agent in the registry).

        Raises:
            ValueError: If agent_id is already registered.
        """
        if identity.agent_id in self._agents:
            raise ValueError(
                f"Agent '{identity.agent_id}' is already registered. "
                f"Use revoke() and re-register if keys need rotation."
            )

        kem_pk  = identity.kem_keypair.public_key
        sig_vk  = identity.signing_keypair.verify_key

        did_str = _build_did(identity.agent_id, kem_pk)

        agent_did = AgentDID(
            did            = did_str,
            agent_id       = identity.agent_id,
            owner_id       = owner_id,
            kem_pk_hex     = kem_pk.hex(),
            signing_vk_hex = sig_vk.hex(),
            kem_fp         = fingerprint(kem_pk),
            sig_fp         = fingerprint(sig_vk),
            registered_at  = time.time(),
            status         = "active",
            metadata       = metadata or {},
        )

        self._agents[identity.agent_id] = agent_did
        self._did_index[did_str]         = identity.agent_id

        self._log_event("REGISTER", agent_id=identity.agent_id, owner_id=owner_id)
        return agent_did

    # ── Lookup ────────────────────────────────────────────────

    def lookup(self, agent_id: str) -> Optional[AgentDID]:
        """
        Look up an agent's public DID document by agent_id.

        Returns None if agent is not found or has been revoked.
        Active status is checked automatically.
        """
        doc = self._agents.get(agent_id)
        if doc and doc.status == "active":
            return doc
        return None

    def lookup_by_did(self, did: str) -> Optional[AgentDID]:
        """Look up an agent by their full DID string."""
        agent_id = self._did_index.get(did)
        if agent_id:
            return self.lookup(agent_id)
        return None

    def get_kem_public_key(self, agent_id: str) -> Optional[bytes]:
        """
        Get an agent's Kyber1024 public key for encrypting messages TO them.
        Returns None if agent not found or revoked.
        """
        doc = self.lookup(agent_id)
        if doc:
            return bytes.fromhex(doc.kem_pk_hex)
        return None

    def get_signing_verify_key(self, agent_id: str) -> Optional[bytes]:
        """
        Get an agent's Dilithium5 verify key for verifying signatures FROM them.
        Returns None if agent not found or revoked.
        """
        doc = self.lookup(agent_id)
        if doc:
            return bytes.fromhex(doc.signing_vk_hex)
        return None

    # ── Revocation ────────────────────────────────────────────

    def revoke(self, agent_id: str, reason: str = "manual") -> bool:
        """
        Revoke an agent's registration.

        Once revoked, the agent cannot participate in secure channels.
        All future messages from this agent will fail verification.
        The record is retained for audit purposes (never deleted).

        Args:
            agent_id: The agent to revoke.
            reason:   Human-readable reason (logged for audit trail).

        Returns:
            True if successfully revoked, False if not found.
        """
        doc = self._agents.get(agent_id)
        if not doc:
            return False
        doc.status = "revoked"
        doc.metadata["revocation_reason"] = reason
        doc.metadata["revoked_at"] = time.time()
        self._log_event("REVOKE", agent_id=agent_id, reason=reason)
        return True

    # ── Listing ───────────────────────────────────────────────

    def list_agents(self, include_revoked: bool = False) -> list[AgentDID]:
        """List all registered agents."""
        agents = list(self._agents.values())
        if not include_revoked:
            agents = [a for a in agents if a.status == "active"]
        return agents

    def __len__(self) -> int:
        return len([a for a in self._agents.values() if a.status == "active"])

    # ── Audit Log ─────────────────────────────────────────────

    def _log_event(self, event_type: str, **kwargs):
        self._audit_log.append({
            "event":     event_type,
            "timestamp": time.time(),
            **kwargs,
        })

    def get_audit_log(self) -> list[dict]:
        return list(self._audit_log)

    # ── Display ───────────────────────────────────────────────

    def print_summary(self):
        active  = [a for a in self._agents.values() if a.status == "active"]
        revoked = [a for a in self._agents.values() if a.status == "revoked"]
        print(f"\n{'='*60}")
        print(f"  Entangl Agent Registry — {len(active)} active, {len(revoked)} revoked")
        print(f"{'='*60}")
        for agent in active:
            print(f"  ✓  {agent.did}")
            print(f"     Owner   : {agent.owner_id}")
            print(f"     KEM FP  : {agent.kem_fp}")
            print(f"     Sig FP  : {agent.sig_fp}")
            print(f"     Since   : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(agent.registered_at))}")
            print()
        for agent in revoked:
            reason = agent.metadata.get("revocation_reason", "unknown")
            print(f"  ✗  {agent.did}  [REVOKED: {reason}]")
        print(f"{'='*60}\n")
