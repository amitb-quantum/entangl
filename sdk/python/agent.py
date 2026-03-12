"""
Entangl SDK — EntanglAgent
======================
The main developer-facing class. Drop this into any agent framework.

Minimal usage:
    from entangl.sdk import EntanglAgent

    agent = EntanglAgent(name="my-agent", owner="alice@corp.io")
    await agent.connect("ws://localhost:8420")

    # Send a secure message
    await agent.send("other-agent", {"action": "buy", "qty": 10})

    # Listen for incoming messages
    @agent.on_message
    async def handle(sender: str, payload: dict):
        print(f"From {sender}: {payload}")

    await agent.listen()

Framework integrations:
    LangChain : QSAPLangChainTool
    CrewAI    : QSAPCrewTool
    AutoGen   : QSAPAutoGenAgent (coming in v0.2)
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import websockets
from websockets.exceptions import ConnectionClosed

from entangl.core.crypto import (
    AgentCryptoIdentity,
    generate_agent_identity,
    fingerprint,
)
from entangl.registry.agent_registry import AgentRegistry
from entangl.transport.secure_channel import (
    MessageType,
    EntanglEnvelope,
    EntanglSecureChannel,
)

log = logging.getLogger("entangl.sdk")


# ─────────────────────────────────────────────────────────────
# Message handler type
# ─────────────────────────────────────────────────────────────

MessageHandler = Callable[[str, str, dict], Awaitable[None]]
# (sender_id, msg_type, payload) → None


# ─────────────────────────────────────────────────────────────
# Connection state
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentStats:
    messages_sent:     int   = 0
    messages_received: int   = 0
    messages_rejected: int   = 0
    bytes_sent:        int   = 0
    bytes_received:    int   = 0
    connected_since:   float = field(default_factory=time.time)

    def uptime_seconds(self) -> float:
        return time.time() - self.connected_since


# ─────────────────────────────────────────────────────────────
# EntanglAgent — the main SDK class
# ─────────────────────────────────────────────────────────────

class EntanglAgent:
    """
    A quantum-secure AI agent that communicates via the Entangl protocol.

    Each agent has:
        - A post-quantum cryptographic identity (Kyber1024 + Dilithium5)
        - A DID registered in the Entangl network
        - A secure WebSocket channel to the Entangl server
        - A simple async API for send/receive

    Thread-safe. Fully async.

    Args:
        name:     Unique agent identifier. e.g. "buyer-bot-alpha"
        owner:    Human/org accountability tether. e.g. "alice@corp.io"
        server_url: Entangl WebSocket server. Default: ws://localhost:8420
        metadata: Optional dict of agent capabilities and info.
        log_level: Logging level. Default: WARNING (quiet).
    """

    def __init__(
        self,
        name:       str,
        owner:      str,
        server_url: str  = "ws://localhost:8420",
        metadata:   Optional[dict] = None,
        log_level:  int  = logging.WARNING,
    ):
        logging.basicConfig(level=log_level)

        self.name       = name
        self.owner      = owner
        self.server_url = server_url
        self.metadata   = metadata or {}

        # Generated at construction — identity is stable for the agent's lifetime
        log.info(f"[{name}] Generating post-quantum identity...")
        self._identity: AgentCryptoIdentity = generate_agent_identity(name)
        self._registry: AgentRegistry       = AgentRegistry()
        self._channel:  Optional[EntanglSecureChannel] = None

        # WebSocket connection (set after connect())
        self._ws = None
        self._connected = False
        self._running   = False

        # Message handlers registered via @agent.on_message
        self._handlers: list[MessageHandler] = []

        # Outbound message queue (buffered while connecting)
        self._send_queue: asyncio.Queue = asyncio.Queue()

        # Stats
        self.stats = AgentStats()

        log.info(f"[{name}] Identity ready: {self.did}")

    # ── Identity ──────────────────────────────────────────────

    @property
    def did(self) -> str:
        """This agent's Entangl DID. e.g. entangl:buyer-bot-alpha:1746aa4f"""
        fp = fingerprint(self._identity.kem_keypair.public_key)[:8]
        return f"entangl:{self.name}:{fp}"

    @property
    def kem_public_key_hex(self) -> str:
        return self._identity.kem_keypair.public_key.hex()

    @property
    def signing_verify_key_hex(self) -> str:
        return self._identity.signing_keypair.verify_key.hex()

    # ── Connection ────────────────────────────────────────────

    async def connect(self, server_url: Optional[str] = None) -> "EntanglAgent":
        """
        Connect to the Entangl server and register this agent.

        Sends a HANDSHAKE message containing this agent's public keys.
        The server registers the agent and makes it discoverable.

        Args:
            server_url: Override the server URL set at construction.

        Returns:
            self (for chaining: await agent.connect().listen())

        Raises:
            ConnectionError: If server is unreachable.
        """
        url = server_url or self.server_url
        log.info(f"[{self.name}] Connecting to {url}...")

        try:
            self._ws = await websockets.connect(
                url,
                ping_interval=20,
                ping_timeout=10,
            )
        except Exception as e:
            raise ConnectionError(f"Cannot reach Entangl server at {url}: {e}")

        self._connected = True
        log.info(f"[{self.name}] WebSocket connected")

        # Send HANDSHAKE — register with the server
        handshake = {
            "type":        "HANDSHAKE",
            "agent_id":    self.name,
            "owner_id":    self.owner,
            "did":         self.did,
            "kem_pk":      self.kem_public_key_hex,
            "signing_vk":  self.signing_verify_key_hex,
            "metadata":    self.metadata,
            "timestamp":   time.time(),
        }
        await self._ws.send(json.dumps(handshake))
        log.info(f"[{self.name}] Handshake sent")

        # Wait for server ACK
        raw_ack = await asyncio.wait_for(self._ws.recv(), timeout=10.0)
        ack = json.loads(raw_ack)

        if ack.get("status") != "ok":
            raise ConnectionError(
                f"Server rejected handshake: {ack.get('error', 'unknown')}"
            )

        # Server sends back the current registry snapshot
        # so we can encrypt messages to other agents immediately
        registry_data = ack.get("registry", {})
        for agent_id, agent_info in registry_data.items():
            if agent_id != self.name:
                self._registry._agents[agent_id] = _agent_did_from_dict(agent_info)

        # Set up our local secure channel
        # Register ourselves locally too (for receive-side verification)
        try:
            self._registry.register(
                identity  = self._identity,
                owner_id  = self.owner,
                metadata  = self.metadata,
            )
        except ValueError:
            pass  # Already registered (reconnect scenario)

        self._channel = EntanglSecureChannel(
            identity = self._identity,
            registry = self._registry,
        )

        log.info(
            f"[{self.name}] Registered. "
            f"Registry has {len(self._registry)} active agents."
        )
        return self

    async def disconnect(self):
        """Gracefully close the WebSocket connection."""
        self._running   = False
        self._connected = False
        if self._ws:
            await self._ws.close()
            log.info(f"[{self.name}] Disconnected")

    # ── Sending ───────────────────────────────────────────────

    async def send(
        self,
        recipient_id: str,
        payload:      dict,
        msg_type:     str = MessageType.PROPOSE,
    ) -> bool:
        """
        Send a quantum-secure message to another agent.

        Automatically:
          - Fetches recipient's public key from the registry
          - Generates a fresh Kyber1024 key encapsulation
          - Encrypts payload with AES-256-GCM
          - Signs with Dilithium5
          - Transmits over WebSocket

        Args:
            recipient_id: Target agent's name. e.g. "seller-bot"
            payload:      Dict of message content.
            msg_type:     Entangl message type. Default: PROPOSE.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self._connected or not self._channel:
            log.error(f"[{self.name}] Not connected. Call connect() first.")
            return False

        # Ensure recipient is in our local registry
        if not self._registry.lookup(recipient_id):
            log.warning(
                f"[{self.name}] Recipient '{recipient_id}' not in local registry. "
                f"Requesting from server..."
            )
            await self._request_peer_keys(recipient_id)

        try:
            envelope = self._channel.send(
                recipient_id = recipient_id,
                msg_type     = msg_type,
                payload      = payload,
            )
        except ValueError as e:
            log.error(f"[{self.name}] Cannot encrypt to '{recipient_id}': {e}")
            return False

        wire = json.dumps({
            "type":     "MESSAGE",
            "envelope": json.loads(envelope.to_json()),
        })

        await self._ws.send(wire)
        self.stats.messages_sent += 1
        self.stats.bytes_sent    += len(wire)
        log.info(f"[{self.name}] → {recipient_id} [{msg_type}]")
        return True

    async def reply(
        self,
        original_envelope: EntanglEnvelope,
        payload:           dict,
        msg_type:          str = MessageType.COUNTER,
    ) -> bool:
        """
        Convenience method: reply to an incoming envelope.

        Args:
            original_envelope: The envelope you received.
            payload:           Your reply payload.
            msg_type:          Reply type. Default: COUNTER.
        """
        return await self.send(
            recipient_id = original_envelope.sender_id,
            payload      = payload,
            msg_type     = msg_type,
        )

    # ── Receiving ─────────────────────────────────────────────

    def on_message(self, handler: MessageHandler) -> MessageHandler:
        """
        Decorator to register a message handler.

        Usage:
            @agent.on_message
            async def handle(sender: str, msg_type: str, payload: dict):
                print(f"{sender} says: {payload}")

        Multiple handlers can be registered. All are called for each message.
        """
        self._handlers.append(handler)
        return handler

    async def listen(self):
        """
        Start listening for incoming messages. Runs until disconnect() is called.

        Processes:
          - REGISTRY_UPDATE : Server pushed new agent to registry
          - MESSAGE         : Incoming encrypted A2A message
          - PING            : Server keepalive
          - ERROR           : Server error notification
        """
        self._running = True
        log.info(f"[{self.name}] Listening for messages...")

        try:
            async for raw in self._ws:
                if not self._running:
                    break

                self.stats.bytes_received += len(raw)

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning(f"[{self.name}] Received non-JSON message, skipping")
                    continue

                msg_type = msg.get("type")

                if msg_type == "REGISTRY_UPDATE":
                    # New agent joined — add to local registry
                    agent_info = msg.get("agent")
                    if agent_info:
                        agent_id = agent_info["agent_id"]
                        if not self._registry.lookup(agent_id):
                            self._registry._agents[agent_id] = (
                                _agent_did_from_dict(agent_info)
                            )
                            log.info(f"[{self.name}] Registry updated: +{agent_id}")

                elif msg_type == "MESSAGE":
                    await self._handle_incoming(msg)

                elif msg_type == "PING":
                    await self._ws.send(json.dumps({"type": "PONG"}))

                elif msg_type == "ERROR":
                    log.error(f"[{self.name}] Server error: {msg.get('error')}")

        except ConnectionClosed:
            log.info(f"[{self.name}] Connection closed by server")
        except Exception as e:
            log.error(f"[{self.name}] Listen error: {e}")
        finally:
            self._connected = False

    async def _handle_incoming(self, msg: dict):
        """Verify, decrypt, and dispatch an incoming MESSAGE frame."""
        if not self._channel:
            return

        try:
            envelope_dict = msg["envelope"]
            envelope = EntanglEnvelope(**envelope_dict)
        except Exception as e:
            log.warning(f"[{self.name}] Malformed envelope: {e}")
            self.stats.messages_rejected += 1
            return

        # Ensure sender is in local registry (trust chain)
        sender_id = envelope.sender_id
        if not self._registry.lookup(sender_id):
            log.warning(
                f"[{self.name}] Unknown sender '{sender_id}' — "
                f"not in registry, rejecting"
            )
            self.stats.messages_rejected += 1
            return

        # Verify + decrypt
        payload = self._channel.receive(envelope)
        if payload is None:
            log.warning(
                f"[{self.name}] Message from '{sender_id}' "
                f"failed verification — rejected"
            )
            self.stats.messages_rejected += 1
            return

        self.stats.messages_received += 1
        log.info(f"[{self.name}] ← {sender_id} [{envelope.msg_type}] ✓")

        # Dispatch to all registered handlers
        for handler in self._handlers:
            try:
                await handler(sender_id, envelope.msg_type, payload)
            except Exception as e:
                log.error(f"[{self.name}] Handler error: {e}")

    async def _request_peer_keys(self, agent_id: str):
        """Ask the server for a peer's public keys."""
        await self._ws.send(json.dumps({
            "type":     "LOOKUP",
            "agent_id": agent_id,
        }))
        # Wait briefly for REGISTRY_UPDATE response
        await asyncio.sleep(0.1)

    # ── Context manager ───────────────────────────────────────

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()

    # ── Repr ──────────────────────────────────────────────────

    def __repr__(self) -> str:
        status = "connected" if self._connected else "disconnected"
        return f"EntanglAgent(name={self.name!r}, owner={self.owner!r}, status={status})"


# ─────────────────────────────────────────────────────────────
# Helper: reconstruct AgentDID from server dict
# ─────────────────────────────────────────────────────────────

def _agent_did_from_dict(d: dict):
    """Reconstruct an AgentDID object from a server-sent dict."""
    from entangl.registry.agent_registry import AgentDID
    return AgentDID(
        did            = d["did"],
        agent_id       = d["agent_id"],
        owner_id       = d["owner_id"],
        kem_pk_hex     = d["kem_pk"],
        signing_vk_hex = d["signing_vk"],
        kem_fp         = d.get("kem_fp", ""),
        sig_fp         = d.get("sig_fp", ""),
        registered_at  = d.get("registered_at", time.time()),
        status         = "active",
        metadata       = d.get("metadata", {}),
    )
