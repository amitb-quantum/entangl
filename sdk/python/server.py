"""
Entangl Server — Phase 6
=======================
FastAPI + WebSocket server that routes encrypted envelopes between agents.

The server is intentionally "dumb" about message content:
  - It CANNOT decrypt agent messages (no access to private keys)
  - It ONLY routes envelopes based on the plaintext header
  - It maintains the public registry (public keys only)
  - It pushes registry updates to all connected agents

This design means a compromised server cannot read agent communications.
End-to-end encryption is maintained at all times.

Run:
    uvicorn entangl.sdk.python.server:app --host 0.0.0.0 --port 8420 --reload

Or via the convenience script:
    python -m entangl.sdk.python.server
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

log = logging.getLogger("entangl.server")
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ─────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "Entangl — Entangl Protocol Server",
    description = "Post-quantum secure routing layer for AI agent-to-agent communication.",
    version     = "0.1.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ─────────────────────────────────────────────────────────────
# In-memory state
# ─────────────────────────────────────────────────────────────

class AgentConnection:
    """Tracks a connected agent's WebSocket and public identity."""

    def __init__(
        self,
        ws:         WebSocket,
        agent_id:   str,
        owner_id:   str,
        did:        str,
        kem_pk:     str,
        signing_vk: str,
        metadata:   dict,
    ):
        self.ws          = ws
        self.agent_id    = agent_id
        self.owner_id    = owner_id
        self.did         = did
        self.kem_pk      = kem_pk
        self.signing_vk  = signing_vk
        self.metadata    = metadata
        self.connected_at = time.time()
        self.msg_routed  = 0
        self.msg_received = 0

    def public_info(self) -> dict:
        """What we share with other agents about this agent."""
        return {
            "agent_id":     self.agent_id,
            "owner_id":     self.owner_id,
            "did":          self.did,
            "kem_pk":       self.kem_pk,
            "signing_vk":   self.signing_vk,
            "metadata":     self.metadata,
            "registered_at": self.connected_at,
        }


class ConnectionManager:
    """
    Manages all active WebSocket connections.
    Thread-safe via asyncio (single-threaded event loop).
    """

    def __init__(self):
        # agent_id → AgentConnection
        self._connections: dict[str, AgentConnection] = {}
        # Audit log of all server events
        self._audit_log: list[dict] = []
        self._server_start = time.time()
        self._messages_routed = 0
        self._messages_rejected = 0

    # ── Registration ──────────────────────────────────────────

    def register(self, conn: AgentConnection):
        self._connections[conn.agent_id] = conn
        self._log("CONNECT", agent_id=conn.agent_id, owner_id=conn.owner_id)
        log.info(f"  + Agent registered: {conn.did}")

    def unregister(self, agent_id: str):
        if agent_id in self._connections:
            del self._connections[agent_id]
            self._log("DISCONNECT", agent_id=agent_id)
            log.info(f"  - Agent disconnected: {agent_id}")

    # ── Lookup ────────────────────────────────────────────────

    def get(self, agent_id: str) -> Optional[AgentConnection]:
        return self._connections.get(agent_id)

    def all_agents(self) -> list[AgentConnection]:
        return list(self._connections.values())

    def registry_snapshot(self) -> dict[str, dict]:
        """Public registry — what we send to new agents on handshake."""
        return {
            agent_id: conn.public_info()
            for agent_id, conn in self._connections.items()
        }

    # ── Routing ───────────────────────────────────────────────

    async def route(self, envelope_dict: dict) -> bool:
        """
        Route an encrypted envelope to its recipient.

        The server reads ONLY the plaintext header (sender_id, recipient_id).
        The encrypted payload and signature are forwarded untouched.
        The server CANNOT read the message content.

        Returns True if routed, False if recipient not found.
        """
        recipient_id = envelope_dict.get("recipient_id")
        sender_id    = envelope_dict.get("sender_id")

        recipient = self.get(recipient_id)
        if not recipient:
            log.warning(f"  ✗ Route failed: '{recipient_id}' not connected")
            self._messages_rejected += 1
            return False

        wire = json.dumps({"type": "MESSAGE", "envelope": envelope_dict})
        await recipient.ws.send_text(wire)

        self._messages_routed += 1
        if sender_id in self._connections:
            self._connections[sender_id].msg_routed += 1

        self._log(
            "ROUTE",
            sender_id    = sender_id,
            recipient_id = recipient_id,
            msg_type     = envelope_dict.get("msg_type", "?"),
        )
        return True

    async def broadcast_registry_update(self, new_agent: AgentConnection):
        """
        Notify all connected agents that a new agent has joined.
        This lets agents encrypt to the new agent immediately.
        """
        update = json.dumps({
            "type":  "REGISTRY_UPDATE",
            "agent": new_agent.public_info(),
        })
        for conn in self.all_agents():
            if conn.agent_id != new_agent.agent_id:
                try:
                    await conn.ws.send_text(update)
                except Exception:
                    pass  # Will be cleaned up on next recv

    # ── Audit ─────────────────────────────────────────────────

    def _log(self, event: str, **kwargs):
        self._audit_log.append({
            "event":     event,
            "timestamp": time.time(),
            **kwargs,
        })
        # Keep last 10k events
        if len(self._audit_log) > 10_000:
            self._audit_log = self._audit_log[-10_000:]

    def stats(self) -> dict:
        uptime = time.time() - self._server_start
        return {
            "uptime_seconds":    round(uptime, 1),
            "active_agents":     len(self._connections),
            "messages_routed":   self._messages_routed,
            "messages_rejected": self._messages_rejected,
            "audit_log_entries": len(self._audit_log),
        }


# Global connection manager
manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────
# WebSocket endpoint — the main A2A routing channel
# ─────────────────────────────────────────────────────────────

@app.websocket("/")
async def websocket_endpoint(ws: WebSocket):
    """
    Main WebSocket endpoint for agent connections.

    Protocol:
        1. Agent connects
        2. Agent sends HANDSHAKE with public keys
        3. Server responds with ACK + registry snapshot
        4. Server broadcasts REGISTRY_UPDATE to all others
        5. Agent sends MESSAGE frames containing encrypted envelopes
        6. Server routes envelopes to recipients (cannot decrypt)
        7. Agent disconnects → server broadcasts removal (future: tombstone)

    Frame types (client → server):
        HANDSHAKE   : Register agent and public keys
        MESSAGE     : Encrypted envelope to route
        LOOKUP      : Request another agent's public keys
        PONG        : Response to server PING

    Frame types (server → client):
        ACK              : Handshake accepted + registry snapshot
        REGISTRY_UPDATE  : New agent joined
        MESSAGE          : Incoming envelope from another agent
        PING             : Keepalive
        ERROR            : Something went wrong
    """
    await ws.accept()
    agent_id = None

    try:
        # ── Step 1: Wait for HANDSHAKE ────────────────────────
        raw = await asyncio.wait_for(ws.receive_text(), timeout=15.0)
        msg = json.loads(raw)

        if msg.get("type") != "HANDSHAKE":
            await ws.send_text(json.dumps({
                "status": "error",
                "error":  "First message must be HANDSHAKE",
            }))
            await ws.close()
            return

        agent_id   = msg["agent_id"]
        owner_id   = msg.get("owner_id", "unknown")
        did        = msg.get("did", f"entangl:{agent_id}:unknown")
        kem_pk     = msg["kem_pk"]
        signing_vk = msg["signing_vk"]
        metadata   = msg.get("metadata", {})

        # ── Step 2: Register agent ────────────────────────────
        conn = AgentConnection(
            ws         = ws,
            agent_id   = agent_id,
            owner_id   = owner_id,
            did        = did,
            kem_pk     = kem_pk,
            signing_vk = signing_vk,
            metadata   = metadata,
        )
        manager.register(conn)

        # ── Step 3: ACK with registry snapshot ────────────────
        ack = json.dumps({
            "status":   "ok",
            "did":      did,
            "registry": manager.registry_snapshot(),
            "server_time": time.time(),
        })
        await ws.send_text(ack)
        log.info(f"  ✓ ACK sent to {agent_id} — registry has {len(manager.all_agents())} agents")

        # ── Step 4: Broadcast new agent to all peers ──────────
        await manager.broadcast_registry_update(conn)

        # ── Step 5: Message loop ──────────────────────────────
        async for raw in ws.iter_text():
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({
                    "type": "ERROR", "error": "Invalid JSON"
                }))
                continue

            frame_type = msg.get("type")

            if frame_type == "MESSAGE":
                # Route encrypted envelope — server never decrypts
                envelope = msg.get("envelope", {})
                routed = await manager.route(envelope)
                if not routed:
                    await ws.send_text(json.dumps({
                        "type":  "ERROR",
                        "error": f"Recipient '{envelope.get('recipient_id')}' not connected",
                    }))

            elif frame_type == "LOOKUP":
                # Agent asking for a peer's public keys
                lookup_id = msg.get("agent_id")
                peer = manager.get(lookup_id)
                if peer:
                    await ws.send_text(json.dumps({
                        "type":  "REGISTRY_UPDATE",
                        "agent": peer.public_info(),
                    }))
                else:
                    await ws.send_text(json.dumps({
                        "type":  "ERROR",
                        "error": f"Agent '{lookup_id}' not found",
                    }))

            elif frame_type == "PONG":
                pass  # Keepalive acknowledged

            else:
                await ws.send_text(json.dumps({
                    "type":  "ERROR",
                    "error": f"Unknown frame type: {frame_type}",
                }))

    except asyncio.TimeoutError:
        log.warning("  ✗ Handshake timeout — closing connection")
    except WebSocketDisconnect:
        log.info(f"  ~ {agent_id or 'unknown'} disconnected")
    except Exception as e:
        log.error(f"  ✗ WebSocket error for {agent_id}: {e}")
    finally:
        if agent_id:
            manager.unregister(agent_id)


# ─────────────────────────────────────────────────────────────
# REST endpoints — monitoring and registry
# ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check — used by load balancers and monitoring."""
    return {"status": "ok", "timestamp": time.time()}


@app.get("/stats")
async def stats():
    """Server statistics — messages routed, active agents, uptime."""
    return manager.stats()


@app.get("/registry")
async def registry():
    """
    Public registry of all currently connected agents.
    Returns only public keys — no private key material.
    """
    agents = [conn.public_info() for conn in manager.all_agents()]
    return {
        "count":  len(agents),
        "agents": agents,
    }


@app.get("/registry/{agent_id}")
async def registry_lookup(agent_id: str):
    """Look up a specific agent's public information."""
    conn = manager.get(agent_id)
    if not conn:
        return JSONResponse(
            status_code = 404,
            content     = {"error": f"Agent '{agent_id}' not found or not connected"},
        )
    return conn.public_info()


@app.get("/audit")
async def audit_log(limit: int = 100):
    """Recent server audit log — last N events."""
    return {
        "events": manager._audit_log[-limit:],
        "total":  len(manager._audit_log),
    }


# ─────────────────────────────────────────────────────────────
# Startup banner
# ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    log.info("")
    log.info("  ═══════════════════════════════════════════════")
    log.info("    Entangl Server v0.1.0 — Starting")
    log.info("  ═══════════════════════════════════════════════")
    log.info("    Protocol : Entangl Protocol")
    log.info("    Crypto   : Kyber1024 + Dilithium5 (NIST PQ)")
    log.info("    Routing  : Encrypted — server cannot read payloads")
    log.info("  ═══════════════════════════════════════════════")
    log.info("")


# ─────────────────────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "entangl.sdk.python.server:app",
        host        = "0.0.0.0",
        port        = 8420,
        reload      = False,
        log_level   = "info",
    )
