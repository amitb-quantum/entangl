# Entangl

> Post-quantum secure communication protocol for AI agents.

Every agent-to-agent message is encrypted with **CRYSTALS-Kyber1024** and signed with **CRYSTALS-Dilithium5** — both NIST-standardized, quantum-resistant algorithms. A quantum computer cannot break this.

## Install
```bash
pip install entangl
```

## Quickstart
```python
from entangl.sdk import EntanglAgent, MessageType

agent = EntanglAgent(name="buyer-bot", owner="alice@corp.io")
await agent.connect("ws://localhost:8420")
await agent.send("seller-bot", {"offer": 0.05}, MessageType.PROPOSE)
```

## Protocol stack
```
CRYSTALS-Kyber1024   (ML-KEM)  — NIST FIPS 203 — Key encapsulation
CRYSTALS-Dilithium5  (ML-DSA)  — NIST FIPS 204 — Digital signatures
AES-256-GCM                    — Symmetric encryption
BB84 / Cirq                    — Quantum key distribution (optional layer)
```

## Status

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | Crypto core (Kyber1024 + Dilithium5) | ✅ |
| 2 | Agent DID registry + human tethering | ✅ |
| 3 | Encrypted A2A transport | ✅ |
| 5 | QKD layer (Cirq BB84) | ✅ |
| 6 | SDK + WebSocket server | ✅ |

## License

Apache 2.0
