# Entangl

**Post-quantum secure communication protocol for AI agents.**

Every agent-to-agent message is encrypted with [CRYSTALS-Kyber1024](https://pq-crystals.org/kyber/) and signed with [CRYSTALS-Dilithium5](https://pq-crystals.org/dilithium/) — both standardized by NIST in 2024 (FIPS 203/204). A sufficiently large quantum computer running Shor's algorithm breaks RSA, ECDH, and ECDSA. It cannot break Entangl.

Built on [Cirq](https://quantumai.google/cirq) and [TensorFlow Quantum](https://www.tensorflow.org/quantum) for the QKD layer.

---

## Why now?

The agentic web is arriving. Agents are already buying ads, booking travel, negotiating compute, and executing financial transactions on behalf of humans. Every one of those interactions is a message between two machines.

Today those messages are protected by RSA and elliptic curve cryptography — algorithms that are mathematically broken by quantum computers. Nation-state adversaries are already running **harvest-now-decrypt-later** attacks: recording encrypted agent traffic today to decrypt it once quantum hardware matures.

Entangl replaces the vulnerable classical layer with NIST-standardized post-quantum algorithms, purpose-built for agent-to-agent communication.

---

## Protocol stack

```
┌──────────────────────────────────────────────────────┐
│              Agent Application Layer                  │
├──────────────────────────────────────────────────────┤
│  Identity Layer    CRYSTALS-Dilithium5  NIST FIPS 204 │  ← Who are you? Prove it.
├──────────────────────────────────────────────────────┤
│  Encryption Layer  CRYSTALS-Kyber1024   NIST FIPS 203 │  ← Forward-secret per message
├──────────────────────────────────────────────────────┤
│  Symmetric Layer   AES-256-GCM + BLAKE2b-HKDF         │
├──────────────────────────────────────────────────────┤
│  QKD Layer         BB84 via Cirq  (optional)          │  ← Information-theoretic security
├──────────────────────────────────────────────────────┤
│  Transport         WebSocket / gRPC                   │
└──────────────────────────────────────────────────────┘
```

| Layer | Algorithm | Standard | Security level |
|-------|-----------|----------|---------------|
| Key exchange | CRYSTALS-Kyber1024 | NIST FIPS 203 (ML-KEM) | 256-bit PQ |
| Signatures | CRYSTALS-Dilithium5 | NIST FIPS 204 (ML-DSA) | 256-bit PQ |
| Symmetric | AES-256-GCM | NIST FIPS 197 | 256-bit |
| QKD | BB84 (Cirq) | Information-theoretic | Unconditional |

---

## Quickstart

```bash
pip install entangl
```

```bash
uvicorn entangl.sdk.python.server:app --host 0.0.0.0 --port 8420
```

```python
import asyncio
from entangl.sdk import EntanglAgent, MessageType

async def main():
    agent = EntanglAgent(name="buyer-bot", owner="alice@corp.io")
    await agent.connect("ws://localhost:8420")

    @agent.on_message
    async def handle(sender: str, msg_type: str, payload: dict):
        print(f"From {sender}: {payload}")

    await agent.send(
        recipient_id = "seller-bot",
        payload      = {"item": "GPU compute", "offer_usd": 0.05},
        msg_type     = MessageType.PROPOSE,
    )
    await agent.listen()

asyncio.run(main())
```

Every `send()` automatically generates a fresh Kyber1024 key encapsulation, encrypts with AES-256-GCM, signs with Dilithium5, and routes through the server — which cannot read the content.

---

## Live demo

```
  📤 BuyerBot  │ PROPOSE  →  offer: $0.05/min
  🔐 Kyber1024 encapsulation → 1568 byte ciphertext
  🔐 Dilithium5 signature    → 4595 bytes
  ✓  Signature VERIFIED  ✓  Decryption OK

  📤 SellerBot │ COUNTER  →  counter: $0.07/min
  ✓  Signature VERIFIED  ✓  Decryption OK

  📤 BuyerBot  │ ACCEPT   →  agreed: $0.065/min
  📤 SellerBot │ CONFIRM  →  session: gpu-session-1773289605

  Deal completed in 1.40s
  Messages routed   : 4
  Server read       : 0 bytes of payload content
  Rogue agent       : BLOCKED
  Tampered message  : REJECTED
```

```bash
git clone https://github.com/amitb-quantum/entangl.git
cd entangl
pip install -e .
python demo.py
python sdk/examples/integration_test.py
```

---

## Quantum Key Distribution (BB84)

The optional QKD layer uses Cirq to simulate BB84. Eavesdroppers are detectable by physics:

```python
from entangl.qkd.bb84 import QKDSession

session = QKDSession(n_qubits=256, eavesdropper=False)
result = session.run()
# QBER: 0.00% — channel secure ✓

session_eve = QKDSession(n_qubits=256, eavesdropper=True)
result_eve = session_eve.run()
# QBER: 22.8% — EAVESDROPPER DETECTED ⚠
```

---

## Agent identity

Every agent has a cryptographic DID:

```
entangl:buyer-bot:797b63c1
         │          │         └── SHA3-256 fingerprint of KEM public key
         │          └──────────── Agent name
         └─────────────────────── Protocol prefix
```

---

## Security properties

| Property | Status | Mechanism |
|----------|--------|-----------|
| Quantum-resistant encryption | ✅ | Kyber1024 (lattice-based) |
| Quantum-resistant signatures | ✅ | Dilithium5 (lattice-based) |
| Forward secrecy | ✅ | Fresh KEM per message |
| Server-side E2E | ✅ | Server routes, cannot decrypt |
| Replay attack prevention | ✅ | Timestamp + 30s window |
| Rogue agent blocking | ✅ | Registry + signature verification |
| Eavesdropper detection | ✅ | BB84 QBER check |
| Human accountability | ✅ | Owner tether in every DID |

---

## Roadmap

- [ ] Phase 4 — Tamper-evident Merkle audit ledger
- [ ] gRPC transport
- [ ] LangChain / CrewAI / AutoGen integrations
- [ ] Key rotation protocol
- [ ] Persistent registry backend (Redis / PostgreSQL)
- [ ] TFQ noise-assisted QKD error correction
- [ ] PyPI release

---

## License

Apache 2.0

---

*Built on [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) and [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/) — the NIST post-quantum standards. QKD layer powered by [Cirq](https://quantumai.google/cirq) and [TensorFlow Quantum](https://www.tensorflow.org/quantum).*
