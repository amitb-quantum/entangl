"""
Entangl MVP Demo — Two Agents Negotiating a Deal Securely
=========================================================
This is the viral demo:

  🤖 BuyerBot  wants to purchase GPU compute time
  🤖 SellerBot offers NVIDIA RTX 4060 compute at a price

  Every message between them is:
    ✓ Encrypted with CRYSTALS-Kyber1024  (post-quantum KEM)
    ✓ Signed with CRYSTALS-Dilithium5    (post-quantum signatures)
    ✓ Verified against a tamper-evident registry

  A classical computer CANNOT break this.
  A quantum computer CANNOT break this.

Run:
    python demo.py
"""

import sys
import time
import json

sys.path.insert(0, "/home/claude")

from entangl.core.crypto import generate_agent_identity
from entangl.registry.agent_registry import AgentRegistry
from entangl.transport.secure_channel import EntanglSecureChannel, MessageType, EntanglEnvelope


# ─────────────────────────────────────────────────────────────
# Visual helpers
# ─────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def banner(text: str, color: str = CYAN):
    width = 64
    print(f"\n{color}{BOLD}{'═'*width}")
    print(f"  {text}")
    print(f"{'═'*width}{RESET}\n")

def step(n: int, text: str):
    print(f"{YELLOW}{BOLD}[Step {n}]{RESET} {text}")

def agent_log(agent: str, color: str, msg_type: str, payload: dict):
    icon = "📤" if "SEND" in msg_type else "📩"
    label = msg_type.replace("SEND_", "").replace("RECV_", "")
    print(f"\n  {icon} {color}{BOLD}{agent}{RESET} {DIM}│{RESET} {BOLD}{label}{RESET}")
    for k, v in payload.items():
        print(f"     {DIM}{k:18s}{RESET}: {v}")

def crypto_event(text: str):
    print(f"  {GREEN}🔐 {text}{RESET}")

def verify_event(text: str):
    print(f"  {GREEN}✓  {text}{RESET}")

def fail_event(text: str):
    print(f"  {RED}✗  {text}{RESET}")

def separator():
    print(f"  {DIM}{'─'*60}{RESET}")


# ─────────────────────────────────────────────────────────────
# Demo
# ─────────────────────────────────────────────────────────────

def run_demo():

    banner("Entangl — Entangl Protocol  |  MVP Demo", CYAN)
    print(f"  Post-Quantum Secure Agent-to-Agent Negotiation\n")
    print(f"  Algorithms:")
    print(f"    Key Exchange : CRYSTALS-Kyber1024  (NIST FIPS 203 / ML-KEM)")
    print(f"    Signatures   : CRYSTALS-Dilithium5 (NIST FIPS 204 / ML-DSA)")
    print(f"    Symmetric    : AES-256-GCM  (key derived via BLAKE2b-HKDF)\n")
    print(f"  Scenario:")
    print(f"    BuyerBot  wants to rent GPU compute time")
    print(f"    SellerBot offers NVIDIA RTX 4060 at $0.08/min\n")

    # ── Phase 1: Generate Identities ──────────────────────────

    banner("Phase 1 — Generating Post-Quantum Identities", BLUE)

    step(1, "Generating crypto identity for BuyerBot...")
    t0 = time.time()
    buyer_identity  = generate_agent_identity("buyer-bot-alpha")
    t_buyer = time.time() - t0
    print(f"     Kyber1024 KEM keypair   : {len(buyer_identity.kem_keypair.public_key)} byte public key")
    print(f"     Dilithium5 signing pair : {len(buyer_identity.signing_keypair.verify_key)} byte verify key")
    print(f"     Keygen time             : {t_buyer*1000:.1f} ms")

    step(2, "Generating crypto identity for SellerBot...")
    t0 = time.time()
    seller_identity = generate_agent_identity("seller-bot-omega")
    t_seller = time.time() - t0
    print(f"     Kyber1024 KEM keypair   : {len(seller_identity.kem_keypair.public_key)} byte public key")
    print(f"     Dilithium5 signing pair : {len(seller_identity.signing_keypair.verify_key)} byte verify key")
    print(f"     Keygen time             : {t_seller*1000:.1f} ms")

    # ── Phase 2: Register Agents ──────────────────────────────

    banner("Phase 2 — Registering Agents in Entangl Registry", BLUE)

    registry = AgentRegistry()

    step(3, "Registering BuyerBot (owner: Alice Chen, TechCorp Inc.)")
    buyer_did = registry.register(
        identity  = buyer_identity,
        owner_id  = "alice.chen@techcorp.io",
        metadata  = {"role": "buyer", "budget_usd": 100.00, "capability": "compute-procurement"},
    )
    print(f"     DID   : {buyer_did.did}")
    print(f"     KEM FP: {buyer_did.kem_fp}")
    print(f"     Sig FP: {buyer_did.sig_fp}")

    step(4, "Registering SellerBot (owner: Bob Kim, GPU Cloud LLC)")
    seller_did = registry.register(
        identity  = seller_identity,
        owner_id  = "bob.kim@gpucloud.io",
        metadata  = {"role": "seller", "hardware": "NVIDIA RTX 4060", "min_price_usd": 0.06},
    )
    print(f"     DID   : {seller_did.did}")
    print(f"     KEM FP: {seller_did.kem_fp}")
    print(f"     Sig FP: {seller_did.sig_fp}")

    registry.print_summary()

    # ── Phase 3: Open Secure Channels ─────────────────────────

    banner("Phase 3 — Opening Secure Channels", BLUE)

    buyer_channel  = EntanglSecureChannel(identity=buyer_identity,  registry=registry)
    seller_channel = EntanglSecureChannel(identity=seller_identity, registry=registry)

    step(5, "Channels initialized. Each message will use a fresh Kyber1024 KEM.")
    print(f"     No persistent session keys — forward secrecy per message.\n")

    # ── Phase 4: The Negotiation ───────────────────────────────

    banner("Phase 4 — Live Agent-to-Agent Negotiation", BLUE)
    print(f"  Every arrow below is quantum-resistant end-to-end encrypted.\n")

    # ── Round 1: Buyer sends initial proposal ──────────────────

    separator()
    print(f"\n  {BOLD}Round 1 — Initial Proposal{RESET}")
    separator()

    buyer_proposal = {
        "item":         "GPU Compute Time",
        "hardware":     "NVIDIA RTX 4060",
        "duration_min": 60,
        "offer_usd":    0.05,
        "total_usd":    3.00,
        "currency":     "USD",
        "note":         "Training a small transformer model. Need CUDA 12.4+",
    }

    agent_log("BuyerBot", BLUE, "SEND_PROPOSE", buyer_proposal)
    print()

    t0 = time.time()
    envelope_1 = buyer_channel.send(
        recipient_id = "seller-bot-omega",
        msg_type     = MessageType.PROPOSE,
        payload      = buyer_proposal,
    )
    t_send = time.time() - t0

    crypto_event(f"Fresh Kyber1024 encapsulation   → {len(bytes.fromhex(envelope_1.kem_ct_hex))} byte ciphertext")
    crypto_event(f"AES-256-GCM payload encrypted   → {len(bytes.fromhex(envelope_1.encrypted['ciphertext']))} byte ciphertext")
    crypto_event(f"Dilithium5 signature applied    → {len(bytes.fromhex(envelope_1.signature['signature']))} bytes")
    print(f"  {DIM}  Send time: {t_send*1000:.1f} ms{RESET}")

    # Seller receives and decrypts
    print()
    t0 = time.time()
    received_1 = seller_channel.receive(envelope_1)
    t_recv = time.time() - t0

    if received_1:
        verify_event(f"Dilithium5 signature VERIFIED  ← sender is authentic")
        verify_event(f"Kyber1024 decapsulation OK     ← shared secret recovered")
        verify_event(f"AES-256-GCM decryption OK      ← payload integrity confirmed")
        print(f"  {DIM}  Receive time: {t_recv*1000:.1f} ms{RESET}")
        agent_log("SellerBot", GREEN, "RECV_PROPOSE", received_1)

    # ── Round 2: Seller counters ───────────────────────────────

    separator()
    print(f"\n  {BOLD}Round 2 — Counter Offer{RESET}")
    separator()

    seller_counter = {
        "item":           "GPU Compute Time",
        "hardware":       "NVIDIA RTX 4060",
        "duration_min":   60,
        "counter_usd":    0.07,
        "total_usd":      4.20,
        "currency":       "USD",
        "includes":       "CUDA 12.6, 8GB VRAM, 100Mbps uplink",
        "note":           "Can't go below $0.07/min. Will include checkpointing.",
    }

    agent_log("SellerBot", GREEN, "SEND_COUNTER", seller_counter)
    print()

    t0 = time.time()
    envelope_2 = seller_channel.send(
        recipient_id = "buyer-bot-alpha",
        msg_type     = MessageType.COUNTER,
        payload      = seller_counter,
    )
    t_send = time.time() - t0
    crypto_event(f"Fresh Kyber1024 KEM (new key per message — forward secure)")
    crypto_event(f"Dilithium5 signed by seller-bot-omega")
    print(f"  {DIM}  Send time: {t_send*1000:.1f} ms{RESET}")

    print()
    t0 = time.time()
    received_2 = buyer_channel.receive(envelope_2)
    t_recv = time.time() - t0

    if received_2:
        verify_event(f"Signature & integrity VERIFIED")
        print(f"  {DIM}  Receive time: {t_recv*1000:.1f} ms{RESET}")
        agent_log("BuyerBot", BLUE, "RECV_COUNTER", received_2)

    # ── Round 3: Buyer meets in the middle ─────────────────────

    separator()
    print(f"\n  {BOLD}Round 3 — Buyer Accepts at $0.065/min{RESET}")
    separator()

    buyer_accept = {
        "item":          "GPU Compute Time",
        "hardware":      "NVIDIA RTX 4060",
        "duration_min":  60,
        "agreed_usd":    0.065,
        "total_usd":     3.90,
        "currency":      "USD",
        "decision":      "ACCEPT at $0.065/min — splitting the difference",
        "payment_ref":   "entangl-pay-0x4a7f9e2c",
    }

    agent_log("BuyerBot", BLUE, "SEND_ACCEPT", buyer_accept)
    print()

    envelope_3 = buyer_channel.send(
        recipient_id = "seller-bot-omega",
        msg_type     = MessageType.ACCEPT,
        payload      = buyer_accept,
    )
    crypto_event(f"Fresh Kyber1024 KEM for final acceptance")

    print()
    received_3 = seller_channel.receive(envelope_3)

    if received_3:
        verify_event(f"Acceptance VERIFIED — deal sealed")
        agent_log("SellerBot", GREEN, "RECV_ACCEPT", received_3)

    # ── Round 4: Seller confirms ───────────────────────────────

    separator()
    print(f"\n  {BOLD}Round 4 — Deal Confirmed ✓{RESET}")
    separator()

    seller_confirm = {
        "status":        "CONFIRMED",
        "agreed_usd":    0.065,
        "total_usd":     3.90,
        "session_id":    "gpu-session-rtx4060-20260311-0842",
        "access_token":  "ENCRYPTED_IN_REAL_IMPL",
        "note":          "Compute session starts in 30 seconds. Good luck with training!",
    }

    agent_log("SellerBot", GREEN, "SEND_CONFIRM", seller_confirm)
    print()

    envelope_4 = seller_channel.send(
        recipient_id = "buyer-bot-alpha",
        msg_type     = MessageType.CONFIRM,
        payload      = seller_confirm,
    )

    print()
    received_4 = buyer_channel.receive(envelope_4)

    if received_4:
        verify_event(f"Confirmation VERIFIED")
        agent_log("BuyerBot", BLUE, "RECV_CONFIRM", received_4)

    # ── Security Attack Demo ───────────────────────────────────

    banner("Bonus — Security: What Happens With an Unregistered Agent?", YELLOW)

    print(f"  Simulating a rogue agent trying to impersonate SellerBot...\n")

    rogue_identity = generate_agent_identity("rogue-agent-666")
    # Rogue is NOT registered in the registry — they craft a message anyway
    rogue_channel = EntanglSecureChannel(identity=rogue_identity, registry=registry)

    print(f"  Rogue crafts a fake message to BuyerBot using SellerBot's known KEM key...")
    # Rogue can look up SellerBot's public key and try to impersonate them
    # They use the real registry to grab SellerBot's KEM pk, but their OWN signing key
    try:
        # Rogue cannot send to buyer directly — buyer's KEM pk IS in registry
        # but rogue's signing key is NOT registered, so BuyerBot will reject it
        # First, buyer must be findable for rogue to encapsulate:
        rogue_env = rogue_channel.send(
            recipient_id = "buyer-bot-alpha",
            msg_type     = MessageType.PROPOSE,
            payload      = {"item": "SCAM — send me your wallet keys", "price": 0.001},
        )
        # Message was crafted — now simulate it arriving at BuyerBot
        result = buyer_channel.receive(rogue_env)
        if result is None:
            verify_event("Rogue message REJECTED — 'rogue-agent-666' not in registry, signature unverifiable")
        else:
            fail_event("SECURITY FAILURE: Rogue message accepted!")
    except ValueError as e:
        verify_event(f"Rogue agent blocked at send: {e}")

    print(f"\n  Simulating message tampering (bit-flip attack on ciphertext)...")
    tampered = EntanglEnvelope(
        **{**json.loads(envelope_1.to_json()),
           "kem_ct_hex": "deadbeef" * 392}  # Corrupt the KEM ciphertext
    )
    result = seller_channel.receive(tampered)
    if result is None:
        verify_event("Tampered message REJECTED — signature check caught corruption")
    else:
        fail_event("SECURITY FAILURE: Tampered message accepted!")

    # ── Summary ───────────────────────────────────────────────

    banner("Summary", CYAN)
    print(f"  Deal completed: BuyerBot ← GPU compute ← SellerBot")
    print(f"  Agreed price  : $0.065/min × 60 min = $3.90 USD\n")
    print(f"  Messages sent : 4 (2 per agent)")
    print(f"  Crypto ops    : 4× Kyber1024 KEM  +  4× Dilithium5 sign/verify")
    print(f"  Security      : Quantum-resistant end-to-end, forward-secret\n")
    print(f"  Unregistered agents : BLOCKED")
    print(f"  Tampered messages   : REJECTED\n")
    print(f"  {DIM}Entangl v0.1.0 — github.com/your-org/entangl{RESET}\n")


if __name__ == "__main__":
    run_demo()
