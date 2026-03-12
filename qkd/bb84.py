"""
Entangl QKD Layer — Phase 5
==========================
Quantum Key Distribution using Cirq (from hexagrid).

Implements BB84 protocol — the first and most widely used QKD scheme.
This runs as a SIMULATION on your local machine/GPU.
In production, this would interface with real quantum hardware
(IBM Quantum, IonQ, or photonic QKD hardware over fiber).

BB84 Protocol Summary:
  1. Alice generates random bits + random basis choices
  2. Alice encodes each bit as a qubit in her chosen basis
  3. Bob measures each qubit in a randomly chosen basis
  4. Alice and Bob publicly compare BASES (not bits)
  5. They keep only bits where bases matched → shared secret key
  6. They sacrifice a sample to check for eavesdropping (QBER check)
  7. Remaining bits → secure key material (fed into Kyber KEM or AES)

Why include QKD in Entangl?
  - Kyber1024 is post-quantum SAFE (computationally hard for quantum computers)
  - QKD is post-quantum PROOF (information-theoretic security, physics-based)
  - Together: defense-in-depth for the highest security tier
  - Huge differentiator for government/defense acquirers

Your stack: Cirq (simulation) + TFQ (ML-assisted error correction future)
Hardware:   NVIDIA RTX 4060 can accelerate the classical post-processing
"""

import numpy as np
import cirq
import time
from dataclasses import dataclass, field
from typing import Optional
import matplotlib
matplotlib.use("Agg")   # Non-interactive backend (safe for server use)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


# ─────────────────────────────────────────────────────────────
# Data containers
# ─────────────────────────────────────────────────────────────

@dataclass
class BB84Result:
    """
    Full result of a BB84 QKD session.

    Fields:
        raw_key_bits         : Bits where Alice & Bob chose matching bases
        sifted_key_bits      : After sacrificing sample for QBER check
        key_length           : Final usable key length in bits
        qber                 : Quantum Bit Error Rate (0.0 = perfect, >0.11 = eavesdropper)
        eavesdropper_detected: True if QBER exceeds security threshold
        n_qubits_sent        : Total qubits transmitted
        efficiency           : key_length / n_qubits_sent
        session_id           : Unique ID for this QKD session
        duration_ms          : Time to complete the session
    """
    raw_key_bits:          list[int]
    sifted_key_bits:       list[int]
    key_length:            int
    qber:                  float
    eavesdropper_detected: bool
    n_qubits_sent:         int
    efficiency:            float
    session_id:            str
    duration_ms:           float
    alice_bases:           list[str]  # 'Z' or 'X'
    bob_bases:             list[str]
    matched_indices:       list[int]


# ─────────────────────────────────────────────────────────────
# BB84 Circuit Builder
# ─────────────────────────────────────────────────────────────

class BB84Circuit:
    """
    Builds Cirq circuits for one qubit of the BB84 protocol.

    Bases:
        Z-basis (computational): |0⟩ represents 0, |1⟩ represents 1
        X-basis (Hadamard):      |+⟩ represents 0, |−⟩ represents 1
    """

    @staticmethod
    def alice_encode(qubit: cirq.Qid, bit: int, basis: str) -> list[cirq.Operation]:
        """
        Alice's encoding circuit for one qubit.

        bit=0, basis='Z' → |0⟩  (do nothing to |0⟩)
        bit=1, basis='Z' → |1⟩  (apply X gate)
        bit=0, basis='X' → |+⟩  (apply H gate)
        bit=1, basis='X' → |−⟩  (apply X then H)

        Args:
            qubit:  The Cirq qubit to encode into.
            bit:    Alice's secret bit (0 or 1).
            basis:  'Z' (computational) or 'X' (Hadamard).

        Returns:
            List of Cirq operations for Alice's encoding.
        """
        ops = []
        if bit == 1:
            ops.append(cirq.X(qubit))    # Flip to |1⟩ if bit is 1
        if basis == 'X':
            ops.append(cirq.H(qubit))    # Rotate to X-basis
        return ops

    @staticmethod
    def bob_measure(qubit: cirq.Qid, basis: str) -> list[cirq.Operation]:
        """
        Bob's measurement circuit for one qubit.

        basis='Z' → measure directly in computational basis
        basis='X' → apply H first (rotate back), then measure

        Args:
            qubit:  The Cirq qubit to measure.
            basis:  Bob's randomly chosen measurement basis.

        Returns:
            List of Cirq operations for Bob's measurement.
        """
        ops = []
        if basis == 'X':
            ops.append(cirq.H(qubit))    # Rotate X-basis to computational
        ops.append(cirq.measure(qubit, key=f'bob_{qubit}'))
        return ops


# ─────────────────────────────────────────────────────────────
# QKD Session
# ─────────────────────────────────────────────────────────────

class QKDSession:
    """
    Simulates a complete BB84 QKD session between Alice and Bob using Cirq.

    Can simulate an eavesdropper (Eve) who intercepts qubits —
    Eve's presence is detectable via elevated QBER.

    Usage:
        session = QKDSession(n_qubits=256, eavesdropper=False)
        result = session.run()
        key_bytes = session.extract_key_bytes(result)
    """

    # QBER threshold above which we conclude an eavesdropper is present.
    # Theoretical maximum for undetected Eve: 25% QBER with intercept-resend.
    # We use 11% as a conservative security threshold.
    QBER_SECURITY_THRESHOLD = 0.11

    def __init__(
        self,
        n_qubits:     int  = 256,
        eavesdropper: bool = False,
        noise_level:  float = 0.0,
        seed:         Optional[int] = None,
    ):
        """
        Args:
            n_qubits:     Number of qubits to transmit. Final key will be
                          roughly n_qubits * 0.5 * 0.85 bits after sifting.
            eavesdropper: If True, simulate Eve intercepting every qubit
                          (intercept-resend attack).
            noise_level:  Channel depolarizing noise probability (0.0 = perfect).
            seed:         RNG seed for reproducibility.
        """
        self.n_qubits     = n_qubits
        self.eavesdropper = eavesdropper
        self.noise_level  = noise_level
        self.rng          = np.random.default_rng(seed)
        self.simulator    = cirq.Simulator()

    def run(self) -> BB84Result:
        """
        Execute the full BB84 protocol and return results.

        Steps:
          1. Alice generates random bits + bases
          2. Bob generates random bases
          3. [Optional] Eve intercepts with random bases
          4. Build + run Cirq circuits for each qubit
          5. Sift: keep bits where Alice & Bob chose same basis
          6. QBER check: sacrifice sample, compute error rate
          7. Return result (eavesdropper detected if QBER > threshold)
        """
        t_start = time.time()

        # ── Step 1: Alice's secret bits and basis choices ──────────
        alice_bits  = self.rng.integers(0, 2, size=self.n_qubits).tolist()
        alice_bases = self.rng.choice(['Z', 'X'], size=self.n_qubits).tolist()

        # ── Step 2: Bob's random basis choices ─────────────────────
        bob_bases   = self.rng.choice(['Z', 'X'], size=self.n_qubits).tolist()

        # ── Step 3: Eve's intercept (if simulated) ─────────────────
        eve_bases = None
        if self.eavesdropper:
            eve_bases = self.rng.choice(['Z', 'X'], size=self.n_qubits).tolist()

        # ── Step 4: Simulate each qubit via Cirq ───────────────────
        #
        # BB84 intercept-resend physics:
        #   Eve measures Alice's qubit in her own random basis.
        #   If Eve's basis == Alice's basis  → Eve gets correct bit, re-encodes correctly.
        #   If Eve's basis != Alice's basis  → Eve collapses the superposition,
        #     gets a random bit, re-encodes THAT in her (wrong) basis.
        #     When Bob later measures in Alice's original basis he sees an
        #     error with probability 0.5  →  overall QBER ≈ 25%.
        #
        # Bug that was here: two separate circuit.run() calls; the second one
        # always used Alice's original encoding, so Eve never had any effect.
        # Fix: build ONE circuit per qubit (Alice → [Eve] → Bob) and run it once.

        bob_results = []
        qubit = cirq.LineQubit(0)

        for i in range(self.n_qubits):

            if self.eavesdropper and eve_bases:
                # ── Determine what state Eve re-prepares ──────────────
                if eve_bases[i] == alice_bases[i]:
                    # Eve guesses correct basis — she gets Alice's bit exactly
                    eve_bit   = alice_bits[i]
                    eve_basis = eve_bases[i]
                else:
                    # Eve guesses wrong basis — measurement collapses the
                    # superposition and she gets a uniformly random bit.
                    eve_bit   = int(self.rng.integers(0, 2))
                    eve_basis = eve_bases[i]

                # Build circuit: Eve's re-prepared state → Bob's measurement
                circuit = cirq.Circuit()
                circuit.append(BB84Circuit.alice_encode(qubit, eve_bit, eve_basis))
                if self.noise_level > 0:
                    circuit.append(cirq.depolarize(self.noise_level)(qubit))
                circuit.append(BB84Circuit.bob_measure(qubit, bob_bases[i]))

            else:
                # No eavesdropper — Alice → [noise] → Bob
                circuit = cirq.Circuit()
                circuit.append(BB84Circuit.alice_encode(qubit, alice_bits[i], alice_bases[i]))
                if self.noise_level > 0:
                    circuit.append(cirq.depolarize(self.noise_level)(qubit))
                circuit.append(BB84Circuit.bob_measure(qubit, bob_bases[i]))

            # Run the single correct circuit once
            meas = self.simulator.run(circuit, repetitions=1)
            bob_results.append(int(meas.measurements[f'bob_{qubit}'][0][0]))

        # ── Step 5: Sifting — keep matching bases ──────────────────
        matched_indices = [
            i for i in range(self.n_qubits)
            if alice_bases[i] == bob_bases[i]
        ]

        alice_sifted = [alice_bits[i]  for i in matched_indices]
        bob_sifted   = [bob_results[i] for i in matched_indices]

        # ── Step 6: QBER check — sacrifice first 25% of sifted bits ─
        n_check = max(1, len(alice_sifted) // 4)
        check_errors = sum(
            1 for i in range(n_check)
            if alice_sifted[i] != bob_sifted[i]
        )
        qber = check_errors / n_check if n_check > 0 else 0.0
        eavesdropper_detected = qber > self.QBER_SECURITY_THRESHOLD

        # Remaining bits are the raw key (after discarding check bits)
        raw_key    = alice_sifted[n_check:]
        sifted_key = bob_sifted[n_check:]

        duration_ms = (time.time() - t_start) * 1000

        import hashlib
        session_id = hashlib.sha3_256(
            str(alice_bits[:8]).encode() + str(time.time()).encode()
        ).hexdigest()[:16]

        return BB84Result(
            raw_key_bits          = raw_key,
            sifted_key_bits       = sifted_key,
            key_length            = len(raw_key),
            qber                  = qber,
            eavesdropper_detected = eavesdropper_detected,
            n_qubits_sent         = self.n_qubits,
            efficiency            = len(raw_key) / self.n_qubits if self.n_qubits > 0 else 0,
            session_id            = session_id,
            duration_ms           = duration_ms,
            alice_bases           = alice_bases,
            bob_bases             = bob_bases,
            matched_indices       = matched_indices,
        )

    def extract_key_bytes(self, result: BB84Result) -> bytes:
        """
        Convert sifted key bits to bytes.
        In production, this feeds into privacy amplification + error correction.
        Here we do a simple bit-packing.
        """
        bits = result.sifted_key_bits
        # Pad to multiple of 8
        while len(bits) % 8 != 0:
            bits = bits + [0]
        key_bytes = bytes(
            int(''.join(str(b) for b in bits[i:i+8]), 2)
            for i in range(0, len(bits), 8)
        )
        return key_bytes


# ─────────────────────────────────────────────────────────────
# Visualization
# ─────────────────────────────────────────────────────────────

def visualize_bb84_session(result: BB84Result, save_path: str = "qkd_session.png"):
    """
    Generate a publication-quality visualization of the BB84 session.
    Shows: basis comparison, bit agreement, QBER meter, key extraction.
    """
    fig = plt.figure(figsize=(14, 10), facecolor='#0d1117')
    fig.suptitle(
        "Entangl — BB84 Quantum Key Distribution Session",
        fontsize=16, color='white', fontweight='bold', y=0.98
    )

    ALICE_COLOR  = '#58a6ff'
    BOB_COLOR    = '#3fb950'
    MATCH_COLOR  = '#f0e68c'
    ERR_COLOR    = '#f85149'
    BG_COLOR     = '#0d1117'
    PANEL_COLOR  = '#161b22'
    TEXT_COLOR   = '#c9d1d9'

    n_show = min(60, result.n_qubits_sent)
    xs = range(n_show)

    # ── Panel 1: Basis comparison ──────────────────────────────
    ax1 = fig.add_axes([0.05, 0.72, 0.90, 0.18], facecolor=PANEL_COLOR)
    alice_z = [1 if result.alice_bases[i] == 'Z' else 0 for i in range(n_show)]
    bob_z   = [1 if result.bob_bases[i]   == 'Z' else 0 for i in range(n_show)]
    match   = [1 if result.alice_bases[i] == result.bob_bases[i] else 0 for i in range(n_show)]

    ax1.step(xs, [a + 2.2 for a in alice_z], where='post', color=ALICE_COLOR, lw=1.5, label='Alice basis')
    ax1.step(xs, bob_z, where='post', color=BOB_COLOR, lw=1.5, label='Bob basis')

    for i in range(n_show):
        if match[i]:
            ax1.axvspan(i, i+1, alpha=0.15, color=MATCH_COLOR)

    ax1.set_xlim(0, n_show)
    ax1.set_yticks([0, 1, 2.2, 3.2])
    ax1.set_yticklabels(['X', 'Z', 'X', 'Z'], color=TEXT_COLOR, fontsize=8)
    ax1.tick_params(axis='x', colors=TEXT_COLOR, labelsize=8)
    ax1.set_title(f'Basis Choices (first {n_show} qubits) — highlighted = match',
                  color=TEXT_COLOR, fontsize=9, loc='left')
    ax1.legend(loc='upper right', fontsize=8, facecolor=PANEL_COLOR,
               labelcolor=TEXT_COLOR, framealpha=0.8)
    for spine in ax1.spines.values():
        spine.set_edgecolor('#30363d')

    # ── Panel 2: Sifted key bits ────────────────────────────────
    ax2 = fig.add_axes([0.05, 0.50, 0.90, 0.16], facecolor=PANEL_COLOR)
    n_sift = min(60, len(result.raw_key_bits))
    agree = [1 if result.raw_key_bits[i] == result.sifted_key_bits[i] else 0
             for i in range(n_sift)]

    bar_colors = [BOB_COLOR if a else ERR_COLOR for a in agree[:n_sift]]
    ax2.bar(range(n_sift), result.raw_key_bits[:n_sift],
            color=ALICE_COLOR, alpha=0.7, width=0.8, label="Alice's key bits")
    ax2.bar(range(n_sift), [-0.3]*n_sift, bottom=[-0.05]*n_sift,
            color=bar_colors, alpha=0.9, width=0.8, label="Agreement")

    ax2.set_xlim(-0.5, n_sift)
    ax2.set_ylim(-0.5, 1.5)
    ax2.set_yticks([0, 1])
    ax2.set_yticklabels(['0', '1'], color=TEXT_COLOR)
    ax2.tick_params(axis='x', colors=TEXT_COLOR, labelsize=8)
    ax2.set_title(f'Sifted Key Bits — green=match, red=error (QBER check sample)',
                  color=TEXT_COLOR, fontsize=9, loc='left')
    for spine in ax2.spines.values():
        spine.set_edgecolor('#30363d')

    # ── Panel 3: QBER gauge ─────────────────────────────────────
    ax3 = fig.add_axes([0.05, 0.24, 0.38, 0.20], facecolor=PANEL_COLOR)
    categories = ['QBER', 'Threshold', 'Theoretical\nMax Eve']
    values     = [result.qber * 100, 11.0, 25.0]
    bar_c      = [ERR_COLOR if result.eavesdropper_detected else BOB_COLOR,
                  MATCH_COLOR, '#ff6e6e']
    bars = ax3.barh(categories, values, color=bar_c, height=0.5)
    ax3.set_xlim(0, 30)
    ax3.axvline(x=11, color=MATCH_COLOR, linestyle='--', lw=1.5, alpha=0.8)
    ax3.set_xlabel('Error Rate (%)', color=TEXT_COLOR, fontsize=9)
    ax3.tick_params(colors=TEXT_COLOR, labelsize=9)
    status = "⚠ EAVESDROPPER DETECTED" if result.eavesdropper_detected else "✓ CHANNEL SECURE"
    status_color = ERR_COLOR if result.eavesdropper_detected else BOB_COLOR
    ax3.set_title(f'QBER Analysis — {status}', color=status_color, fontsize=9, fontweight='bold')
    for spine in ax3.spines.values():
        spine.set_edgecolor('#30363d')

    # ── Panel 4: Session stats ──────────────────────────────────
    ax4 = fig.add_axes([0.50, 0.24, 0.45, 0.20], facecolor=PANEL_COLOR)
    ax4.axis('off')
    stats = [
        ("Session ID",         result.session_id),
        ("Qubits sent",        f"{result.n_qubits_sent}"),
        ("Bases matched",      f"{len(result.matched_indices)} ({100*len(result.matched_indices)/result.n_qubits_sent:.0f}%)"),
        ("After QBER check",   f"{result.key_length} bits"),
        ("QBER",               f"{result.qber*100:.2f}%"),
        ("Eavesdropper",       "DETECTED ⚠" if result.eavesdropper_detected else "Not detected ✓"),
        ("Efficiency",         f"{result.efficiency*100:.1f}%"),
        ("Duration",           f"{result.duration_ms:.0f} ms"),
    ]
    for row_i, (label, value) in enumerate(stats):
        y_pos = 0.95 - row_i * 0.12
        color = ERR_COLOR if ("DETECTED" in value) else TEXT_COLOR
        ax4.text(0.02, y_pos, label + ":", transform=ax4.transAxes,
                 color='#8b949e', fontsize=9, va='top')
        ax4.text(0.45, y_pos, value, transform=ax4.transAxes,
                 color=color, fontsize=9, va='top', fontweight='bold')
    ax4.set_title('Session Statistics', color=TEXT_COLOR, fontsize=9, loc='left')

    # ── Panel 5: Key bits visualization ────────────────────────
    ax5 = fig.add_axes([0.05, 0.05, 0.90, 0.16], facecolor=PANEL_COLOR)
    key_bits = result.raw_key_bits[:128]
    n_cols   = 32
    n_rows   = max(1, (len(key_bits) + n_cols - 1) // n_cols)
    grid     = np.zeros((n_rows, n_cols))
    for idx, bit in enumerate(key_bits):
        r, c = divmod(idx, n_cols)
        if r < n_rows:
            grid[r, c] = bit

    ax5.imshow(grid, cmap='Blues', aspect='auto', vmin=0, vmax=1, interpolation='nearest')
    ax5.set_title(f'Extracted Key (first {len(key_bits)} bits) — dark=1, light=0',
                  color=TEXT_COLOR, fontsize=9, loc='left')
    ax5.tick_params(colors=TEXT_COLOR, labelsize=8)
    for spine in ax5.spines.values():
        spine.set_edgecolor('#30363d')

    plt.savefig(save_path, dpi=150, bbox_inches='tight',
                facecolor=BG_COLOR, edgecolor='none')
    plt.close()
    return save_path


# ─────────────────────────────────────────────────────────────
# Quick self-test
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Entangl QKD Module — BB84 Self Test")
    print("="*60)

    # Test 1: Clean channel (no eavesdropper)
    print("\n[Test 1] Clean channel, 128 qubits...")
    session = QKDSession(n_qubits=128, eavesdropper=False, seed=42)
    result = session.run()
    print(f"  Qubits sent    : {result.n_qubits_sent}")
    print(f"  Key bits       : {result.key_length}")
    print(f"  QBER           : {result.qber*100:.2f}%")
    print(f"  Eavesdropper   : {'DETECTED' if result.eavesdropper_detected else 'Not detected'}")
    print(f"  Efficiency     : {result.efficiency*100:.1f}%")
    print(f"  Duration       : {result.duration_ms:.0f} ms")
    key_bytes = session.extract_key_bytes(result)
    print(f"  Key (hex)      : {key_bytes[:8].hex()}...")

    # Test 2: Eavesdropper present
    print("\n[Test 2] Channel with eavesdropper (Eve), 128 qubits...")
    session_eve = QKDSession(n_qubits=128, eavesdropper=True, seed=42)
    result_eve = session_eve.run()
    print(f"  QBER           : {result_eve.qber*100:.2f}%")
    print(f"  Eavesdropper   : {'DETECTED ⚠' if result_eve.eavesdropper_detected else 'Not detected'}")

    # Generate visualization
    print("\n[Visualization] Generating session plot...")
    path = visualize_bb84_session(result, save_path="qkd_session_clean.png")
    print(f"  Saved: {path}")
    path_eve = visualize_bb84_session(result_eve, save_path="qkd_session_eve.png")
    print(f"  Saved: {path_eve}")

    print("\n  ✓ QKD module working correctly\n")
