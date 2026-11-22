#!/usr/bin/env python3
"""Incentive model for BIP 462 fee routing.

A fee F paid on-chain is split: a share `alpha` goes to the miner of the block
that includes it, (1 - alpha) to the fee pool, which pays miners pro rata to
blocks found. `counted` is the share of the fee that counts towards covered_k
(BIP 462 0.4.0: alpha = 0, counted = 1).

Agent: hashrate share h, share of effective supply s.
"""

P2A_OUTPUT_VB = 13      # 8 value + 1 script length + 4-byte P2A script
P2A_SWEEP_INPUT_VB = 41  # outpoint 36 + empty scriptSig 1 + sequence 4; no witness
BYPASS_VB = P2A_OUTPUT_VB + P2A_SWEEP_INPUT_VB


def self_dealing_net(s, h, alpha, counted):
    """Net gain per unit fee X that an agent pays to itself in its own block.

    Recovers alpha*X immediately and h of the pooled part; the measured fees
    rise by counted*X, which cuts next period's demurrage by counted*X (while
    demurrage is positive): the agent saves s of that as a holder and loses h
    of it as a miner (lost dividend).
    """
    recovered = alpha + h * (1 - alpha)
    return recovered - 1 + counted * (s - h)


def marginal_inclusion(alpha):
    """What a miner earns by including a fee F itself rather than leaving it to
    the next miner: only the share paid to the includer. Its pro-rata share of
    the pooled part arrives whoever includes the transaction."""
    return alpha


def bypass_gain(h, alpha):
    """Extra revenue a miner earns per unit fee if paid directly (an output it
    sweeps) instead of an on-chain fee."""
    return 1 - (alpha + h * (1 - alpha))


def bypass_min_vsize(h, alpha):
    """Smallest transaction (vB) for which paying the fee through a P2A output
    swept by the miner beats paying it as a fee: b * vsize * feerate > BYPASS_VB * feerate."""
    b = bypass_gain(h, alpha)
    return float("inf") if b <= 0 else BYPASS_VB / b


def table():
    designs = [
        ("BIP 462 0.4.0: all fees pooled", 0.0, 1.0),
        ("no pool, fees counted (rejected by the BIP)", 1.0, 1.0),
        ("no pool, fees not counted (fee-independent rate)", 1.0, 0.0),
        ("half pooled, pooled half counted", 0.5, 0.5),
        ("70% to miner, pooled 30% counted", 0.7, 0.3),
        ("half pooled, all counted", 0.5, 1.0),
    ]
    agents = [("small miner, no coins", 0.01, 0.0), ("large pool", 0.30, 0.0), ("custodian, 2% pool", 0.02, 0.06),
              ("miner-custodian", 0.10, 0.05), ("whale-miner", 0.30, 0.20)]
    print("Self-dealing net gain per unit of self-paid fee (positive = manipulation pays)")
    print(f"{'design':52}" + "".join(f"{a[0]:>24}" for a in agents))
    for name, alpha, counted in designs:
        row = "".join(f"{self_dealing_net(s, h, alpha, counted):>24.3f}" for _, h, s in agents)
        print(f"{name:52}{row}")
    print()
    print("Marginal inclusion reward (fraction of the fee), bypass gain and in-band bypass threshold, h = 10%")
    for name, alpha, counted in designs:
        print(f"{name:52} include={marginal_inclusion(alpha):.2f}  bypass={bypass_gain(0.10, alpha):.2f}"
              f"  bypass pays for txs >= {bypass_min_vsize(0.10, alpha):.0f} vB")


def holders_cost():
    """Demurrage paid by holders per year (BTC), 2036-2040 epoch numbers from the BIP."""
    target, subsidy = 62_600, 20_531
    print()
    print("Holders' demurrage per year (BTC), 2036-2040: target 62,600, subsidy 20,531")
    print(f"{'on-chain fees':>14} {'fees counted':>14} {'fees bypassed':>14} {'fee-independent':>16}")
    for fees in (1_000, 10_000, 30_000, 60_000):
        counted = max(0, target - subsidy - fees)
        bypassed = max(0, target - subsidy)
        print(f"{fees:>14,} {counted:>14,} {bypassed:>14,} {bypassed:>16,}")
        print(f"{'':>14} pool's bypass incentive at h=10%: {0.9 * fees:,.0f} BTC/yr")


def quantile_manipulation():
    """With fees paid to the includer and covered_k measured as RATE_PERIOD x a
    quantile q of per-block fees, a miner with share h can put its own blocks at
    the top (self-paid fees) or the bottom (empty, or fees taken out of band).
    The measured quantile becomes the honest quantile q_up or q_down."""
    print()
    print("Quantile fee measure: which honest quantile a miner with share h can force")
    print(f"{'h':>6} {'median up':>10} {'median down':>12} {'p25 up':>8} {'p25 down':>9}")
    for h in (0.05, 0.10, 0.20, 0.30, 0.40):
        def up(q): return min(1.0, q / (1 - h))
        def down(q): return max(0.0, (q - h) / (1 - h))
        print(f"{h:>6.2f} {up(0.5):>10.3f} {down(0.5):>12.3f} {up(0.25):>8.3f} {down(0.25):>9.3f}")


if __name__ == "__main__":
    table()
    holders_cost()
    quantile_manipulation()
