# BIP 462 design review: the fee pool and the reference height

> **Status:** this reviews draft 0.4.0 and its implementation (up to commit
> `1bb4e43e18`). Its recommendations, Options B and 2B, were adopted in draft
> 0.5.0. The experiment script ran against the 0.4.0 code and no longer
> applies to later commits.

This review of BIP 462 (draft 0.4.0) covers two design problems. Each finding
comes either from the incentive model in `contrib/bip462/fee_incentives.py` or
from the regtest experiment in `contrib/bip462/truc_experiment.py`, run against
the reference implementation (`bip462-demurrage`).

## Summary

1. **The fee pool does more damage than "weakening" the incentive to include
   transactions.**
   - A miner's *marginal* reward for including a fee-paying transaction is
     zero. It receives its pool share whichever miner includes the
     transaction.
   - Paying the miner through an output it sweeps (a P2A output with value)
     beats paying a fee for any transaction above about 60 vB. Consensus
     cannot tell such an output from any other payment.
   - Rational users and miners therefore move fees out of the measured
     channel. The more fees there are, the stronger that pull: the BIP's fee
     responsiveness works only when fees are too small to matter. In
     equilibrium the BIP charges holders `T − S` regardless of fees, which is
     fixed-schedule demurrage with extra machinery.
   - **Recommendation:** pay fees to the block producer, as today, and stop
     counting them towards the target (Option B below). The fee pool, and the
     self-dealing it guards against, then disappear. If fee responsiveness is
     essential, count the *median* per-block fee instead (Option C).
2. **The version 4 coupling breaks TRUC, as you described. The experiment
   found two further failures.**
   - After activation, the reference node rejects every TRUC transaction.
   - A zero-fee commitment can be relayed as version 4, but loses TRUC's
     anti-pinning limit: a 5 kvB low-feerate pinning child was accepted.
   - Decoupling the field from the version fixes both. Tested: a version 3
     package with a reference height was accepted, and was still accepted 30
     blocks after signing.
   - Separately, a legacy transaction **signed before activation** became
     invalid three blocks into activation. The BIP values it at its inclusion
     height, so any pre-signed transaction (inheritance, vaults, channels
     opened before activation) dies once decay exceeds its fee margin.
   - **Recommendation:** go further than decoupling and drop the explicit
     field. A transaction inherits the highest reference height among the
     outputs it spends (Option 2B). The BIP already establishes that the
     choice of reference height is value-neutral. Inheritance removes the new
     field, its serialization, the sighash change and the version coupling. It
     keeps every pre-signed transaction valid, including those signed before
     activation, and Lightning needs no change to stay safe.

## Issue 1: the fee pool

### What the pool protects against

A miner can include a transaction paying a fee `X` to itself. If fees go to the
block producer and count towards `covered_k`, that costs it nothing, and it cuts
the next period's demurrage by `X`. For an agent with share `s` of effective
supply and `h` of hashrate, the net gain is `s − h` per unit (it saves `s·X` as
a holder and loses `h·X` of dividend). A single transaction can carry any fee,
so the size of `X` is limited only by capital (for 100 blocks, until the
coinbase matures), not by block space. A custodian holding 6% of supply and
running a 2% pool could erase the whole shortfall, about 42,000 BTC a year in
2036–2040, at no cost. The BIP's concern is real, and the pool does remove it:
the self-dealer then recovers only `h·X` and nets `s − 1 < 0`.

General result (model, `self_dealing_net`): with a share `α` of each fee paid
to the includer and `1 − α` pooled, the net gain from self-dealing is
`α + h(1 − α) − 1 + c·(s − h)`, where `c` is the share of the fee that counts
towards `covered_k`.

| design | small miner | 30% pool | custodian, 2% pool (s = 6%) | whale-miner (h 30%, s 20%) |
|---|---|---|---|---|
| all fees pooled (0.4.0) | −1.00 | −1.00 | −0.94 | −0.80 |
| no pool, fees counted | −0.01 | −0.30 | **+0.04** | −0.10 |
| no pool, fees not counted | 0 | 0 | 0 | 0 |
| half pooled, pooled half counted | −0.50 | −0.50 | −0.47 | −0.40 |
| 70% to miner, pooled 30% counted | −0.30 | −0.30 | −0.28 | −0.24 |

The finding that matters: **if only the pooled share is counted (`c = 1 − α`),
the net gain is `(1 − α)(s − 1)`, negative for every agent and every `α`.**
Self-dealing is defeated by *not counting* the share a miner can recover, not
by pooling everything.

### The cost: inclusion incentives

- **The marginal reward for inclusion is `α·F`, which is zero in 0.4.0.** A
  pooled fee reaches every miner pro rata whichever miner includes the
  transaction. A miner gains nothing by including it itself rather than
  leaving it for the next miner. (The `h·F` figure in the BIP's Security
  Considerations is what a miner receives if *it alone* would ever include
  the transaction.) Including transactions becomes a public good. Every cost
  of inclusion (propagation, validation, orphan risk) is borne privately, so
  small miners have reason to mine empty blocks and leave inclusion to
  others.
- **Fees move out of the measured channel, in-band.** A user can pay the
  includer through a P2A output with value, which the miner sweeps in the same
  block. Consensus cannot distinguish that from any other output, or from a
  payment to a pool's address. The bypass costs about 54 vB of block space (a
  13 vB output and a 41 vB sweep input). It gains the miner a share
  `b = (1 − α)(1 − h)` of the fee, so it pays for any transaction larger than
  `54 / b` vB:

| design (h = 10%) | marginal inclusion reward | bypass gain `b` | bypass pays for transactions ≥ |
|---|---|---|---|
| all fees pooled (0.4.0) | 0 | 0.90 | 60 vB (every transaction) |
| half pooled | 0.50 | 0.45 | 120 vB |
| 70% to miner | 0.70 | 0.27 | 200 vB |
| no pool | 1 | 0 | never |

  Batched and consolidation transactions are large, so they bypass even at
  small `b`. Out-of-band accelerators bypass at any `b`, with no block-space
  cost.
- **Centralisation.** Direct payment needs a counterparty. Users pay the
  pools that find blocks most often, which favours the largest miners.

### Fee responsiveness defeats itself

These are the BIP's 2036–2040 figures (target 62,600 BTC a year, subsidy
20,531). The last column is what the pool pays out to other miners when a 10%
miner takes a fee on-chain, which is the incentive to bypass it:

| on-chain fees (BTC/yr) | holders pay if fees stay pooled | holders pay once fees bypass the pool | bypass incentive (BTC/yr) |
|---|---|---|---|
| 1,000 | 41,069 | 42,069 | 900 |
| 10,000 | 32,069 | 42,069 | 9,000 |
| 30,000 | 12,069 | 42,069 | 27,000 |
| 60,000 | 0 | 42,069 | 54,000 |

The pool lets fees reduce demurrage only while fees are small, when that saves
holders little. The incentive to bypass grows one-for-one with fees, so as fees
become large enough to replace demurrage, they leave the pool. The BIP's
selling point over fixed-rate demurrage ("charges holders only for the part of
the security budget that subsidy and fees fail to cover") does not survive
equilibrium. The BIP's Out-of-band section already notes the worst case. The
model shows it is the expected case, reached in-band without any off-chain
coordination.

The comparison with EIP-1559, which the BIP cites, cuts the other way.
EIP-1559 burns only the *base fee*, which is protocol-set and mandatory, so it
cannot be routed around. It keeps *priority tips* for the block producer
precisely to preserve the incentive to include transactions. BIP 462's pool
has neither property.

### Options

| | self-dealing | marginal inclusion reward | bypass pressure | fees reduce demurrage | steady per-block reward | consensus complexity |
|---|---|---|---|---|---|---|
| A. all fees pooled (0.4.0) | defeated | 0 | very high | only while small | yes | pool state, `fee_effective`, payout |
| **B. fees to producer, not counted** | no lever | full | none | no | yes, dividend ≥ `T − S` | **lowest: no pool** |
| C. fees to producer, median per-block fee counted | needs > 50% of hashrate to shift far | full | none from the pool | yes, bounded | weaker as fees dominate | low: per-block fee totals and a median |
| D. share `α` to producer, only the pooled share counted | defeated for any `α` | `α` | `(1 − α)(1 − h)` | only `1 − α` of fees | partial | pool state |
| E. protocol base fee pooled, tips to producer (EIP-1559) | defeated | tips | none for the base fee | base fees | yes | dynamic base fee in consensus |

**Option B** is the structure you attribute to Todd: only demurrage is pooled,
and fees stay with the block producer. Consensus counts no fees, so there is
nothing to manipulate in either direction. Miners keep the full incentive to
include transactions. The rate becomes a deterministic function of the subsidy
schedule and the UTXO set value, known years ahead. Its dividend is a steady
per-block reward of at least `T − S` (about 1.2 BTC per block after 2140),
which also answers the reorganisation-incentive argument (Carlsten et al.)
that the BIP gives for the pool. The cost: holders pay `T − S` even when fees
are high. Option A converges to that in equilibrium anyway.

**Option C** keeps fee responsiveness without a pool. `covered_k` uses
`RATE_PERIOD × median(per-block fees)` over the previous period instead of
the sum. A miner with share `h` can put its blocks above or below every honest
block, but it can only move the measured median to the honest quantile
`0.5 / (1 − h)` or `(0.5 − h) / (1 − h)`. With `h = 30%`, that is between the
29th and 71st honest percentiles, whatever fee it pays itself. A median is
robust in both directions only below 50% hashrate. That is Bitcoin's existing
assumption, and the same reason the median time past is used. The residual
weakness: a cartel holding a majority of hashrate could take its fees out of
band to raise demurrage, and miners as a group would gain from it.

Lower quantiles are a trap. A miner with 25% of hashrate can drive the 25th
percentile to zero by mining empty blocks.

**Recommendation: Option B.** Choose C if the BIP must keep fees reducing
demurrage. D is the only defensible way to keep a pool. A and E are not
recommended: A for the reasons above, E because it adds a dynamic base fee to
Bitcoin's consensus.

For the reference implementation, B *removes* code: the pool, `fee_effective`,
the payout and the period fee totals. The coinbase limit becomes
`subsidy + fees + dividend`.

## Issue 2: the reference height and TRUC

### Reproduced on the reference node

`contrib/bip462/truc_experiment.py` builds a zero-fee commitment package, as
in current Lightning designs: a parent with fee 0 and a 0-value P2A anchor,
and a child paying for both. It also builds a pinning variant: a 5 kvB
low-feerate child sweeping the anchor. All runs are on regtest 3 blocks after
activation. "Decoupled" means the version check in `CheckTxRefHeightField`
was removed, as a temporary patch.

| case | 0.4.0 | decoupled |
|---|---|---|
| version 3 TRUC, no `ref_height` | rejected: `demurrage-legacy-version` | rejected: `demurrage-legacy-version` |
| version 4 with `ref_height` | accepted | accepted |
| … with a 5 kvB pinning child | **accepted (pinnable)** | **accepted (pinnable)** |
| version 3 TRUC with `ref_height` | rejected: `bad-txns-refheight-version` | **accepted** |
| … with a 5 kvB pinning child | — | **rejected: `TRUC-violation … 5000 > 1000`** |
| … broadcast 30 blocks after signing | rejected: `bad-txns-refheight-version` | **accepted and mined** |
| legacy transaction signed before activation (1,000 sat fee on 50 BTC) | **invalid** after 3 blocks (`bad-txns-in-belowout`), and not relayed | same |

What the experiment adds to the conflict you described:

- **TRUC is unusable after activation, not just inconvenient.** A version 3
  transaction cannot carry a reference height, so it is legacy-valued. The
  mempool cannot hold legacy-valued transactions, because their value changes
  every block. A zero-fee commitment without a reference height is invalid
  after a single block of decay.
- **The version 4 route relays, but gives up pinning resistance.** TRUC exists
  to cap the size of the child of an unconfirmed parent (1,000 vB) and the
  number of its descendants. A version 4 commitment accepts a 5 kvB
  low-feerate child that the honest party must outbid in absolute fee. That
  is the attack TRUC was designed to stop.
- **Pre-signed transactions from before activation break.** A legacy
  transaction is valued at its inclusion height, so it dies once decay
  exceeds its fee margin. That takes `margin / r` blocks: at the full target
  rate (5.7e-8 per block), a 1 BTC transaction with a 1,000 sat fee lasts
  about 175 blocks. Every timelocked inheritance or recovery transaction,
  every vault unvault, and every channel commitment signed before activation
  is affected. This is a backward-compatibility failure in the BIP itself,
  separate from TRUC.

### Option 2A: decouple the field from the version (your proposal)

Signal `ref_height` only by flag bit `0x02`, on any version. Drop
`bad-txns-refheight-version`, keep the rule that a coinbase may not carry
one, and leave TRUC as "version 3", with or without the field. The experiment
shows it works. It costs nothing: the version coupling protected nothing,
because the flag already makes parsing unambiguous. It does not fix
pre-activation pre-signed transactions.

### Option 2B: inherit the reference height (recommended)

Drop the field. Give every output a reference height:

- `ACTIVATION_HEIGHT − 1` (index 1.0) for outputs created before activation;
- its block's height for a coinbase output;
- otherwise, the reference height of the transaction that created it.

A transaction's reference height is **the highest reference height among the
outputs it spends**. Inputs are valued at `I(ref_height)`, and outputs are
created with that reference height. That is the smallest reference height rule
1 already allows.

Why the BIP's own value-neutrality argument makes this sufficient: a later
reference height revalues the inputs downwards and creates the outputs at the
same lower index, so the effective value delivered is the same. Only the
nominal unit changes. An explicit field therefore adds no capability. Its one
use is expressing amounts in "current" units, which matters only for display,
and the BIP already says nominal values have no economic meaning.

What 2B achieves:

- **No format change.** No new field or flag, no new version semantics, no
  sighash change, no PSBT change, and no parser changes for wallets, explorers
  and hardware signers.
- **Validity no longer depends on inclusion height,** for every transaction,
  including ones signed before activation. Spent outputs from before
  activation are valued at 1.0, so those transactions stay valid forever. The
  "legacy" valuation, and the rule against relaying legacy transactions, both
  disappear.
- **TRUC and Lightning just work.**
  - A commitment's outputs inherit the funding output's reference height. Decay is
    shared pro rata in every state, automatically, as the BIP's Lightning
    section wants.
  - Zero-fee commitments stay at fee 0 forever, because their outputs sum to
    the funding output's nominal value.
  - HTLC and penalty transactions inherit the commitment's reference height,
    so watchtowers need nothing new.
  - Lightning implementations need changes only to display balances.
- **Privacy improves.** No field reveals when a transaction was signed.

What it costs: nominal output amounts are in the units of the youngest input's
index, not the current one. A coin that is 10 years old at 0.3% a year carries
units 3% "larger" than current ones, so wallets must convert amounts. The
mempool should rank transactions by fee converted to the next block's index.
Both are display or policy changes, not consensus ones.

For the reference implementation, 2B removes:
- the field's serialization;
- the three sighash changes;
- the PSBT fields;
- the version policy;
- the wallet's reference height logic;
- the rule against relaying legacy transactions.

It adds one rule in `CheckTxInputs` (the maximum of the spent coins' reference
heights) and passes that height to `AddCoins` and to mempool coins.

## Proposed BIP changes

Recommended combination: **Option B and Option 2B.**

- **Fee pool.** Delete the Fee pool section, `FEE_POOL_DIVISOR`,
  `fee_effective` and the pool's place in the coinbase limit. Set
  `covered_k = subsidy_{k−1}`. The coinbase limit becomes
  `block_subsidy(h) + fees(h) + demurrage_dividend(h)`. Rewrite "Why a target
  rather than a fixed rate" and "Why a fee pool" around the result above:
  measured fees cannot be both resistant to manipulation and impossible to
  route around.
- **Reference height.** Replace the Transaction reference height section
  (serialization, field rules, signature hashes) with the inheritance rule.
  Delete the PSBT and parser items from Backward Compatibility. Shorten the
  Lightning section to the balance display rules, and close the open question
  on TRUC.
- **Supply accounting is unchanged.**

## Sources

- Coverage of Peter Todd's *Tail Emissions and Demurrage* (Bitcoin++
  Toronto, July 2026). It describes his demurrage charge as going into a fund
  that miners draw from:
  [Bitcoin.com](https://news.bitcoin.com/peter-todds-tail-emissions-pitch-sparks-bitcoin-inflation-debate/),
  [CryptoSlate](https://cryptoslate.com/?p=555829),
  [Bitcoin++ archive](https://btcpp.dev/whois/petertodd/archive).
  The review does not depend on the talk's details, and I have not watched
  the video.
- BIP 431 (TRUC), BIP 433 (P2A), EIP-1559.
