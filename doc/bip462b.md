# BIP 462b reference implementation

This branch implements version 0.3.0 of the draft **BIP 462b, Soft-Fork
Demurrage Security Budget** (`bip-0462b.md`), except for the points listed under
[Differences from draft 0.3.0](#differences-from-draft-030). It was first
written against version 0.1.0. Versions 0.2.0 and 0.3.0 address the problems it
found in 0.1.0, listed below, and change no mainnet consensus rule.
The demurrage is charged when an output is
spent. The block owes the charge, the coinbase pays it into a pool output, and a
deterministic claim transaction at index 1 of every later block pays out
`floor(P / 10,000)` of the pool as its fee.

The deployment is `demurrage`. It is defined on every network and is
`NEVER_ACTIVE` everywhere, because the BIP sets no activation parameters at draft
stage. On regtest it can be activated in two ways:

- `-testactivationheight=demurrage@<height>` applies the rules from a fixed
  height, whatever the version bits state. This is what the tests use.
- `-vbparams=demurrage:<start>:<timeout>[:<min_activation_height>]` activates it
  through signalling. The regtest period is 144 blocks and the threshold 108.

## Building and testing

```bash
cmake -B build && cmake --build build -j$(nproc)
build/bin/test_bitcoin --run_test=demurrage_tests
build/test/functional/feature_demurrage.py
```

## Parameters

| Parameter | Mainnet, testnet3, testnet4, signet | Regtest | Where |
|---|---|---|---|
| `RATE_PERIOD` | 2,016 | 144 | `Consensus::Params::DemurrageRatePeriod` |
| `TARGET_RATE_PER_BLOCK` | 3 / 52,560,000 | 1 / 2,000 | `DemurrageTargetNumerator`, `DemurrageTargetDenominator` |
| `POOL_DIVISOR` | 10,000 | 10,000 | `demurrage::POOL_DIVISOR` |
| `INDEX_ONE` | 10^18 | 10^18 | `demurrage::INDEX_ONE` |
| `POOL_SCRIPT` | `0x04706f6f6c7551` | same | `demurrage::PoolScript()` |
| `CHARGE_MARGIN` (policy) | 144 | 144 | `demurrage::CHARGE_MARGIN` |
| Version bit | 4 | 4 | `kernel/chainparams.cpp` |

Regtest halves the subsidy every 150 blocks, so with the mainnet target the
subsidy covers the target until height 2,448. The regtest target is therefore
higher, and its rate periods match its 144-block version bits period. Draft
0.2.0 adopts these regtest values.
With activation at 432, the first rate period has a zero rate, as on mainnet
before 2032. Charges begin at 576, with `r = 237,945,492,662,473`, about 0.024%
per block. At that rate, evaluating charges up to 287 blocks ahead (the policy's
`E`) overstates them by several percent of input value. Regtest transactions
that spend old coins therefore need far larger fees than they would on mainnet.

## Where each part of the specification is implemented

| Spec section | Code |
|---|---|
| Parameters | `src/consensus/demurrage.h`; `src/consensus/params.h` (`DEPLOYMENT_DEMURRAGE`, `Demurrage*`); per-network values in `src/kernel/chainparams.cpp` |
| Fixed-point arithmetic | `src/consensus/demurrage.cpp`: every product goes through `Wide`, which is `unsigned __int128`, or `arith_uint256` on compilers without it. `Narrow()` asserts that each result fits in 64 bits. |
| Demurrage rate | `demurrage::ScheduledSubsidy`, `ScheduledSupply`, `PeriodRate` |
| Demurrage index | `demurrage::NextIndex`, `demurrage::IndexSchedule::Index`, cached per activation height by `ChainstateManager::DemurrageSchedule` |
| Demurrage charge | `demurrage::Charge`, `IndexSchedule::ChargeFor`; `C(h)` is summed in `Chainstate::ConnectBlock` from `Coin::nHeight` |
| Pool outputs | `demurrage::IsPoolScript`; `ConnectBlock` rejects `bad-demurrage-pool-create` and `bad-demurrage-pool-spend` |
| Coinbase contribution | `ConnectBlock`, after the transaction loop: `bad-cb-demurrage-missing`, `-amount`, `-multiple`, `-unexpected` |
| Claim transaction | `demurrage::BuildClaimTransaction`; pool inputs from `ChainstateManager::GetDemurragePoolInputs`, which uses `GetDemurragePoolOutputs` and `RecordDemurragePoolOutputs` and `demurrage::FindBlockPoolOutputs`; `ConnectBlock` rejects `bad-demurrage-claim-missing` and `bad-demurrage-claim` |
| Summary of new block rules | `Chainstate::ConnectBlock`, all three rules |
| Deployment | `DEPLOYMENT_DEMURRAGE`, `deploymentinfo.cpp`, `DemurrageActivationHeight()` in `deploymentstatus.h`, `VersionBitsCache::ActivationHeight`, `-testactivationheight` in `chainparams.cpp`, `getdeploymentinfo` in `rpc/blockchain.cpp` |
| Relay and mining policy: mining score | `CTxMemPoolEntry::m_demurrage_charge`, which `GetModifiedFee()` excludes; `ChangeSet::StageAddition`; `CTxMemPool::SetDemurrageCharge`; `MemPoolAccept::PreChecks`; `Chainstate::UpdateMempoolDemurrageCharges`, called from `ConnectTip` and `MaybeUpdateMempoolForReorg` |
| Relay and mining policy: unconfirmed inputs | `MemPoolAccept::PreChecks` (coins at `MEMPOOL_HEIGHT`) and `Chainstate::UpdateMempoolDemurrageCharges` (parents found with `CTxMemPool::get`) charge an output of an unconfirmed transaction from the next block's height |
| Relay and mining policy: relay | The existing fee checks (`CheckFeeRate`, package feerate, RBF, eviction) all read modified fees, so they use the net fee at `E` |
| Relay and mining policy: pool outputs | `PreChecks`: `demurrage-pool-output`, `demurrage-pool-spend`. Claim transactions from disconnected blocks fail the first check, so they are not returned to the mempool. |
| Relay and mining policy: block assembly | `BlockAssembler::CreateNewBlock`, `node::GetDemurrageCharges`, `node::GetBlockDemurrageCharge`; `node::UpdateDemurrageContribution` for `generateblock`; the contribution is added to `CoinbaseTx::required_outputs` for IPC mining clients |
| getblocktemplate | `getblocktemplate` in `rpc/mining.cpp`: the rule is listed as `demurrage` from activation and as `!demurrage` from `IndexSchedule::FirstChargeHeight()`, and `WarnDemurrageRuleRequired` logs the warning. `gbt_optional_rule` is `true` in `deploymentinfo.cpp`, so the version bit is set for every client while signalling. The `charge` and `demurrage_contribution` fields come from `CBlockTemplate::vTxDemurrageCharges` and `CBlockTemplate::demurrage_contribution`. |
| Test vectors | `src/test/demurrage_tests.cpp`, `test/functional/feature_demurrage.py` |

### Reject reasons

| Reason | Rule |
|---|---|
| `bad-demurrage-claim-missing` | The block has pool inputs, but it has no transaction at index 1, or that transaction spends none of them. This covers a missing or misplaced claim. |
| `bad-demurrage-claim` | The transaction at index 1 spends pool inputs but is not exactly the claim transaction: other or reordered inputs, version, nLockTime, nSequence, scriptSig, witness, or outputs. |
| `bad-demurrage-pool-create` | A transaction other than the coinbase and the claim creates a `POOL_SCRIPT` output. |
| `bad-demurrage-pool-spend` | A transaction other than the claim spends a pool output. |
| `bad-cb-demurrage-missing` | `C(h) > 0` and the coinbase has no pool output. |
| `bad-cb-demurrage-amount` | The contribution differs from `C(h)`. |
| `bad-cb-demurrage-multiple` | The coinbase has more than one pool output. |
| `bad-cb-demurrage-unexpected` | `C(h) = 0` and the coinbase has a pool output. |
| `demurrage-pool-output`, `demurrage-pool-spend` | Mempool policy. |

## Implementation choices the specification does not dictate

- **Finding the pool inputs.** The UTXO set is keyed by outpoint, so it cannot
  be searched by script. The carry is output 0 of the claim transaction of block
  `h − 1`. The matured contribution is the coinbase pool output of block
  `h − 100`. Both blocks have passed validation, so only their coinbase and their
  transaction at index 1 can have created a pool output. `ConnectBlock` records
  each block's pool outputs in a cache of recent blocks, keyed by block index,
  and on a miss reads the block from disk. Values come from the coins view.
- **Input prefetching.** `ConnectBlock`'s parallel input fetcher expects coins
  to be read in block order. The claim's inputs are therefore compared as
  outpoints before the loop, and their coins are read only when the loop reaches
  index 1.
- **Order of checks.** The claim check runs before `CheckTxInputs`. An altered
  claim is reported as `bad-demurrage-claim`, even when its output exceeds its
  inputs. The contribution is checked after the existing `bad-cb-amount` check.
- **Net fee as modified fee.** Charges are applied like a negative
  `prioritisetransaction` delta. Cluster linearisation, block assembly, package
  relay, RBF and mempool trimming then all rank by net fee without further
  changes. `getmempoolentry` reports `fees.modified` as base fee + delta − charge.
- **When charges are recomputed.** All mempool charges are recomputed when `E`
  or the activation height changes, and after every reorg. When a block connects
  without changing either, only the entries that spend its outputs are
  recomputed, because their inputs have just confirmed. Those inputs were
  charged as if confirmed in the next block at the time, so their charges can
  only fall. Other entries keep that next-block height for their unconfirmed
  inputs until `E` moves, which overstates the charge a little more with each
  block.
- **Block assembly.** The claim's weight is reserved before transactions are
  selected. `C(h)` is computed exactly at the block's height from the coins tip.
  Inputs spending outputs of earlier transactions in the block have no charge.
  The contribution is coinbase output 1, before the witness commitment.

## Problems found in draft 0.1.0

Drafts 0.2.0 and 0.3.0 address each of these. Each numeric claim in draft 0.1.0 was checked against an independent
arbitrary-precision implementation, in the unit tests and in Python. The rate
table, the 19,284,730,634 rate at 1,260,000, the maximum rate 57,077,625,570,
the index falls (0.41%, 1.21%, 2.19%), the 67-, 108- and 16-byte sizes and the
17 ppm overstatement are all correct. No consensus rule turned out to be
ambiguous enough to allow two readings. The problems below are about policy,
interfaces and wording.

1. **The charge of unconfirmed inputs is not specified (policy).** The mining
   score evaluates charges at `E`, but an input that spends an unconfirmed
   output has no confirmation height. This implementation charges it nothing,
   on the assumption that parent and child confirm together. The consequence:
   when the parent confirms alone, the child suddenly owes the charge for its
   parent's output from that height to `E`, up to 287 blocks of decay. A child
   whose fee was sized for a package can then become unminable until bumped.
   The functional test showed this. The BIP should choose a rule, for example
   assume confirmation at the next block (conservative) or in the same block
   (this implementation at the time). Draft 0.2.0 chose the next block, and this
   implementation now does the same.
2. **What a recomputation does to transactions whose net fee becomes too low is
   not specified (policy).** "Each transaction therefore pays its way for at
   least `CHARGE_MARGIN` blocks before a recomputation can evict it" implies
   eviction, but no rule says when to evict. Here transactions stay, ranked by
   their now lower or negative net fee, until mempool trimming, expiry,
   replacement or a CPFP child.
3. **Charges before activation is known (policy).** `E` is up to 287 blocks
   ahead, so it can lie beyond an activation height that version bits has not
   yet fixed. This implementation charges nothing until the deployment is
   active for the next block. On mainnet this changes nothing, because the rate
   is zero until 1,260,000.
4. **Test networks.** The BIP gives only mainnet values, and ties `RATE_PERIOD`
   to the 2,016-block difficulty adjustment period. On regtest the version bits
   period is 144, so `ACTIVATION_HEIGHT` is a multiple of 144, not of 2,016. The
   subsidy halves every 150 blocks, so the mainnet target makes every charge zero
   for about 2,000 blocks. The BIP should say that `RATE_PERIOD` is the
   deployment's signalling period, and that test networks may use other target
   values. The regtest values here are the implementation's choice.
5. **The "annual rate" column of the rate table is undefined.** It is the
   compounded decay over 52,560 blocks, `1 − (1 − r)^52,560`. For 2044–2048 the
   simple rate `r × 52,560` is 0.2755%, which would round to 0.276%, not the
   0.275% shown. The other rows agree either way.
6. **"The carry and immature contributions can be found from [the UTXO set]".**
   This is true, since the carry is the only unspent non-coinbase pool output
   and contributions are the unspent coinbase pool outputs. But it needs a scan
   by script, which the UTXO set does not index. The BIP could state these two
   identities. This implementation reads blocks `h − 1` and `h − 100` instead,
   which breaks assumeutxo (see below).
7. **`getblocktemplate`.** The BIP defers it, but the gap is sharp. Today's GBT
   `coinbasevalue` is the template's coinbase output 0, which here is
   `subsidy + fees − C(h)`, and nothing tells the client to add the
   contribution. Every block built by a GBT client is invalid once charges
   begin. This implementation first made the rule required from activation for
   this reason. It now follows draft 0.3.0 (see [getblocktemplate](#getblocktemplate)).
   The IPC mining interface already has a place for the contribution
   (`required_outputs`), and that is implemented here.
8. **Ephemeral dust and other fee rules.** Policy rules that require a zero fee,
   such as ephemeral dust, must compare the fee, not the net fee, or no such
   transaction could be relayed once charges begin. This implementation
   compares the fee. The BIP's "TRUC rules are unchanged" does not cover this.
9. **Invalid blocks reach non-upgraded nodes through upgraded ones.** High
   bandwidth compact block relay (BIP 152) forwards a block before
   `ConnectBlock`. An upgraded node therefore relays a block from a lagging
   miner that breaks only BIP 462b rules, and its non-upgraded peers accept it.
   This is true of any soft fork. It matters more here, because the Security
   Considerations expect such blocks every day if any hashrate lags. The
   functional test had to isolate its non-enforcing node for this reason.
10. **Minor wording.** "The rate depends on nothing but `H_k`", and
    `H_k = ACTIVATION_HEIGHT + k × RATE_PERIOD`, so the rate depends on the
    activation height. This is harmless on mainnet, where every activation
    height is a multiple of 2,016. On regtest,
    `-testactivationheight=demurrage@433` shifts every rate period. Also, the
    first 67-byte claim is clear of the proposed rule against 64-byte
    transactions (BIP 54), which the BIP could note.

## getblocktemplate

This follows the draft's `getblocktemplate` section as of version 0.3.0.

- **Rule.** From activation the template lists the optional rule `demurrage`,
  and a client that does not declare it gets a template as usual. From the first
  rate period with a non-zero rate (1,260,000 on mainnet, or the activation
  height if that is later; 576 on regtest with activation at 432) the template
  lists `!demurrage`, and a client that does not declare it gets the error
  `Support for 'demurrage' rule requires explicit client support`. This applies
  whether the deployment activated through version bits or was forced with
  `-testactivationheight`.
- **Warning.** Between the two, each request from a client that does not
  declare the rule logs a warning that templates will require it from that
  height, at most once an hour.
- **Signalling.** While the deployment is `started` or `locked_in`, the
  template's version has the deployment's bit for every client, so signalling
  counts upgraded nodes, not upgraded mining software.
- **Fields.** While the deployment is active, each transaction has a `charge`,
  its charge at the template's height, and the template has a
  `demurrage_contribution`, `C(h)`. The claim transaction is the first entry of
  `transactions`, with the payout as its `fee` and a `charge` of 0.
  `coinbasevalue` is `subsidy + fees − C(h)`, where fees include the payout.
  `default_witness_commitment` is still the witness commitment. The contribution
  is not one of the outputs it describes.

## Differences from draft 0.3.0

- **Before activation.** This implementation charges nothing until the
  deployment is active for the next block. The draft charges from lock-in,
  when `ACTIVATION_HEIGHT` is known.
- **Compact blocks.** Senders do not prefill the claim transaction, and nodes do
  not check it before relaying a block ahead of validation.
- **assumeutxo.** The draft states how to find the pool inputs in a snapshot.
  This implementation does not do so yet (see below).

The charge of unconfirmed inputs, the `getblocktemplate` support, the
no-eviction rule for recomputation, the fee rule for ephemeral dust and the
regtest parameters match the draft.

## Not implemented

- **Wallet.** The wallet does not add the charge to its fee. Once a wallet
  transaction's charge at `E` exceeds its fee, the mempool rejects it with
  `min relay fee not met`. The wallet does not report effective balances.
- **Stratum V2 and PSBT fields**: left by the draft to separate specifications.
- **assumeutxo.** After a snapshot is loaded, the first blocks need the claim of
  the base block and the contributions of the 100 blocks below it, which are not
  on disk. `ConnectBlock` then stops with a fatal error. A fix is to record the
  pool outputs while loading the snapshot, using the identities in problem 6.
- **Fee estimation** still uses fees, not net fees.

## Tests

- `src/test/demurrage_tests.cpp`:
  - `POOL_SCRIPT` bytes, non-standardness, and that an empty scriptSig
    satisfies it;
  - the scheduled supply;
  - every mainnet rate period below 1,260,000 (all zero), the first non-zero
    rate 19,284,730,634, the first period of each later era, and the bound;
  - the index over sequences of periods, including that it does not depend on
    the activation height;
  - charges: outputs created before activation, outputs created and spent in
    the same block, rounding and `MAX_MONEY`;
  - claim transactions with one and with two inputs, their sizes and payouts;
  - the evaluation height;
  - the regtest schedule;
  - the height from which `getblocktemplate` requires the rule, for several
    activation heights.
- `test/functional/feature_demurrage.py`. node0 enforces the rules from height
  432. node1 does not enforce them, and accepts every block node0 accepts,
  claims and contributions included, which shows the rules are a soft fork. The
  test keeps its own model of the rate, index, charges and pool, and checks
  every block from activation against it. node2 has a chain of its own, on which
  the deployment activates through signalling. It covers:
  - on node2, the version bit for clients that do and do not declare the rule
    while the deployment is `started` and `locked_in`; the optional rule and the
    rate-limited warning from activation; and the required rule from 576;
  - on node0, the same switch at 576 with a forced activation height, and every
    `getblocktemplate` field checked against the model: each transaction's
    `charge` (zero for an input from an earlier transaction in the template),
    `demurrage_contribution`, `coinbasevalue` and the claim transaction. A block
    built from the template alone is valid;
  - pre-activation `POOL_SCRIPT` outputs, in the coinbase and in a transaction,
    and spending one after activation;
  - the zero-rate first period;
  - net fees at the evaluation height, and their recomputation when `E` moves
    and when a parent confirms;
  - inputs from unconfirmed parents, charged as if the parent confirms in the
    next block: the child's charge stays the same when the parent confirms in
    that block, and falls when it confirms later, also in a CPFP package;
  - contributions from block assembly and from `generateblock`;
  - an output created and spent in the same block;
  - claims with one and with two inputs, and their payouts;
  - every invalid-block case in the BIP's Test Vectors section, including 13
    alterations of the claim transaction;
  - the mempool policy for pool outputs on both kinds of node;
  - a pre-signed transaction whose fee is below its charge: mined at a loss in
    one case, rescued by CPFP through `submitpackage` in the other;
  - a reorg, in which claim transactions are not returned to the mempool,
    charges are recomputed, and the replacement claim has the same txid;
  - a block that node1 accepts and node0 rejects.
