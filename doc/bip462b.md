# BIP 462b reference implementation

This branch implements version 0.4.0 of the draft **BIP 462b, Soft-Fork
Demurrage Security Budget** (`bip-0462b.md`), except for the points listed under
[Differences from draft 0.4.0](#differences-from-draft-040). It was first
written against version 0.1.0. Versions 0.2.0 and 0.3.0 address the problems it
found in 0.1.0, listed below. Version 0.4.0 follows a review of 0.3.1 and of
this branch. No version changes a mainnet consensus rule when both deployments
activate together.

The demurrage is charged when an output is spent. The block owes the charge, the
coinbase pays it into a pool output, and a deterministic claim transaction at
index 1 of every later block pays out `floor(P / 10,000)` of the pool as its
fee.

There are two deployments. `demurrage` starts enforcement, at
`ACTIVATION_HEIGHT`. `demurrage_charges` starts the index, at `CHARGE_HEIGHT`,
the first height at which both are active. Both are defined on every network and
are `NEVER_ACTIVE` everywhere, because the BIP sets no activation parameters at
draft stage. On regtest they can be activated in two ways:

- `-testactivationheight=demurrage@<height>` and
  `-testactivationheight=demurrage_charges@<height>` apply each from a fixed
  height, whatever the version bits state. This is what most of the tests use.
  Forcing `demurrage` alone starts charges at the same height. Both heights are
  then known from the start, so the mempool computes policy charges even before
  them.
- `-vbparams=<deployment>:<start>:<timeout>[:<min_activation_height>]` activates
  either through signalling. The regtest period is 144 blocks and the threshold
  108.

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
| `CHARGE_TOLERANCE` (policy) | 1,000 satoshis | 1,000 satoshis | `demurrage::CHARGE_TOLERANCE` |
| Version bit of `demurrage` | 4 | 4 | `kernel/chainparams.cpp` |
| Version bit of `demurrage_charges` | 3 | 3 | `kernel/chainparams.cpp` |

Both bits are below 5, the range in which Bitcoin Core warns about unknown
deployments.

Regtest halves the subsidy every 150 blocks, so with the mainnet target the
subsidy covers the target until height 2,448. The regtest target is therefore
higher, and its rate periods match its 144-block version bits period.
With `CHARGE_HEIGHT` at 432, the first rate period has a zero rate, as on
mainnet before 2032. Charges begin at 576, with `r = 237,945,492,662,473`, about
0.024% per block. That is some 4,000 times the full mainnet rate, so the policy
margins are much shorter than on mainnet. An input of up to about 29,000
satoshis is evaluated 144 blocks ahead. One above about 0.042 BTC gains more
than `CHARGE_TOLERANCE` in a single block, so it is evaluated at the next
block's height and again every block. The mainnet equivalents at the full
target rate are about 1.2 BTC and 175 BTC.

## Where each part of the specification is implemented

| Spec section | Code |
|---|---|
| Parameters | `src/consensus/demurrage.h`; `src/consensus/params.h` (`DEPLOYMENT_DEMURRAGE`, `DEPLOYMENT_DEMURRAGE_CHARGES`, `Demurrage*`); per-network values in `src/kernel/chainparams.cpp` |
| Fixed-point arithmetic | `src/consensus/demurrage.cpp`: every product goes through `Wide`, which is `unsigned __int128`, or `arith_uint256` on compilers without it. `Narrow()` asserts that each result fits in 64 bits. |
| Demurrage rate | `demurrage::ScheduledSubsidy`, `ScheduledSupply`, `PeriodRate` |
| Demurrage index | `demurrage::NextIndex`, `demurrage::IndexSchedule::Index`, cached per `CHARGE_HEIGHT` by `ChainstateManager::DemurrageSchedule` |
| Demurrage charge | `demurrage::Charge`, `IndexSchedule::ChargeFor`; `C(h)` is summed in `Chainstate::ConnectBlock` from `Coin::nHeight`, and is zero until `CHARGE_HEIGHT` |
| Pool outputs | `demurrage::IsPoolScript`; `ConnectBlock` rejects `bad-demurrage-pool-create` and `bad-demurrage-pool-spend` from `ACTIVATION_HEIGHT` |
| Coinbase contribution | `ConnectBlock`, after the transaction loop: `bad-cb-demurrage-missing`, `-amount`, `-multiple`, `-unexpected` |
| Claim transaction | `demurrage::BuildClaimTransaction`; pool inputs from `ChainstateManager::GetDemurragePoolInputs`, which uses `GetDemurragePoolOutputs`, `RecordDemurragePoolOutputs` and `demurrage::FindBlockPoolOutputs`; `ConnectBlock` rejects `bad-demurrage-claim-missing` and `bad-demurrage-claim` |
| Summary of new block rules | `Chainstate::ConnectBlock`, all three rules |
| Deployment | `deploymentinfo.cpp`; in `deploymentstatus.h`, `DemurrageActivationHeight()` and `DemurrageChargeHeight()` (the later of the two activation heights); `VersionBitsCache::ActivationHeight`; `-testactivationheight` in `chainparams.cpp`; `getdeploymentinfo` in `rpc/blockchain.cpp` |
| Relay and mining policy: mining score | `demurrage::EvaluatePolicyCharge` gives `E_tx` and the policy charge. `CTxMemPoolEntry` keeps them (`m_demurrage_charge`) with the value and created height of each input (`m_demurrage_inputs`), and `GetModifiedFee()` excludes the charge. `MemPoolAccept::PreChecks`, `ChangeSet::StageAddition`, `CTxMemPool::SetDemurrageCharge` |
| Relay and mining policy: re-evaluation | `Chainstate::UpdateMempoolDemurrageCharges`, called from `ConnectTip` and `MaybeUpdateMempoolForReorg`. When a block connects, it evaluates again the entries whose `E_tx` is below the next block's height. After a reorganisation, or when `CHARGE_HEIGHT` changes, it looks up every input again and evaluates every entry. Nothing is evicted. |
| Relay and mining policy: unconfirmed inputs | An input that spends a mempool output has the created height `demurrage::UNCONFIRMED_HEIGHT`, which `EvaluatePolicyCharge` reads as the next block's height. When a block confirms the output, `UpdateMempoolDemurrageCharges` records the block's height for the input (found through `mapNextTx`) and leaves the charge as it is until the entry is next evaluated. |
| Relay and mining policy: before charges begin | `DemurrageKnownChargeHeight()` in `deploymentstatus.h` and `VersionBitsCache::KnownActivationHeight` give `CHARGE_HEIGHT` once each deployment is locked in or active, or at any height when forced with `-testactivationheight`. `PreChecks` and `UpdateMempoolDemurrageCharges` use it. Consensus and block assembly use `DemurrageChargeHeight()`, which applies only once both are active. |
| Relay and mining policy: relay | The existing fee checks (`CheckFeeRate`, package feerate, eviction) all read modified fees, so they use the net fee |
| Relay and mining policy: replacement | `CTxMemPoolEntry::GetModifiedFeeForReplacement()` adds back the growth of the policy charge since acceptance (`m_demurrage_charge_at_acceptance`). `MemPoolAccept::ReplacementChecks` and `PackageRBFChecks` sum it over the conflicts. |
| Relay and mining policy: fee rules | The ephemeral dust check in `PreChecks` compares the fee, not the net fee |
| Relay and mining policy: pool outputs | `PreChecks`: `demurrage-pool-output`, `demurrage-pool-spend`. Claim transactions from disconnected blocks fail the first check, so they are not returned to the mempool. |
| Relay and mining policy: block assembly | `BlockAssembler::CreateNewBlock`, `node::GetDemurrageCharges`, `node::GetBlockDemurrageCharge`; `BlockAssembler::RemoveUnfundedTransaction` leaves out a transaction whose charge the block cannot fund, with its descendants; `node::UpdateDemurrageContribution` for `generateblock`; the contribution is added to `CoinbaseTx::required_outputs` for IPC mining clients |
| Relay and mining policy: compact blocks | The `CBlockHeaderAndShortTxIDs` constructor in `blockencodings.cpp` prefills the transaction at index 1 when it is a claim transaction |
| Relay and mining policy: checking before relay | `ChainstateManager::HasExpectedDemurrageClaim`, in `ChainstateManager::AcceptBlock` before `NewPoWValidBlock` is signalled |
| getblocktemplate | `getblocktemplate` in `rpc/mining.cpp`, and `gbt_optional_rule` in `deploymentinfo.cpp`: `true` for `demurrage`, `false` for `demurrage_charges`. `WarnDemurrageRuleRequired` logs the warning. The `charge` and `demurrage_contribution` fields come from `CBlockTemplate::vTxDemurrageCharges` and `CBlockTemplate::demurrage_contribution`. |
| Fees and interfaces: node interfaces | `getmempoolentry`, `getrawmempool` and the other RPCs that describe mempool entries give `chargeheight`, `fees.charge` and `fees.net` (`rpc/mempool.cpp`). `gettxout` gives `charge` and `effective_value` (`rpc/blockchain.cpp`). Each field appears once `CHARGE_HEIGHT` is known. |
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
  `h − 100`. `ConnectBlock` records each block's two pool outpoints in the block
  index database, under `'d'` and the block's hash (72 bytes a block), and in a
  cache of recent blocks. A pruned node therefore does not need the blocks
  themselves. A block connected before these records were kept has none, and is
  read from disk once. Values come from the coins view.
- **Input prefetching.** `ConnectBlock`'s parallel input fetcher expects coins
  to be read in block order. The claim's inputs are therefore compared as
  outpoints before the loop, and their coins are read only when the loop reaches
  index 1.
- **Order of checks.** The claim check runs before `CheckTxInputs`. An altered
  claim is reported as `bad-demurrage-claim`, even when its output exceeds its
  inputs. The contribution is checked after the existing `bad-cb-amount` check.
- **Net fee as modified fee.** Policy charges are applied like a negative
  `prioritisetransaction` delta. Cluster linearisation, block assembly, package
  relay and mempool trimming then all rank by net fee without further changes.
  `getmempoolentry` reports `fees.modified` as base fee + delta − charge. The
  saved mempool (`mempool.dat`) records the delta without the charge, which is
  computed again when the transaction is loaded.
- **Net fee at acceptance.** It is kept in memory only. After a restart it is
  the net fee when the transaction was loaded.
- **Finding `E_tx`.** `charge_at(e)` does not fall as `e` rises, so
  `EvaluatePolicyCharge` finds `E_tx` by bisection: about ten evaluations of
  `charge_at` for each transaction, and three when the full margin is within the
  tolerance.
- **Block assembly.** The claim's weight is reserved before transactions are
  selected. `C(h)` is computed exactly at the block's height from the coins tip.
  Inputs spending outputs of earlier transactions in the block have no charge.
  The contribution is coinbase output 1, before the witness commitment. When the
  contribution exceeds the subsidy, the fees and the payout, the assembler
  removes the transaction with the greatest charge less fee, and its
  descendants, until it does not, and logs each one. Only a transaction
  prioritised by hand can cause this.
- **Checking before relay.** The check covers blocks whose parent is the tip,
  which are the only ones announced before validation. It passes a block whose
  pool inputs it cannot find.

## Defects found in the review of draft 0.3.1

The review that led to draft 0.4.0 reproduced two defects of this branch on
regtest, and found a third by reading. All three are fixed, and the functional
test covers each.

1. **Policy charges doubled at every restart.** The saved mempool recorded
   `modified fee − fee` as the transaction's prioritisation, and that difference
   included the charge. On loading, the charge was applied as a delta and then
   computed again. A transaction with a 4.21 BTC charge had 8.41 BTC after one
   restart, and was dropped after the second, leaving a prioritisation entry for
   a transaction that no longer existed.
2. **A pruned node shut down when it connected a block again.** The pool inputs
   were found by reading blocks `h − 1` and `h − 100`. On a pruned node,
   `verifychain 4 0` connects again the lowest blocks that are still stored. It
   failed to read the pruned blocks below them and stopped the node. The pool
   outpoints are now kept with the block index.
3. **Block assembly threw when a block could not fund its contribution.** A
   transaction prioritised by hand whose charge exceeded the block's subsidy and
   fees made every `getblocktemplate` call fail until it left the mempool. The
   assembler now leaves it out.

## Observations on draft 0.4.0

Found while implementing it.

1. **Large inputs have no margin.** An input whose charge grows by more than
   `CHARGE_TOLERANCE` a block (about 175 BTC at the full mainnet rate, any
   coinbase output on regtest) is evaluated at the next block's height. A
   transaction that spends it at the minimum relay feerate falls below that
   feerate after one block. Its net fee then falls every block until it is
   bumped. The same holds for a child of an unconfirmed parent: its policy
   charge is zero, and it owes a block's decay as soon as its parent confirms
   without it. The draft's Open Questions now ask whether a minimum margin is
   needed.
2. **Mempools of nodes that do not enforce the rules diverge.** Such a node
   compares fees where an enforcing node compares net fees. In the functional
   test, node1 keeps a transaction that node0 has replaced, until the block that
   confirms the replacement arrives. This follows from any policy on net fees.
3. **The check before relay does not cover the contribution**, as the draft
   says. A block with the right claim transaction and a wrong contribution is
   still announced to high-bandwidth compact block peers before it is rejected.
   The functional test shows both cases, and still has to isolate its
   non-enforcing node for the second.

## Problems found in draft 0.1.0

Drafts 0.2.0 and 0.3.0 address each of these. The evaluation height `E` they
refer to was one height for the whole mempool, which draft 0.4.0 replaced with a
height for each transaction. Each numeric claim in draft 0.1.0 was checked against an independent
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
   yet fixed. This implementation charged nothing until the deployment was
   active for the next block. On mainnet this matters only if the deployment
   activates at 1,260,000 or later, because the rate is zero below that height.
   Draft 0.2.0 charges from lock-in, and this
   implementation now does the same.
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

This follows the draft's `getblocktemplate` section as of version 0.4.0.

- **`demurrage`.** While the deployment is `started` or `locked_in`, the
  template's version has its bit for every client, so its signalling counts
  upgraded nodes, not upgraded mining software. From `ACTIVATION_HEIGHT` the
  template lists it as an optional rule.
- **`demurrage_charges`.** While signalling, it is listed in `vbavailable` as
  `!demurrage_charges`, and the template's version has its bit only for clients
  that declare the rule. From `CHARGE_HEIGHT` the template lists it in `rules`:
  as `demurrage_charges` while no block can owe a charge, and as
  `!demurrage_charges` from the first rate period with a non-zero rate
  (`IndexSchedule::FirstChargeHeight()`: 1,260,000 on mainnet, or
  `CHARGE_HEIGHT` if that is later; 576 on regtest with `CHARGE_HEIGHT` at 432).
  From then a client that does not declare it gets the error
  `Support for 'demurrage_charges' rule requires explicit client support`. This
  applies whether the deployments activated through version bits or were forced
  with `-testactivationheight`.
- **Warning.** From `ACTIVATION_HEIGHT` until the rule is required, each request
  from a client that does not declare `demurrage_charges` logs a warning that
  templates will require it, and from which height once `CHARGE_HEIGHT` is
  known, at most once an hour.
- **Fields.** From `ACTIVATION_HEIGHT`, each transaction has a `charge`, its
  charge at the template's height, and the template has a
  `demurrage_contribution`, `C(h)`. The claim transaction is the first entry of
  `transactions`, with the payout as its `fee` and a `charge` of 0.
  `coinbasevalue` is `subsidy + fees − C(h)`, where fees include the payout.
  `default_witness_commitment` is still the witness commitment. The contribution
  is not one of the outputs it describes.

## Differences from draft 0.4.0

- **Compact blocks, receiving side.** A node does not build the claim
  transaction of a compact block that lacks it. It requests it with
  `getblocktxn`, as for any other missing transaction. Senders prefill it, so
  this costs a round trip only for blocks relayed by nodes that do not implement
  the BIP.
- **assumeutxo.** The draft states how to find the pool inputs in a snapshot.
  This implementation does not do so. After a snapshot is loaded, the first
  blocks need the claim of the base block and the contributions of the 100
  blocks below it, of which there is no record, and `ConnectBlock` stops with a
  fatal error. A fix is to write the records while loading the snapshot, using
  the identities in problem 6 below.
- **PSBT.** There is no per-input confirmation height field.
- **Wallet.** The wallet does not add the charge to its fee. Once a wallet
  transaction's policy charge exceeds its fee, the mempool rejects it with
  `min relay fee not met`. The wallet does not report effective balances.
- **Fee estimation** still uses fees, not net fees.
- **Node interfaces.** Only the mempool RPCs and `gettxout` report charges.
  `scantxoutset`, `testmempoolaccept` and the REST interface do not.
- **Stratum V2**: left by the draft to a separate specification.

The two deployments, per-transaction evaluation heights, re-evaluation, the
charge of unconfirmed inputs, charges from the lock-in of both deployments, the
replacement rule, block assembly, compact block prefilling, the check before
relay, the `getblocktemplate` support, the fee rule for ephemeral dust and the
regtest parameters match the draft.

## Tests

- `src/test/demurrage_tests.cpp`:
  - `POOL_SCRIPT` bytes, non-standardness, and that an empty scriptSig
    satisfies it;
  - the scheduled supply;
  - every mainnet rate period below 1,260,000 (all zero), the first non-zero
    rate 19,284,730,634, the first period of each later era, and the bound;
  - the index over sequences of periods, including that it does not depend on
    the height at which it starts;
  - charges: outputs created before `CHARGE_HEIGHT`, outputs created and spent
    in the same block, rounding and `MAX_MONEY`;
  - claim transactions with one and with two inputs, their sizes and payouts;
  - policy charges: the draft's ten mainnet evaluation height vectors, the
    zero-rate case, and 200 random sets of regtest inputs against a linear
    search;
  - the serialisation of a block's pool output record;
  - the regtest schedule;
  - the height from which `getblocktemplate` requires the rule, for several
    values of `CHARGE_HEIGHT`.
- `src/test/versionbits_tests.cpp`: `VersionBitsCache::KnownActivationHeight`
  while started, locked in and active, with and without a
  `min_activation_height`.
- `test/functional/feature_demurrage.py`. node0 enforces the rules from height
  288 and starts the index at 432. node1 does not enforce them, and accepts
  every block node0 accepts, claims and contributions included, which shows the
  rules are a soft fork. The test keeps its own model of the rate, index,
  charges, pool and policy charge, and checks every block from activation, and
  node0's mempool entries, against it. node2 has a chain of its own, on which
  the deployments activate through signalling. node3 is pruned. It covers:
  - on node2, both version bits for clients that do and do not declare
    `demurrage_charges`. Blocks built without the declaration lock in
    `demurrage` alone, and `demurrage_charges` follows a period later, so
    `ACTIVATION_HEIGHT` is 432 and `CHARGE_HEIGHT` 576. The optional
    `demurrage` rule and the rate-limited warning from 432, no policy charges
    until both are locked in, and the required rule from 576;
  - on node0, enforcement without charges from 288, the optional
    `demurrage_charges` rule from 432 and the required one from 576, and every
    `getblocktemplate` field checked against the model: each transaction's
    `charge` (zero for an input from an earlier transaction in the template),
    `demurrage_contribution`, `coinbasevalue` and the claim transaction. A block
    built from the template alone is valid;
  - pre-activation `POOL_SCRIPT` outputs, in the coinbase and in a transaction,
    and spending one after activation;
  - the zero-rate first period, and `gettxout`'s `charge` and `effective_value`
    before and after charges begin;
  - evaluation heights: inputs of 20,000, 100,000 and 1,000,000 satoshis and of
    50 BTC get margins of 144 blocks, some tens, a few and none. Each
    transaction is evaluated again only when the next block's height exceeds its
    own evaluation height;
  - inputs from unconfirmed parents, charged as if the parent confirms in the
    next block. The child's policy charge does not change when the parent
    confirms, in that block or a later one, and from its next evaluation it is
    charged from the parent's actual height;
  - contributions from block assembly and from `generateblock`;
  - an output created and spent in the same block;
  - claims with one and with two inputs, and their payouts;
  - every invalid-block case in the BIP's Test Vectors section, including 13
    alterations of the claim transaction;
  - the mempool policy for pool outputs on both kinds of node;
  - a pre-signed transaction whose fee is below its charge: mined at a loss in
    one case, rescued by CPFP through `submitpackage` in the other;
  - replacement: a transaction whose net fee has fallen below zero cannot be
    replaced for less than its net fee at acceptance;
  - a prioritised transaction whose charge no block can fund, and its child,
    are left out of the template, and the template is valid;
  - two restarts, after which policy charges, net fees and prioritisation are
    what they were;
  - compact blocks that prefill the claim transaction; a block without the
    expected claim transaction is not announced before validation, and one with
    a wrong contribution still is;
  - a reorg, in which claim transactions are not returned to the mempool, every
    policy charge is evaluated again, and the replacement claim has the same
    txid;
  - on node3, `verifychain` at level 4 over blocks whose pool inputs were
    created in pruned blocks;
  - a block that node1 accepts and node0 rejects.

Each of the replacement, announcement and pruning cases was also run against a
build with the corresponding change removed, and failed there.
