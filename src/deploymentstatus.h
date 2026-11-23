// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <algorithm>
#include <limits>
#include <optional>

/**
 * BIP 462b, test-only: the height from which one of its two deployments is
 * forced active with -testactivationheight, whatever the version bits state.
 */
inline std::optional<int> DemurrageTestHeight(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    if (dep == Consensus::DEPLOYMENT_DEMURRAGE) return params.DemurrageTestActivationHeight;
    if (dep == Consensus::DEPLOYMENT_DEMURRAGE_CHARGES) return params.DemurrageTestChargesHeight;
    return std::nullopt;
}

/** Determine if a deployment is active for the next block */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (const auto forced{DemurrageTestHeight(params, dep)}) {
        return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= *forced;
    }
    return versionbitscache.IsActiveAfter(pindexPrev, params, dep);
}

/**
 * BIP 462b: if one of its two deployments is active for the block after
 * pindexPrev, the first height at which it is active, otherwise nullopt.
 */
inline std::optional<int> DemurrageDeploymentHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    if (const auto forced{DemurrageTestHeight(params, dep)}) {
        const int next_height{pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1};
        return next_height >= *forced ? forced : std::nullopt;
    }
    return versionbitscache.ActivationHeight(pindexPrev, params, dep);
}

/**
 * BIP 462b policy: the first height at which one of its two deployments is
 * active, if that is known for the block after pindexPrev: once the deployment
 * is locked in, or at any height if it is forced with -testactivationheight.
 * Otherwise nullopt.
 */
inline std::optional<int> DemurrageKnownDeploymentHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    if (const auto forced{DemurrageTestHeight(params, dep)}) return forced;
    return versionbitscache.KnownActivationHeight(pindexPrev, params, dep);
}

/**
 * BIP 462b: if the demurrage rules apply to the block after pindexPrev, the
 * first height at which they apply (ACTIVATION_HEIGHT), otherwise nullopt.
 */
inline std::optional<int> DemurrageActivationHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    return DemurrageDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE, versionbitscache);
}

/**
 * BIP 462b: if the demurrage index has started to fall by the block after
 * pindexPrev, the height at which it started (CHARGE_HEIGHT): the first height
 * at which the demurrage and demurrage_charges deployments are both active.
 * Otherwise nullopt, and no block owes a charge.
 */
inline std::optional<int> DemurrageChargeHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    const auto activation{DemurrageDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE, versionbitscache)};
    const auto charges{DemurrageDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE_CHARGES, versionbitscache)};
    if (!activation || !charges) return std::nullopt;
    return std::max(*activation, *charges);
}

/**
 * BIP 462b policy: ACTIVATION_HEIGHT, if it is known for the block after
 * pindexPrev. The mempool refuses spends of pool outputs from it; consensus
 * uses DemurrageActivationHeight().
 */
inline std::optional<int> DemurrageKnownActivationHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    return DemurrageKnownDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE, versionbitscache);
}

/**
 * BIP 462b policy: CHARGE_HEIGHT, if it is known for the block after
 * pindexPrev: once each of the two deployments is locked in or active. The
 * mempool computes policy charges from it; consensus uses
 * DemurrageChargeHeight().
 */
inline std::optional<int> DemurrageKnownChargeHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    const auto activation{DemurrageKnownDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE, versionbitscache)};
    const auto charges{DemurrageKnownDeploymentHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE_CHARGES, versionbitscache)};
    if (!activation || !charges) return std::nullopt;
    return std::max(*activation, *charges);
}

/** Determine if a deployment is active for this block */
inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return index.nHeight >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAt(const CBlockIndex& index, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return DeploymentActiveAfter(index.pprev, params, dep, versionbitscache);
}

/** Determine if a deployment is enabled (can ever be active) */
inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::BuriedDeployment dep)
{
    assert(Consensus::ValidDeployment(dep));
    return params.DeploymentHeight(dep) != std::numeric_limits<int>::max();
}

inline bool DeploymentEnabled(const Consensus::Params& params, Consensus::DeploymentPos dep)
{
    assert(Consensus::ValidDeployment(dep));
    if (DemurrageTestHeight(params, dep)) return true;
    return params.vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
