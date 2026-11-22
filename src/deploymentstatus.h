// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTSTATUS_H
#define BITCOIN_DEPLOYMENTSTATUS_H

#include <chain.h>
#include <versionbits.h>

#include <limits>
#include <optional>

/** Determine if a deployment is active for the next block */
inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::BuriedDeployment dep, [[maybe_unused]] VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= params.DeploymentHeight(dep);
}

inline bool DeploymentActiveAfter(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos dep, VersionBitsCache& versionbitscache)
{
    assert(Consensus::ValidDeployment(dep));
    if (dep == Consensus::DEPLOYMENT_DEMURRAGE && params.DemurrageTestActivationHeight) {
        return (pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1) >= *params.DemurrageTestActivationHeight;
    }
    return versionbitscache.IsActiveAfter(pindexPrev, params, dep);
}

/**
 * BIP 462b: if the demurrage rules apply to the block after pindexPrev, the
 * first height at which they apply (ACTIVATION_HEIGHT), otherwise nullopt.
 */
inline std::optional<int> DemurrageActivationHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params, VersionBitsCache& versionbitscache)
{
    if (const auto& forced{params.DemurrageTestActivationHeight}) {
        const int next_height{pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1};
        return next_height >= *forced ? forced : std::nullopt;
    }
    return versionbitscache.ActivationHeight(pindexPrev, params, Consensus::DEPLOYMENT_DEMURRAGE);
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
    if (dep == Consensus::DEPLOYMENT_DEMURRAGE && params.DemurrageTestActivationHeight) return true;
    return params.vDeployments[dep].nStartTime != Consensus::BIP9Deployment::NEVER_ACTIVE;
}

#endif // BITCOIN_DEPLOYMENTSTATUS_H
