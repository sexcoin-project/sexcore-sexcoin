// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** CHECKLOCKVERIFY, BIP66 and AuxPow starting heights for Sexcoin */
    int nCLTVStartBlock;
    int nBIP66MinStartBlock;
    int nAuxPowStartHeight;
    int nWitnessStartHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargetting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t nPowTargetSpacing2;
    int64_t nPowTargetTimespan2;
    int64_t nPowTargetSpacing3;
    int64_t nPowTargetTimespan3;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    int64_t DifficultyAdjustmentInterval2() const { return nPowTargetTimespan2 / nPowTargetSpacing2; }
    int64_t DifficultyAdjustmentInterval3() const { return nPowTargetTimespan3 / nPowTargetSpacing3; }
    uint256 nMinimumChainWork;
    
    /**
      * Sexcoin previous fork heighths
      */
    int Fork1Height; // 1st fork for retarget change
    int Fork2Height; // 1st fork for kgw activation
    int Fork3Height; // 2nd fork for kgw, kgw vulnerability fixed
    int Fork4Height; // 4th fork, fixed magic number problem, age verification and block version.
    int BlockVer4Height; 
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
