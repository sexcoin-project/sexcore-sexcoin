
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=4e9b54001f9976049830128ec0331515eaabe35a70970d79971da1539a400ba1, PoW=000001a16729477595c7247e1b49b4ec93acca8345037177cabbe898ce8a5783, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000,
 *     hashMerkleRoot=0317d32e01a2adf6f2ac6f58c7cdaab6c656edc6fdb45986c739290053275200,
 *     nTime=1405164774, nBits=1e01ffff, nNonce=4016033, vtx=1)
 *   CTransaction(hash=0317d32e01, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *   CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d01044c4e426c6f636b20233331303337393a30303030303030303030303030303030323431323532613762623237626539376265666539323138633132393064666633366331666631323965633732313161)
 *   CTxOut(nValue=0.00000000, scriptPubKey=0459934a6a228ce9716fa0b13aa1cd)
 * vMerkleTree: 0317d32e01a2adf6f2ac6f58c7cdaab6c656edc6fdb45986c739290053275200
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Disaster from the sky in Oklahoma";
    const CScript genesisOutputScript = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 600000;
        consensus.nMajorityEnforceBlockUpgrade = 2348569;
        consensus.nMajorityRejectBlockOutdated = 2348569;
        consensus.nMajorityWindow = 20000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0xf42b9553085a1af63d659d3907a42c3a0052bbfa2693d3acf990af85755f2279");
        consensus.powLimit = ArithToUint256(~(arith_uint256(0)) >> 5); // ~uint25(0) >> 23
        consensus.nPowTargetTimespan = 8 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 144; // 1% of nMinerConfirmationWindow
        consensus.nMinerConfirmationWindow = 14400;     // 1 day
        consensus.nCLTVStartBlock = 3106030;                    // segwit: OP_CHECKTIMELOCKVERIFY
        consensus.nBIP66MinStartBlock = 3106030;                // segwit: strict DER enforcement
        consensus.nAuxPowStartHeight = AuxPow::START_MAINNET;   // AuxPow starting height
        consensus.nWitnessStartHeight = 3106030;                // segwit: activation
        
        consensus.nPowTargetTimespan2 = 30 * 60; // 30 minutes
        consensus.nPowTargetSpacing2 = 30; // 30 seconds
        
        consensus.nPowTargetTimespan3 = 15 * 60; // 15 minutes
        consensus.nPowTargetSpacing3 = 60; // 60 second
        
        consensus.Fork1Height = 155000;
        consensus.Fork2Height = 572000;
        consensus.Fork3Height = 643808;
        consensus.BlockVer4Height = 2348569; // age verification start

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1539892620; // October 18, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1760817419;   // October 18, 2025

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1539892620; // October 18, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1760817419;   // October 18, 2025

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000b22b163c2b81fb4d");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0x69;
        pchMessageStart[3] = 0x69;
        nDefaultPort = 9560;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1369146359, 244086, 0x1e7fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xf42b9553085a1af63d659d3907a42c3a0052bbfa2693d3acf990af85755f2279"));
        assert(genesis.hashMerkleRoot == uint256S("0x661de12dc8dd26989adb169733b5a99150d52b8b6e8332976277856e246101f4"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        // TODO - LED - Check which viacoin nodes support service bits and add the 'true' flag
        vSeeds.push_back(CDNSSeedData("sexcoin.info", "dnsseed.sexcoin.info"));
        vSeeds.push_back(CDNSSeedData("lavajumper.com", "dnsseed.lavajumper.com"));


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,62);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,69);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,190);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

	checkpointData = (CCheckpointData) {
		boost::assign::map_list_of
                ( 0, uint256S("0x2946a91685f253cd2ca29cde8cc35d7773cab280cdab4a075f613636e697aca4"))
                ( 5363, uint256S("0xc5dd0d66a07c176a4463be3df7d9309986a3918b75935dde1c4769e4a64f9593"))
                ( 5369, uint256S("0xdcd139890a39921876ab035eca34ee48c5239889f1dcdb8e3de3d097847f12d8"))
                ( 5380, uint256S("0xb105b9cbb7b0ff4f2f6aef1d040c196edc2ab4318f7e6811a4373e8278cd5bb4"))
                ( 13899, uint256S("0x883879d5325e48511e96557fff17df10123f062de23bc1f91f4e153154dbc764"))
                ( 14050, uint256S("0x5be09cdd886573a50d543e3cca35a03eff2e46e4596bb2f509cede9e28dd33e9"))
                ( 22984, uint256S("0x87ecfd9aa3c722132dd1786caa5ccb25b8ff821a3797aa0c424e10662aca509d"))
                ( 39986, uint256S("0x9dba252fa6eebbf2b6c790965806c51916870bdf1e91bb7bf11eea55e64f12f8"))
                ( 49979, uint256S("0xe564a2434f3acb7fe4af103927083fee3fa6429afa430e53b6eade3249dfe026"))
                ( 80493, uint256S("0x6da822b8d4b5c060aee57523952630ac2262d5f56759ffc451ba6298b5fa423b"))
                ( 94458, uint256S("0x084c2dec2c0da13e8f0143303d8f27ae79c81311ec804b2f746fbc1ad83bff14"))
                ( 136354,uint256S("0x4f75d45e08213d5bb0584ce1e65666d47596cb8059b20d1c354b5bfd26309fbe"))
                (146221,uint256S("0xc9d38afb57b0b25c822b1287197de413204cacfb27ca9c974772d8d8399737cb"))
                (146849,uint256S("0xc5e18cab151a7eca95b02bd469c5a2aee301ef1b01e3b72add7f04a9c11f8b60"))
                (249936,uint256S("0x6722b04059d14fce5f74eb4a9ea02784ae690c4985ba32801e2cf1f8b65582f3"))
                (279841,uint256S("0xeb3bdef3524a2b0fd89f5480ac2a0a82108539b8e3156b598675e7109803cafa"))
                (319767,uint256S("0x8fbcfa3dac1721fd899f4cf67a7381a86fdcfb5fb504e1729d6a9fe3b389a790"))
                (359900,uint256S("0xfc4faa77d8e6c01941170e131125d5ebb5c9453fbaf3e6c2b0974b66c00f3bcd"))
                (499996,uint256S("0xd28773f08f4747ff6e7e4d113753b5a79b60d905e59ae4046fa4b5ee9965badc"))
                (599825,uint256S("0x0ddf7a53506b99acd201c13fba89b13837eb1707e97c27416f7513052cfd14af"))
                (699886,uint256S("0x1663390cdccecaeea59f35affa91d04f57f9b790b8f1493b7f62d4de2279449a"))
                (809963,uint256S("0xe7c094afaeaf37d20ce7d912b8353c41ac51c5219b1984acda32bfc889898203"))
                (1000293,uint256S("0x40cb1f758e1c3f71b22326f0f9c610202600bd5f83aea5272f4a2d978d344163"))
                (1200283,uint256S("0x6a1238c4d255d45d2669b83730b015ac0534e9e61af543fa66832c918747260f"))
                (1400278,uint256S("0x5c75334308a26b9220b50b8d0adf06fed4921e7a2fbc2b5c551bb9a807533b9f"))
                (1600189,uint256S("0x4b0608c7e733c1b6d2d660469f1b3c17be857ccb19d8e102f41503ab549e2f69"))
                (1800085,uint256S("0x422e9d5dab710fae371a1e182243af38a49db0cfb3d075a5c67da2c4f35df9ef"))
                (2000124,uint256S("0x34710dfebf36429ee09c7bd351671a2716f62f60fbbf9fb231be2314e88615ce"))
                (2100141,uint256S("0xb449eb898b032e00ec87458991a5182cc541c3b479250ed0087860dc60980412"))
                (2399993,uint256S("0xce314cabe66fb60e79a00170b584595d8113e379f165ed9b530db8cc4cb9da0b"))
                (2699990,uint256S("0xfc077d18f64576094c6a6397a7588c6b85ddf2c7a2d41b52ba200ab875aea4e2"))
                (3013737,uint256S("0xeff50a7e9b94b04662d2209dbe8f0f6d0a3796b6f3915cee8ca8dbbae606455c")),
            1542196226, // * UNIX timestamp of last checkpoint block
            3814864,   // * total number of transactions between genesis and last checkpoint
			//   (the tx=... number in the SetBestChain debug.log lines)
			10000.0     // * estimated number of transactions per day after checkpoint
	};

    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 200000;
        consensus.nMajorityEnforceBlockUpgrade = 510;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256S("0x0");
        consensus.powLimit = ArithToUint256(~(arith_uint256(0)) >> 5); // ~uint25(0) >> 19
        consensus.nPowTargetTimespan = 8 * 60 * 60; // 8 Hours 
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1; // 75% of nMinerConfirmationWindow
        consensus.nMinerConfirmationWindow = 25; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nCLTVStartBlock = 3100;                       // segwit: OP_CHECKTIMELOCKVERIFY
        consensus.nBIP66MinStartBlock = 3100;                   // segwit: strict DER enforcement
        consensus.nAuxPowStartHeight = AuxPow::START_TESTNET;   // auxpow: start accepting auxpow blocks
        consensus.nWitnessStartHeight = 2100;                   // segwit: start accepting segwit
        


        consensus.nPowTargetTimespan2 = 30 * 60; // 30 minutes
        consensus.nPowTargetSpacing2 = 30; // 30 seconds
        
        consensus.nPowTargetTimespan3 = 15 * 60; // 15 minutes
        consensus.nPowTargetSpacing3 = 60; // 60 seconds

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1232032894; // start + (1year/25)

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1494547200; // May 12, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1760294955; // Oct 12, 2025

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1494547200; // May 12, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1526083200; // May 12, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000006fce5d67766e");
        consensus.nMinimumChainWork = uint256S("0x0");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0x96;
        pchMessageStart[3] = 0x69;
        nDefaultPort = 19560;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1473215502,517454, 0x1e7fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x73dc70a1698579360b62e724ecfeacfd938f45283162f3cf18f1b9eb3fc9fcd7"));
        // assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("bootstrap-testnet.viacoin.net", "testnet.viacoin.net"));


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,124);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
                ( 4230, uint256S("0x15a29dde01cbad777180c089bc8fcf0d7b4bd18993b47d8c301c41fc90ce8c8f")),
                1405625749,
                4440,
                5000
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 900;
        consensus.nMajorityEnforceBlockUpgrade = 7500;
        consensus.nMajorityRejectBlockOutdated = 9500;
        consensus.nMajorityWindow = 10000;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint25(0) >> 1
        consensus.nPowTargetTimespan = 8 * 60 * 60; // 8 hours
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 30; // Faster than normal for regtest (144 instead of 2016)
        consensus.nCLTVStartBlock = 1;
        consensus.nBIP66MinStartBlock = 1;
        consensus.nAuxPowStartHeight = AuxPow::START_REGTEST;
        consensus.nWitnessStartHeight = 20000;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0x99;
        pchMessageStart[3] = 0x99;
        nDefaultPort = 19569;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1473215502, 517454, 0x1e1fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x73dc70a1698579360b62e724ecfeacfd938f45283162f3cf18f1b9eb3fc9fcd7"));
        // assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

	checkpointData = (CCheckpointData){
         boost::assign::map_list_of
            ( 0, uint256S("0x73dc70a1698579360b62e724ecfeacfd938f45283162f3cf18f1b9eb3fc9fcd7")),
            1405166035,
			0,
			0
	};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
