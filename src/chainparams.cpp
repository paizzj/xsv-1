// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "policy/policy.h"
#include "script/script_num.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cassert>
#include <iostream>

#include "chainparamsseeds.h"

#define GENESIS_ACTIVATION_MAIN                 4950
#define GENESIS_ACTIVATION_STN                  14896
#define GENESIS_ACTIVATION_TESTNET              1344
#define GENESIS_ACTIVATION_REGTEST              10000

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "2020-02-27 genesis block";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
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
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 388381;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 363725;
        // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.CSVHeight = 419328;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        // 95% of 2016
        consensus.nRuleChangeActivationThreshold = 1916;
        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(
            "000000000000000000000000000000000000000000a0f3064330647e2f6c4828");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S(
            "000000000000000000e45ad2fbcc5ff3e85f0868dd8f00ad4e92dffabe28f8d2");

        // August 1, 2017 hard fork
        consensus.uahfHeight = 478558;

        // November 13, 2017 hard fork
        consensus.daaHeight = 504031;

        // February 2020, Genesis Upgrade
        consensus.genesisHeight = GENESIS_ACTIVATION_MAIN;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1582772650, 48272618, 0x1d00ffff, 1,
                                     50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
       /* assert(consensus.hashGenesisBlock ==
               uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1"
                        "b60a8ce26f"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));*/

        // Note that of those with the service bits flag, most only support a
        // subset of possible options.
        // Bitcoin SV seeder
        //vSeeds.push_back(CDNSSeedData("bitcoinsv.io", "seed.bitcoinsv.io", true));
        // cascharia.com
        //vSeeds.push_back(CDNSSeedData("cascharia.com", "seed.cascharia.com", true));
        // satoshisvision.network
        //vSeeds.push_back(CDNSSeedData("satoshisvision.network", "seed.satoshisvision.network", true));
        
    // top7 seednode   
	vSeeds.push_back(CDNSSeedData("47.110.137.123", "47.110.137.123", false));
	// v6 seed node
	vSeeds.push_back(CDNSSeedData("47.75.53.6", "47.75.53.6", false));
    // xsv seednode
    vSeeds.push_back(CDNSSeedData("120.77.45.167", "120.77.45.167", false));
	
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

	vFixedSeeds = std::vector<SeedSpec6>(
	     pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = { {
	    // todo
            }};

        // Data as of block
        // 000000000000000001d2ce557406b017a928be25ee98906397d339c3f68eec5d
        // (height 523992).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1522608016,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the SetBestChain bitcoind.log lines)
            248589038,
            // Estimated number of transactions per second after that timestamp.
            3.2};

        defaultBlockSizeParams = DefaultBlockSizeParams{
            // activation time 
            MAIN_NEW_BLOCKSIZE_ACTIVATION_TIME,
            // max block size
            MAIN_DEFAULT_MAX_BLOCK_SIZE,
            // max generated block size before activation
            MAIN_DEFAULT_MAX_GENERATED_BLOCK_SIZE_BEFORE,
            // max generated block size after activation
            MAIN_DEFAULT_MAX_GENERATED_BLOCK_SIZE_AFTER
        };

        fTestBlockCandidateValidity = false;
    }
};

/**
 * Scaling test network
 */
class CStnParams : public CChainParams
{
public:
    CStnParams()
    {
        strNetworkID = "stn";

        std::vector<unsigned char> rawScript(ParseHex("76a914a123a6fdc265e1bbcf1123458891bd7af1a1b5d988ac"));
        CScript outputScript(rawScript.begin(), rawScript.end());

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526"
                        "f8d77f4943"));

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        // Do not allow min difficulty blocks after some time has elapsed
        consensus.fPowAllowMinDifficultyBlocks = false;

        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 144; // fast

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // August 1, 2017 hard fork
        consensus.uahfHeight = 15;

        // November 13, 2017 hard fork
        consensus.daaHeight = 2200;     // must be > 2016 - see assert in pow.cpp:268

        // February 2020, Genesis Upgrade
        consensus.genesisHeight = GENESIS_ACTIVATION_STN;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xfb;
        diskMagic[1] = 0xce;
        diskMagic[2] = 0xc4;
        diskMagic[3] = 0xf9;
        netMagic[0] = 0xfb;
        netMagic[1] = 0xce;
        netMagic[2] = 0xc4;
        netMagic[3] = 0xf9;
        nDefaultPort = 9333;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("bitcoinsv.io", "stn-seed.bitcoinsv.io", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds = std::vector<SeedSpec6>();

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {  { 
                {0, uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")},
                {1, uint256S("00000000e23f9436cc8a6d6aaaa515a7b84e7a1720fc9f92805c0007c77420c4")}
        }};

        defaultBlockSizeParams = DefaultBlockSizeParams{
            // activation time 
            STN_NEW_BLOCKSIZE_ACTIVATION_TIME,
            // max block size
            STN_DEFAULT_MAX_BLOCK_SIZE,
            // max generated block size before activation
            STN_DEFAULT_MAX_GENERATED_BLOCK_SIZE_BEFORE,
            // max generated block size after activation
            STN_DEFAULT_MAX_GENERATED_BLOCK_SIZE_AFTER
        };

        fTestBlockCandidateValidity = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 581885;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 330776;
        // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.CSVHeight = 770112;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 1512;
        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(
            "00000000000000000000000000000000000000000000002a650f6ff7649485da");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S(
            "0000000000327972b8470c11755adf8f4319796bafae01f5a6650490b98a17db");

        // August 1, 2017 hard fork
        consensus.uahfHeight = 1155875;

        // November 13, 2017 hard fork
        consensus.daaHeight = 1188697;

        // February 2020, Genesis Upgrade
        consensus.genesisHeight = GENESIS_ACTIVATION_TESTNET;

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;

        genesis =
            CreateGenesisBlock(1584691144, 1401803327, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

		//assert(consensus.hashGenesisBlock ==
		//uint256S("29830d4540dd4222082d0b7c665d087cf765cb7181ceee280fa95bf22b9cd0da"));
        /*assert(consensus.hashGenesisBlock ==
               uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526"
                        "f8d77f4943"));*/
       /* assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));*/

        //assert(genesis.hashMerkleRoot ==
		//	  uint256S("7b3aa26f615802b673f868ae9201682c40d95d279ab04c7f7d0e4ddf8c0e5a9e"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // Bitcoin SV seeder
        /*vSeeds.push_back(CDNSSeedData("bitcoinsv.io", "testnet-seed.bitcoinsv.io", true));
        vSeeds.push_back(CDNSSeedData("cascharia.com", "testnet-seed.cascharia.com", true));
        vSeeds.push_back(CDNSSeedData("bitcoincloud.net", "testnet-seed.bitcoincloud.net", true));
*/
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = { {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345"
                               "d31b1bcebf76acb70")},
                // UAHF fork block.
                {1155875, uint256S("00000000f17c850672894b9a75b63a1e72830bbd5f4"
                                   "c8889b5c1a80e7faef138")},
                // Nov, 13. DAA activation block.
                {1188697, uint256S("0000000000170ed0918077bde7b4d36cc4c91be69fa"
                                   "09211f748240dabe047fb")}
            }};

        // Data as of block
        // 000000000005b07ecf85563034d13efd81c1a29e47e22b20f4fc6919d5b09cd6
        // (height 1223263)
        chainTxData = ChainTxData{1522608381, 15052068, 0.15};

        defaultBlockSizeParams = DefaultBlockSizeParams{
            // activation time 
            TESTNET_NEW_BLOCKSIZE_ACTIVATION_TIME,
            // max block size
            TESTNET_DEFAULT_MAX_BLOCK_SIZE,
            // max generated block size before activation
            TESTNET_DEFAULT_MAX_GENERATED_BLOCK_SIZE_BEFORE,
            // max generated block size after activation
            TESTNET_DEFAULT_MAX_GENERATED_BLOCK_SIZE_AFTER
        };

        fTestBlockCandidateValidity = false;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        // CSV activated on regtest (Used in rpc activation tests)
        consensus.CSVHeight = 576;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 108;
        // Faster than normal for regtest (144 instead of 2016)
        consensus.nMinerConfirmationWindow = 144;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // UAHF is always enabled on regtest.
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        // February 2020, Genesis Upgrade
        consensus.genesisHeight = GENESIS_ACTIVATION_REGTEST;

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1584690731, 136746120, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));

        //!< Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //!< Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = { {
                              {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5"
                                           "beb436012afca590b1a11466e2206")}
                          }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        defaultBlockSizeParams = DefaultBlockSizeParams{
            // activation time 
            REGTEST_NEW_BLOCKSIZE_ACTIVATION_TIME,
            // max block size
            REGTEST_DEFAULT_MAX_BLOCK_SIZE,
            // max generated block size before activation
            REGTEST_DEFAULT_MAX_GENERATED_BLOCK_SIZE_BEFORE,
            // max generated block size after activation
            REGTEST_DEFAULT_MAX_GENERATED_BLOCK_SIZE_AFTER
        };

        fTestBlockCandidateValidity = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

void ResetNetMagic(CChainParams& chainParam, const std::string& hexcode)
{
    if(!HexToArray(hexcode, chainParam.netMagic))
        throw std::runtime_error(strprintf("%s: Bad hex code %s.", __func__, hexcode)); 
}


bool HexToArray(const std::string& hexstring, CMessageHeader::MessageMagic& array){
    if(!IsHexNumber(hexstring))
        return false;

    const std::vector<uint8_t> hexVect = ParseHex(hexstring);

    if(hexVect.size()!= array.size())
        return false;

    std::copy(hexVect.begin(),hexVect.end(),array.begin());

    return true;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    }

    if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    }

    if (chain == CBaseChainParams::STN) {
        return std::unique_ptr<CChainParams>(new CStnParams());
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);

    // If not mainnet, allow to set the parameter magicbytes (for testing propose)
    const bool isMagicBytesSet = gArgs.IsArgSet("-magicbytes");
    if(network != CBaseChainParams::MAIN && isMagicBytesSet){
        const std::string magicbytesStr = gArgs.GetArg("-magicbytes", "0f0f0f0f");
        LogPrintf("Manually set magicbytes [%s].\n",magicbytesStr);
        ResetNetMagic(*globalChainParams,magicbytesStr);
    }
}
