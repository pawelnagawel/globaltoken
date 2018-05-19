// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <primitives/mining_block.h>
#include <primitives/pure_auxpow.h>

#include <serialize.h>
#include <uint256.h>

namespace Consensus {
    struct Params;
};

static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;

/** Algos */
enum : uint8_t { 
    ALGO_SHA256D   = 0,
    ALGO_SCRYPT    = 1,
    ALGO_X11       = 2,
    ALGO_NEOSCRYPT = 3,
    ALGO_EQUIHASH  = 4,
    ALGO_YESCRYPT  = 5,
    ALGO_HMQ1725   = 6,
    ALGO_XEVAN     = 7,
    ALGO_NIST5     = 8,
    NUM_ALGOS_IMPL };

const int NUM_ALGOS = 9;

std::string GetAlgoName(uint8_t Algo);

/**
 * A block header without auxpow information.  This "intermediate step"
 * in constructing the full header is useful, because it breaks the cyclic
 * dependency between auxpow (referencing a parent block header) and
 * the block header (referencing an auxpow).  The parent block header
 * does not have auxpow itself, so it is a pure header.
 */
class CPureBlockHeader
{
public:
    // header
    uint8_t nAlgo;
    CPureBlockVersion nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nBigNonce;
    std::vector<unsigned char> nSolution;  // Equihash solution.

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        bool new_format = !(s.GetVersion() & SERIALIZE_BLOCK_LEGACY);
        if(new_format)
        {
           READWRITE(nAlgo); 
        }
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        if (new_format && nAlgo == ALGO_EQUIHASH) {
            READWRITE(hashReserved);
        }
        READWRITE(nTime);
        READWRITE(nBits);
        if (new_format && nAlgo == ALGO_EQUIHASH)
        {
            READWRITE(nBigNonce);
            READWRITE(nSolution);
        }
        if(!new_format || nAlgo != ALGO_EQUIHASH)
        {
            READWRITE(nNonce);
        }
    }

    void SetNull()
    {
        nAlgo = 0;
        nVersion.SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashReserved.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nBigNonce.SetNull();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // Set Algo to use
    inline void SetAlgo(uint8_t algo)
    {
        nAlgo = algo;
    }
	
    uint8_t GetAlgo() const;

    uint256 GetHash() const;
	uint256 GetHash(const Consensus::Params& params) const;
	
    uint256 GetPoWHash() const;
    
    CDefaultBlockHeader GetDefaultBlockHeader() const;    
    CEquihashBlockHeader GetEquihashBlockHeader() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
