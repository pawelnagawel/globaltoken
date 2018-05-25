// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <primitives/mining_block.h>
#include <primitives/block_dependencies.h>

#include <serialize.h>
#include <uint256.h>

namespace Consensus {
    struct Params;
};

static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;

/**
 * A block header without auxpow information.  This "intermediate step"
 * in constructing the full header is useful, because it breaks the cyclic
 * dependency between auxpow (referencing a parent block header) and
 * the block header (referencing an auxpow).  The parent block header
 * does not have auxpow itself, so it is a pure header.
 */
class CPureBlockHeader : public CPureBlockVersion
{
public:
    // header
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
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        if (GetAlgo() == ALGO_EQUIHASH) {
            READWRITE(hashReserved);
        }
        READWRITE(nTime);
        READWRITE(nBits);
        if (GetAlgo() == ALGO_EQUIHASH)
        {
            READWRITE(nBigNonce);
            READWRITE(nSolution);
        }
        if(GetAlgo() != ALGO_EQUIHASH)
        {
            READWRITE(nNonce);
        }
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
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

    uint256 GetHash() const;

    uint256 GetPoWHash() const;
    uint256 GetPoWHash(uint8_t nAlgo) const;
    
    // Set Algo to use
    inline void SetAlgo(uint8_t algo)
    {
        nVersion += algo;
    }
	
    uint8_t GetAlgo() const;
    
    CDefaultBlockHeader GetDefaultBlockHeader() const;    
    CEquihashBlockHeader GetEquihashBlockHeader() const;
    
    CDefaultBlock GetDefaultBlock() const;    
    CEquihashBlock GetEquihashBlock() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
