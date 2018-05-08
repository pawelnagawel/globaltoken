// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <arith_uint256.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

namespace Consensus {
    struct Params;
};

class CDefaultBlockHeader;
class CEquihashBlockHeader;

static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;

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

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
	static const size_t HEADER_SIZE = 4+32+32+32+4+4+1+32;  // Excluding Equihash solution
    // header
    uint8_t nAlgo;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nReserved[7];
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nBigNonce;
    std::vector<unsigned char> nSolution;  // Equihash solution.

    CBlockHeader()
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
            for(size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
                READWRITE(nReserved[i]);
            }
        }
        READWRITE(nTime);
        READWRITE(nBits);
        if (new_format && nAlgo != ALGO_EQUIHASH)
        {
            READWRITE(nNonce);
        }
        if (new_format && nAlgo == ALGO_EQUIHASH)
        {
            READWRITE(nAlgo);
            READWRITE(nBigNonce);
            READWRITE(nSolution);
        }
        if(!new_format)
        {
            READWRITE(nNonce);
        }
    }

    void SetNull()
    {
        nAlgo = 0;
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        memset(nReserved, 0, sizeof(nReserved));
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

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
    
    CDefaultBlockHeader GetDefaultBlockHeader() const;    
    CEquihashBlockHeader GetEquihashBlockHeader() const;
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CBlockHeader*>(this));
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nAlgo          = nAlgo;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        memcpy(block.nReserved, nReserved, sizeof(block.nReserved));
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nBigNonce      = nBigNonce;
        block.nSolution      = nSolution;
        return block;
    }

    std::string ToString() const;
};

/**
 * Custom serializer for CBlockHeader that omits the bignonce and solution, for use
 * as input to Equihash.
 */
class CEquihashInput : private CBlockHeader
{
public:
    CEquihashInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAlgo);
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        for(size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
            READWRITE(nReserved[i]);
        }
        READWRITE(nTime);
        READWRITE(nBits);
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
