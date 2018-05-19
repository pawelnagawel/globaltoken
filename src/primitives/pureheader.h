// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <serialize.h>
#include <uint256.h>
#include <version.h>

namespace Consensus {
    struct Params;
};

static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;
static const int SERIALIZE_AUX_EQUIHASH = 0x09000000;

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
 * A block header excluding nAlgo, for raw auxpow blocks.
 */
class CPureAuxHeader
{
private:

    /* Modifiers to the version.  */
    static const int32_t VERSION_AUXPOW = (1 << 8);

    /** Bits above are reserved for the auxpow chain ID.  */
    static const int32_t VERSION_CHAIN_START = (1 << 16);

public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nBigNonce;
    std::vector<unsigned char> nSolution; // Equihash solution.

    CPureAuxHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        bool equihash_format = s.GetVersion() & SERIALIZE_AUX_EQUIHASH;
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        if (equihash_format) {
            READWRITE(hashReserved);
        }
        READWRITE(nTime);
        READWRITE(nBits);
        if (equihash_format)
        {
            READWRITE(nBigNonce);
            READWRITE(nSolution);
        }
        if(!equihash_format)
        {
            READWRITE(nNonce);
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
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

    uint256 GetHash(bool equihash) const;
	
    uint256 GetPoWHash(uint8_t nAlgo) const;
    
    CDefaultBlockHeader GetDefaultBlockHeader() const;    
    CEquihashBlockHeader GetEquihashBlockHeader() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    /* Below are methods to interpret the version with respect to
       auxpow data and chain ID.  This used to be in the CBlockVersion
       class, but was moved here when we switched back to nVersion being
       a pure int member as preparation to undoing the "abuse" and
       allowing BIP9 to work.  */

    /**
     * Extract the base version (without modifiers and chain ID).
     * @return The base version./
     */
    inline int32_t GetBaseVersion() const
    {
        return GetBaseVersion(nVersion);
    }
    static inline int32_t GetBaseVersion(int32_t ver)
    {
        //return ver % VERSION_AUXPOW;
        return (ver & 0x000000ff);
    }

    /**
     * Set the base version (apart from chain ID and auxpow flag) to
     * the one given.  This should only be called when auxpow is not yet
     * set, to initialise a block!
     * @param nBaseVersion The base version.
     * @param nChainId The auxpow chain ID.
     */
    void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId);

    /**
     * Extract the chain ID.
     * @return The chain ID encoded in the version.
     */
    inline int32_t GetChainId() const
    {
        return nVersion / VERSION_CHAIN_START;
    }

    /**
     * Set the chain ID.  This is used for the test suite.
     * @param ch The chain ID to set.
     */
    inline void SetChainId(int32_t chainId)
    {
        nVersion %= VERSION_CHAIN_START;
        nVersion |= chainId * VERSION_CHAIN_START;
    }

    /**
     * Check if the auxpow flag is set in the version.
     * @return True iff this block version is marked as auxpow.
     */
    inline bool IsAuxpow() const
    {
        return nVersion & VERSION_AUXPOW;
    }

    /**
     * Set the auxpow flag.  This is used for testing.
     * @param auxpow Whether to mark auxpow as true.
     */
    inline void SetAuxpowVersion (bool auxpow)
    {
        if (auxpow)
            nVersion |= VERSION_AUXPOW;
        else
            nVersion &= ~VERSION_AUXPOW;
    }

    /**
     * Check whether this is a "legacy" block without chain ID.
     * @return True iff it is.
     */
    inline bool IsLegacy() const
    {
        return (nVersion == 1 || nVersion == 2 || nVersion == 0x20000000);
    }
};

/**
 * A block header without auxpow information.  This "intermediate step"
 * in constructing the full header is useful, because it breaks the cyclic
 * dependency between auxpow (referencing a parent block header) and
 * the block header (referencing an auxpow).  The parent block header
 * does not have auxpow itself, so it is a pure header.
 */
class CPureBlockHeader : public CPureAuxHeader
{
public:
    // header
    uint8_t nAlgo;

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int baseversion = s.GetVersion();
        bool new_format = !(baseversion & SERIALIZE_BLOCK_LEGACY);
        if(new_format)
        {
           READWRITE(nAlgo); 
        }
        if(new_format && nAlgo == ALGO_EQUIHASH)
            s.SetVersion(PROTOCOL_VERSION | SERIALIZE_AUX_EQUIHASH);
        else
            s.SetVersion(PROTOCOL_VERSION | 0);
        READWRITE(*(CPureAuxHeader*)this);
    }

    void SetNull()
    {
        nAlgo = 0;
        CPureBlockHeader::SetNull();
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
    
    CPureAuxHeader GetPureAuxHeader() const
    {
        CPureAuxHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashReserved   = hashReserved;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nBigNonce      = nBigNonce;
        block.nSolution      = nSolution;
        return block;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
