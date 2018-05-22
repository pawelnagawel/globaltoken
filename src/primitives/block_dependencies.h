// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_BLOCK_DEPENDENCIES_H
#define GLOBALTOKEN_BLOCK_DEPENDENCIES_H

#include <serialize.h>
#include <uint256.h>

#include <globaltoken/hardfork.h>

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
 * Pure Version that will inherit to all other Block classes
 * Includes nVersion and AuxPow stuff.
 */
class CPureBlockVersion
{
private:

    /* Modifiers to the version.  */
    static const int32_t VERSION_AUXPOW = (1 << 8);

    /** Bits above are reserved for the auxpow chain ID.  */
    static const int32_t VERSION_CHAIN_START = (1 << 16);
    
public:
    // header
    int32_t nVersion;

    CPureBlockVersion()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
    }

    void SetNull()
    {
        nVersion = 0;
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
    inline int32_t GetBaseVersion(int32_t nChainId) const
    {
        return GetBaseVersion(nVersion, nChainId);
    }
    
    static inline int32_t GetBaseVersion(int32_t ver, int32_t nChainId)
    {
        //return ver % VERSION_AUXPOW;
        return ver ^ (nChainId * VERSION_CHAIN_START);
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
};

#endif // GLOBALTOKEN_BLOCK_DEPENDENCIES_H
