// Copyright (c) 2019 The Globaltoken Core developers
// Copyright (c) 2014-2019 The DigiByte Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_POW_ALGORITHM_H
#define GLOBALTOKEN_POW_ALGORITHM_H

#include <arith_uint256.h>
#include <uint256.h>


/** Algos */
enum : uint8_t { 
    ALGO_SHA256D      = 0,
    ALGO_SCRYPT       = 1,
    ALGO_X11          = 2,
    ALGO_NEOSCRYPT    = 3,
    ALGO_EQUIHASH     = 4,
    ALGO_YESCRYPT     = 5,
    ALGO_HMQ1725      = 6,
    ALGO_XEVAN        = 7,
    ALGO_NIST5        = 8,
    ALGO_TIMETRAVEL10 = 9,
    ALGO_PAWELHASH    = 10,
    ALGO_X13          = 11,
    ALGO_X14          = 12,
    ALGO_X15          = 13,
    ALGO_X17          = 14,
    ALGO_LYRA2RE      = 15,
    ALGO_BLAKE2S      = 16,
    ALGO_BLAKE2B      = 17,
    ALGO_ASTRALHASH   = 18,
    ALGO_PADIHASH     = 19,
    ALGO_JEONGHASH    = 20,
    ALGO_KECCAK       = 21,
    ALGO_ZHASH        = 22,
    ALGO_GLOBALHASH   = 23,
    ALGO_SKEIN        = 24,
    ALGO_GROESTL      = 25,
    ALGO_QUBIT        = 26,
    ALGO_SKUNKHASH    = 27,
    ALGO_QUARK        = 28,
    ALGO_X16R         = 29,
    NUM_ALGOS_IMPL };

enum {
    BLOCK_VERSION_ALGO              = 0x3E00,
    BLOCK_VERSION_SHA256D           = (1 << 9),
    BLOCK_VERSION_SCRYPT            = (2 << 9),
    BLOCK_VERSION_X11               = (3 << 9),
    BLOCK_VERSION_NEOSCRYPT         = (4 << 9),
    BLOCK_VERSION_EQUIHASH          = (5 << 9),
    BLOCK_VERSION_YESCRYPT          = (6 << 9),
    BLOCK_VERSION_HMQ1725           = (7 << 9),
    BLOCK_VERSION_XEVAN             = (8 << 9),
    BLOCK_VERSION_NIST5             = (9 << 9),
    BLOCK_VERSION_TIMETRAVEL10      = (10 << 9),
    BLOCK_VERSION_PAWELHASH         = (11 << 9),
    BLOCK_VERSION_X13               = (12 << 9),
    BLOCK_VERSION_X14               = (13 << 9),
    BLOCK_VERSION_X15               = (14 << 9),
    BLOCK_VERSION_X17               = (15 << 9),
    BLOCK_VERSION_LYRA2RE           = (16 << 9),
    BLOCK_VERSION_BLAKE2S           = (17 << 9),
    BLOCK_VERSION_BLAKE2B           = (18 << 9),
    BLOCK_VERSION_ASTRALHASH        = (19 << 9),
    BLOCK_VERSION_PADIHASH          = (20 << 9),
    BLOCK_VERSION_JEONGHASH         = (21 << 9),
    BLOCK_VERSION_KECCAK            = (22 << 9),
    BLOCK_VERSION_ZHASH             = (23 << 9),
    BLOCK_VERSION_GLOBALHASH        = (24 << 9),
    BLOCK_VERSION_SKEIN             = (25 << 9),
    BLOCK_VERSION_GROESTL           = (26 << 9),
    BLOCK_VERSION_QUBIT             = (27 << 9),
    BLOCK_VERSION_SKUNKHASH         = (28 << 9),
    BLOCK_VERSION_QUARK             = (29 << 9),
    BLOCK_VERSION_X16R              = (30 << 9),
};
    
const int NUM_ALGOS = 30;

std::string GetAlgoName(uint8_t Algo);
uint8_t GetAlgoByName(std::string strAlgo, uint8_t fallback, bool &fAlgoFound);
std::string GetAlgoRangeString();

class CPOWAlgoProperties
{
private:
    
    // the algo ID
    uint8_t nAlgoID;
    
    // the powLimit hash
    uint256 powLimit;
    
    // the diff multiplier
    int nMultiplier;
    
public:

    CPOWAlgoProperties()
    {
        SetNull();
    }
    
    CPOWAlgoProperties(uint8_t nAlgo, uint256 proofOfWorkLimit, int diffMultiplier)
    {
        Initialize(nAlgo, proofOfWorkLimit, diffMultiplier);
    }
    
    void SetNull()
    {
        nAlgoID = 0;
        powLimit.SetNull();
        nMultiplier = 0;
    }
    
    bool IsNull() const
    {
        return (nMultiplier == 0);
    }
    
    void Initialize(uint8_t nAlgo, uint256 proofOfWorkLimit, int diffMultiplier)
    {
        nAlgoID = nAlgo;
        powLimit = proofOfWorkLimit;
        nMultiplier = diffMultiplier;
    }
    
    uint8_t GetAlgoID() const
    {
        return nAlgoID;
    }
    
    uint256 GetPowLimit() const
    {
        return powLimit;
    }
    
    arith_uint256 GetArithPowLimit() const
    {
        return UintToArith256(powLimit);
    }
    
    int GetMultiplier() const
    {
        return nMultiplier;
    }
};

#endif // GLOBALTOKEN_POW_ALGORITHM_H
