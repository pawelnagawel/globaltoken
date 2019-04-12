// Copyright (c) 2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_POW_ALGORITHM_H
#define GLOBALTOKEN_POW_ALGORITHM_H

#include <arith_uint256.h>
#include <uint256.h>

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
