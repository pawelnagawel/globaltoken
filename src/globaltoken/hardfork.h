// Copyright (c) 2018-2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_HARDFORK_PARAMS_H
#define GLOBALTOKEN_HARDFORK_PARAMS_H

#include <arith_uint256.h>

class CHardforkProperties
{
private:
    
    // the hardfork ID
    int nID;
    
    // the unix timestamp, when the hardfork begins
    uint32_t nActivationTime;
    
    // the height, when this hardfork has been activated
    int nHeight;
    
    // the Hash of nHeight (blockhash)
    uint256 Blockhash;
    
public:

    CHardforkProperties()
    {
        SetNull();
    }
    
    void SetNull()
    {
        nID = 0;
        nActivationTime = 0;
        nHeight = 0;
        Blockhash.SetNull();
    }
    
    bool IsNull()
    {
        return (nID == 0);
    }
    
    void Initialize(int nInitializeID, uint32_t nInitializeActivationTime, int nInitializeHeight, uint256 InitializeBlockHash)
    {
        nID = nInitializeID;
        nActivationTime = nInitializeActivationTime;
        nHeight = nInitializeHeight;
        Blockhash = InitializeBlockHash;
    }
    
    int GetHardforkID()
    {
        return nID;
    }
    
    uint32_t GetActivationTime()
    {
        return nActivationTime;
    }
    
    int GetActivationHeight()
    {
        return nHeight;
    }
    
    uint256 GetActivationBlockHash()
    {
        return InitializeBlockHash;
    }
    
    bool IsActivated(uint32_t nTimeCheck);
}

enum {
    DIVIDEDPAYMENTS_BLOCK_WARNING,
    DIVIDEDPAYMENTS_GENERATE_WARNING,
    DIVIDEDPAYMENTS_BLOCKTEMPLATE_WARNING,
    DIVIDEDPAYMENTS_AUXPOW_WARNING
};

std::string GetCoinbaseFeeString(int type);

#endif // GLOBALTOKEN_HARDFORK_PARAMS_H
