// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>
#include <utilstrencodings.h>
#include <chainparams.h>

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

CEquihashBlockHeader CPureBlockHeader::GetEquihashBlockHeader() const
{
    CEquihashBlockHeader block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.hashReserved   = hashReserved;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nBigNonce;
    block.nSolution      = nSolution;
    return block;
}

CDefaultBlockHeader CPureBlockHeader::GetDefaultBlockHeader() const
{
    CDefaultBlockHeader block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    return block;
}

uint256 CPureBlockHeader::GetPoWHash() const
{
    return GetPoWHash(GetAlgo());
}

uint256 CPureBlockHeader::GetPoWHash(uint8_t nAlgo) const
{
    if(nAlgo == ALGO_EQUIHASH)
    {
        CEquihashBlockHeader block;
        block = CPureBlockHeader::GetEquihashBlockHeader();
        return block.GetHash();
    }
    CDefaultBlockHeader block;
    block = CPureBlockHeader::GetDefaultBlockHeader();
    return block.GetPoWHash(nAlgo);
}

uint8_t CPureBlockHeader::GetAlgo() const
{
    int32_t blockversion = nVersion;
    if(IsAuxpow())
    {
        blockversion = GetAuxpowVersion();
    }
    
    if(blockversion == 1 || blockversion == 2 || blockversion == 536870912 || blockversion == 536870913 || blockversion % 100 == 0 || blockversion % 100 == 20 || blockversion % 100 == 40 || blockversion % 100 == 60 || blockversion % 100 == 80)
    {
        return ALGO_SHA256D;
    }
    if(blockversion % 100 == 1 || blockversion % 100 == 21 || blockversion % 100 == 41 || blockversion % 100 == 61 || blockversion % 100 == 81)
    {
        return ALGO_SCRYPT;
    }
    if(blockversion % 100 == 2 || blockversion % 100 == 22 || blockversion % 100 == 42 || blockversion % 100 == 62 || blockversion % 100 == 82)
    {
        return ALGO_X11;
    }
    if(blockversion % 100 == 3 || blockversion % 100 == 23 || blockversion % 100 == 43 || blockversion % 100 == 63 || blockversion % 100 == 83)
    {
        return ALGO_NEOSCRYPT;
    }
    if(blockversion % 100 == 4 || blockversion % 100 == 24 || blockversion % 100 == 44 || blockversion % 100 == 64 || blockversion % 100 == 84)
    {
        return ALGO_EQUIHASH;
    }
    if(blockversion % 100 == 5 || blockversion % 100 == 25 || blockversion % 100 == 45 || blockversion % 100 == 65 || blockversion % 100 == 85)
    {
        return ALGO_YESCRYPT;
    }
    if(blockversion % 100 == 6 || blockversion % 100 == 26 || blockversion % 100 == 46 || blockversion % 100 == 66 || blockversion % 100 == 86)
    {
        return ALGO_HMQ1725;
    }
    if(blockversion % 100 == 7 || blockversion % 100 == 27 || blockversion % 100 == 47 || blockversion % 100 == 67 || blockversion % 100 == 87)
    {
        return ALGO_XEVAN;
    }
    if(blockversion % 100 == 8 || blockversion % 100 == 28 || blockversion % 100 == 48 || blockversion % 100 == 68 || blockversion % 100 == 88)
    {
        return ALGO_NIST5;
    }
    if(blockversion % 100 == 9 || blockversion % 100 == 29 || blockversion % 100 == 49 || blockversion % 100 == 69 || blockversion % 100 == 89)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 10 || blockversion % 100 == 30 || blockversion % 100 == 50 || blockversion % 100 == 70 || blockversion % 100 == 90)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 11 || blockversion % 100 == 31 || blockversion % 100 == 51 || blockversion % 100 == 71 || blockversion % 100 == 91)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 12 || blockversion % 100 == 32 || blockversion % 100 == 52 || blockversion % 100 == 72 || blockversion % 100 == 92)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 13 || blockversion % 100 == 33 || blockversion % 100 == 53 || blockversion % 100 == 73 || blockversion % 100 == 93)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 14 || blockversion % 100 == 34 || blockversion % 100 == 54 || blockversion % 100 == 74 || blockversion % 100 == 94)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 15 || blockversion % 100 == 35 || blockversion % 100 == 55 || blockversion % 100 == 75 || blockversion % 100 == 95)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 16 || blockversion % 100 == 36 || blockversion % 100 == 56 || blockversion % 100 == 76 || blockversion % 100 == 96)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 17 || blockversion % 100 == 37 || blockversion % 100 == 57 || blockversion % 100 == 77 || blockversion % 100 == 97)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 18 || blockversion % 100 == 38 || blockversion % 100 == 58 || blockversion % 100 == 78 || blockversion % 100 == 98)
    {
        return ALGO_SHA256D; // needs to be changed
    }
    if(blockversion % 100 == 19 || blockversion % 100 == 39 || blockversion % 100 == 59 || blockversion % 100 == 79 || blockversion % 100 == 99)
    {
        return ALGO_SHA256D; // needs to be changed
    }
}