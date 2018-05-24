// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#ifndef NO_GLOBALTOKEN_HARDFORK
#include <globaltoken/hardfork.h>
#else
#define IsHardForkActivated(nTime) (((nTime) >= (1533081600)) ? true : false)
#endif

#ifndef NO_GLOBALTOKEN_HARDFORK
uint256 CPureBlockHeader::GetHash(const Consensus::Params& params) const
{
    /*int version;
    if (IsHardForkActivated(nTime, params)) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();*/
    return SerializeHash(*this);
}

uint256 CPureBlockHeader::GetHash() const
{
    /*const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);*/
    return SerializeHash(*this);
}
#else
uint256 CPureBlockHeader::GetHash() const
{
    /*int version;
    if (IsHardForkActivated(nTime)) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();*/
    return SerializeHash(*this);
}
#endif

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
    if(IsHardForkActivated(nTime))
    {
        if(nVersion % 100 == 0 || nVersion % 100 == 20 || nVersion % 100 == 40 || nVersion % 100 == 60 || nVersion % 100 == 80)
        {
            return ALGO_SHA256D;
        }
        if(nVersion % 100 == 1 || nVersion % 100 == 21 || nVersion % 100 == 41 || nVersion % 100 == 61 || nVersion % 100 == 81)
        {
            return ALGO_SCRYPT;
        }
        if(nVersion % 100 == 2 || nVersion % 100 == 22 || nVersion % 100 == 42 || nVersion % 100 == 62 || nVersion % 100 == 82)
        {
            return ALGO_X11;
        }
        if(nVersion % 100 == 3 || nVersion % 100 == 23 || nVersion % 100 == 43 || nVersion % 100 == 63 || nVersion % 100 == 83)
        {
            return ALGO_NEOSCRYPT;
        }
        if(nVersion % 100 == 4 || nVersion % 100 == 24 || nVersion % 100 == 44 || nVersion % 100 == 64 || nVersion % 100 == 84)
        {
            return ALGO_EQUIHASH;
        }
        if(nVersion % 100 == 5 || nVersion % 100 == 25 || nVersion % 100 == 45 || nVersion % 100 == 65 || nVersion % 100 == 85)
        {
            return ALGO_YESCRYPT;
        }
        if(nVersion % 100 == 6 || nVersion % 100 == 26 || nVersion % 100 == 46 || nVersion % 100 == 66 || nVersion % 100 == 86)
        {
            return ALGO_HMQ1725;
        }
        if(nVersion % 100 == 7 || nVersion % 100 == 27 || nVersion % 100 == 47 || nVersion % 100 == 67 || nVersion % 100 == 87)
        {
            return ALGO_XEVAN;
        }
        if(nVersion % 100 == 8 || nVersion % 100 == 28 || nVersion % 100 == 48 || nVersion % 100 == 68 || nVersion % 100 == 88)
        {
            return ALGO_NIST5;
        }
        if(nVersion % 100 == 9 || nVersion % 100 == 29 || nVersion % 100 == 49 || nVersion % 100 == 69 || nVersion % 100 == 89)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 10 || nVersion % 100 == 30 || nVersion % 100 == 50 || nVersion % 100 == 70 || nVersion % 100 == 90)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 11 || nVersion % 100 == 31 || nVersion % 100 == 51 || nVersion % 100 == 71 || nVersion % 100 == 91)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 12 || nVersion % 100 == 32 || nVersion % 100 == 52 || nVersion % 100 == 72 || nVersion % 100 == 92)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 13 || nVersion % 100 == 33 || nVersion % 100 == 53 || nVersion % 100 == 73 || nVersion % 100 == 93)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 14 || nVersion % 100 == 34 || nVersion % 100 == 54 || nVersion % 100 == 74 || nVersion % 100 == 94)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 15 || nVersion % 100 == 35 || nVersion % 100 == 55 || nVersion % 100 == 75 || nVersion % 100 == 95)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 16 || nVersion % 100 == 36 || nVersion % 100 == 56 || nVersion % 100 == 76 || nVersion % 100 == 96)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 17 || nVersion % 100 == 37 || nVersion % 100 == 57 || nVersion % 100 == 77 || nVersion % 100 == 97)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 18 || nVersion % 100 == 38 || nVersion % 100 == 58 || nVersion % 100 == 78 || nVersion % 100 == 98)
        {
            return ALGO_SHA256D; // needs to be changed
        }
        if(nVersion % 100 == 19 || nVersion % 100 == 39 || nVersion % 100 == 59 || nVersion % 100 == 79 || nVersion % 100 == 99)
        {
            return ALGO_SHA256D; // needs to be changed
        }
    }
    return ALGO_SHA256D;
}