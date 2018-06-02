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
    if(IsLegacyVersion(nVersion))
        return ALGO_SHA256D;
    
    switch (nVersion & BLOCK_VERSION_ALGO)
    {
        case BLOCK_VERSION_SHA256D:
            return ALGO_SHA256D;
        case BLOCK_VERSION_SCRYPT:
            return ALGO_SCRYPT;
        case BLOCK_VERSION_X11:
            return ALGO_X11;
        case BLOCK_VERSION_NEOSCRYPT:
            return ALGO_NEOSCRYPT;
        case BLOCK_VERSION_EQUIHASH:
            return ALGO_EQUIHASH;
        case BLOCK_VERSION_YESCRYPT:
            return ALGO_YESCRYPT;
        case BLOCK_VERSION_HMQ1725:
            return ALGO_HMQ1725;
        case BLOCK_VERSION_XEVAN:
            return ALGO_XEVAN;
        case BLOCK_VERSION_NIST5:
            return ALGO_NIST5;
    }
    return ALGO_SHA256D;
}