// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018 The GlobalToken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/mining_block.h>
#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/algos/hashlib/multihash.h>
#include <crypto/algos/neoscrypt/neoscrypt.h>
#include <crypto/algos/scrypt/scrypt.h>
#include <crypto/algos/yescrypt/yescrypt.h>

uint256 CDefaultBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CEquihashBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CDefaultBlockHeader::GetPoWHash(uint8_t algo) const
{
    switch (algo)
    {
        case ALGO_SHA256D:
            return GetHash();
        case ALGO_SCRYPT:
        {
            uint256 thash;
            scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_X11:
        {
            return HashX11(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_NEOSCRYPT:
        {
            unsigned int profile = 0x0;
            uint256 thash;
            neoscrypt((unsigned char *) &nVersion, (unsigned char *) &thash, profile);				
            return thash;
        }
        case ALGO_EQUIHASH:
            return GetHash();
        case ALGO_YESCRYPT:
        {
            uint256 thash;
            yescrypt_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_HMQ1725:
        {
            return HMQ1725(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_XEVAN:
        {
            return XEVAN(BEGIN(nVersion), END(nNonce));	    
        }
        case ALGO_NIST5:
        {
            return NIST5(BEGIN(nVersion), END(nNonce));	    
        }
    }
    return GetHash();
}

CBlock CDefaultBlock::GetBlock() const
{
    CBlock block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    block.vtx            = vtx;
    block.fChecked       = fChecked;
    return block;
}

CBlock CEquihashBlock::GetBlock() const
{
    CBlock block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    memcpy(block.nReserved, nReserved, sizeof(block.nReserved));
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nBigNonce      = nNonce;
    block.nSolution      = nSolution;
    block.vtx            = vtx;
    block.fChecked       = fChecked;
    return block;
}

std::string CDefaultBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CDefaultBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

std::string CEquihashBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CEquihashBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}