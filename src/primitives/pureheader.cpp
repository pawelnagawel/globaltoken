// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>
#include <utilstrencodings.h>
#ifndef NO_GLOBALTOKEN_HARDFORK
#include <globaltoken/hardfork.h>
#else
#define IsHardForkActivated(nTime) (((nTime) >= (1533081600)) ? true : false)
#endif

#ifndef NO_GLOBALTOKEN_HARDFORK
uint256 CPureBlockHeader::GetHash(const Consensus::Params& params) const
{
    int version;
    if (IsHardForkActivated(nTime, params)) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

uint256 CPureBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}
#else
uint256 CPureBlockHeader::GetHash() const
{
    int version;
    if (IsHardForkActivated(nTime)) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
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

uint8_t CPureBlockHeader::GetAlgo() const
{
	if (IsHardForkActivated(nTime)) 
	{
		return nAlgo;
	}
	return ALGO_SHA256D;
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
