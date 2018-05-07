// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#ifndef NO_GLOBALTOKEN_HARDFORK
#include <globaltoken/hardfork.h>
#else
#define IsHardForkActivated(nTime) (((nTime) >= (1527811200)) ? true : false)
#endif
#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/algos/hashlib/multihash.h>
#include <crypto/algos/neoscrypt/neoscrypt.h>
#include <crypto/algos/scrypt/scrypt.h>
#include <crypto/algos/yescrypt/yescrypt.h>

#ifndef NO_GLOBALTOKEN_HARDFORK
uint256 CBlockHeader::GetHash(const Consensus::Params& params) const
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

uint256 CBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}
#else
uint256 CBlockHeader::GetHash() const
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
#ifndef NO_GLOBALTOKEN_HARDFORK
uint256 CDefaultBlockHeader::GetHash(const Consensus::Params& params) const
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

uint256 CDefaultBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}
#else
uint256 CDefaultBlockHeader::GetHash() const
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
#ifndef NO_GLOBALTOKEN_HARDFORK
uint256 CEquihashBlockHeader::GetHash(const Consensus::Params& params) const
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

uint256 CEquihashBlockHeader::GetHash() const
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    return GetHash(consensusParams);
}
#else
uint256 CEquihashBlockHeader::GetHash() const
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
uint8_t CBlockHeader::GetAlgo() const
{
	if (IsHardForkActivated(nTime)) 
	{
		return nAlgo;
	}
	return ALGO_SHA256D;
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint8_t algo = GetAlgo();
    if(algo == ALGO_EQUIHASH)
    {
        CEquihashBlockHeader block;
        block = CBlockHeader::GetEquihashBlockHeader();
        return block.GetHash();
    }
    else
    {
        CDefaultBlockHeader block;
        block = CBlockHeader::GetDefaultBlockHeader();
        return block.GetPoWHash(algo);
    }
    return CBlockHeader::GetHash();
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

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, powalgo=%u, powalgoname=%s, powhash=%s, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nBigNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        GetAlgo(),
        GetAlgoName(GetAlgo()),
        GetPoWHash().ToString(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nBigNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

std::string GetAlgoName(uint8_t Algo)
{
    switch (Algo)
    {
        case ALGO_SHA256D:
            return std::string("sha256d");
        case ALGO_SCRYPT:
            return std::string("scrypt");
        case ALGO_X11:
            return std::string("x11");
        case ALGO_NEOSCRYPT:
            return std::string("neoscrypt");
        case ALGO_YESCRYPT:
            return std::string("yescrypt");
        case ALGO_EQUIHASH:
            return std::string("equihash");
        case ALGO_HMQ1725:
            return std::string("hmq1725");
        case ALGO_XEVAN:
            return std::string("xevan");
        case ALGO_NIST5:
            return std::string("nist5");
    }
    return std::string("unknown");       
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