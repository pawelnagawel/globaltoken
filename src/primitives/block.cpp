// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <globaltoken/hardfork.h>
#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>
#include <crypto/algos/hashlib/multihash.h>
#include <crypto/algos/neoscrypt/neoscrypt.h>
#include <crypto/algos/scrypt/scrypt.h>
#include <crypto/algos/yescrypt/yescrypt.h>

uint256 CBlockHeader::GetHash() const
{
    int version;
    if (IsHardForkActivated(nHeight)) {
        version = PROTOCOL_VERSION;
    } else {
        version = PROTOCOL_VERSION | SERIALIZE_BLOCK_LEGACY;
    }
    CHashWriter writer(SER_GETHASH, version);
    ::Serialize(writer, *this);
    return writer.GetHash();
}

int CBlockHeader::GetAlgo() const
{
    return nAlgo;
}

uint256 CBlockHeader::GetPoWHash(int algo) const
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
			uint32_t default_nonce = (uint32_t)nNonce.GetUint64(0);
            return HashX11(BEGIN(nVersion), END(default_nonce));
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
        case ALGO_HMQ1725
		{
			uint32_t default_nonce = (uint32_t)nNonce.GetUint64(0);
            return HMQ1725(BEGIN(nVersion), END(default_nonce));
		}
    }
    return GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, powalgo=%u, powalgoname=%s, powhash=%s, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
		GetAlgo(),
		GetAlgoName(GetAlgo()),
		GetPoWHash(GetAlgo()).ToString(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

std::string GetAlgoName(int Algo)
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
    }
    return std::string("unknown");       
}
