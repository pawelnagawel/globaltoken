// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/hardfork.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <primitives/block.h>

arith_uint256 GetAlgoPowLimit(uint8_t algo, const Consensus::Params& consensusParams)
{
	if (algo == ALGO_SHA256D)
		return UintToArith256(consensusParams.powLimit_SHA256);
	else if (algo == ALGO_SCRYPT)
		return UintToArith256(consensusParams.powLimit_SCRYPT);
	else if (algo == ALGO_X11)
		return UintToArith256(consensusParams.powLimit_X11);
	else if (algo == ALGO_NEOSCRYPT)
		return UintToArith256(consensusParams.powLimit_NEOSCRYPT);
	else if (algo == ALGO_EQUIHASH)
		return UintToArith256(consensusParams.powLimit_EQUIHASH);
	else if (algo == ALGO_YESCRYPT)
		return UintToArith256(consensusParams.powLimit_YESCRYPT);
	else if (algo == ALGO_HMQ1725)
		return UintToArith256(consensusParams.powLimit_HMQ1725);
	else if (algo == ALGO_XEVAN)
		return UintToArith256(consensusParams.powLimit_XEVAN);
	else if (algo == ALGO_NIST5)
		return UintToArith256(consensusParams.powLimit_NIST5);
    else if (algo == ALGO_TIMETRAVEL10)
		return UintToArith256(consensusParams.powLimit_TIMETRAVEL10);
    else if (algo == ALGO_PAWELHASH)
		return UintToArith256(consensusParams.powLimit_PAWELHASH);
    else if (algo == ALGO_X13)
		return UintToArith256(consensusParams.powLimit_X13);
    else if (algo == ALGO_X14)
		return UintToArith256(consensusParams.powLimit_X14);
    else if (algo == ALGO_X15)
		return UintToArith256(consensusParams.powLimit_X15);
    else if (algo == ALGO_X17)
		return UintToArith256(consensusParams.powLimit_X17);
    else if (algo == ALGO_LYRA2RE)
        return UintToArith256(consensusParams.powLimit_LYRA2RE);
    else if (algo == ALGO_BLAKE2S)
        return UintToArith256(consensusParams.powLimit_BLAKE2S);
    else if (algo == ALGO_BLAKE2B)
        return UintToArith256(consensusParams.powLimit_BLAKE2B);
    else if (algo == ALGO_ASTRALHASH)
        return UintToArith256(consensusParams.powLimit_ASTRALHASH);
    else if (algo == ALGO_PADIHASH)
        return UintToArith256(consensusParams.powLimit_PADIHASH);
    else if (algo == ALGO_JEONGHASH)
        return UintToArith256(consensusParams.powLimit_JEONGHASH);
    else if (algo == ALGO_ZHASH)
        return UintToArith256(consensusParams.powLimit_ZHASH);
    else if (algo == ALGO_KECCAK)
        return UintToArith256(consensusParams.powLimit_KECCAK);
    else if (algo == ALGO_GLOBALHASH)
        return UintToArith256(consensusParams.powLimit_GLOBALHASH);
    else if (algo == ALGO_QUBIT)
        return UintToArith256(consensusParams.powLimit_QUBIT);
    else if (algo == ALGO_SKEIN)
        return UintToArith256(consensusParams.powLimit_SKEIN);
    else if (algo == ALGO_GROESTL)
        return UintToArith256(consensusParams.powLimit_GROESTL);
    else if (algo == ALGO_SKUNKHASH)
        return UintToArith256(consensusParams.powLimit_SKUNKHASH);
    else if (algo == ALGO_QUARK)
        return UintToArith256(consensusParams.powLimit_QUARK);
    else if (algo == ALGO_X16R)
        return UintToArith256(consensusParams.powLimit_X16R);
	else
		return UintToArith256(consensusParams.powLimit_SHA256);
}

arith_uint256 GetAlgoPowLimit(uint8_t algo)
{
	const Consensus::Params& consensusParams = Params().GetConsensus();
	return GetAlgoPowLimit(algo, consensusParams);
}

bool IsHardForkActivated(uint32_t blocktime, const Consensus::Params& consensusParams)
{
	if(blocktime >= consensusParams.HardforkTime)
	{
		return true;
	}
	return false;
}

bool IsHardForkActivated(uint32_t blocktime)
{
	const Consensus::Params& consensusParams = Params().GetConsensus();
	return IsHardForkActivated(blocktime, consensusParams);
}
