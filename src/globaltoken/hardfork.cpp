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

bool IsAlgoBasicVersionAcceptable(int32_t nVersion)
{
    return (nVersion % 100 == 0 || nVersion % 100 == 20 || nVersion % 100 == 40 || nVersion % 100 == 60 || nVersion % 100 == 80);
}

int32_t GetNextBestBlockVersion (int32_t nVersion)
{
    for(;;)
    {
        if(IsAlgoBasicVersionAcceptable(nVersion))
            break;
        nVersion++;
    }
    return nVersion;
}

int64_t GetPoWTargetTimeSpan(uint32_t blocktime, const Consensus::Params& consensusParams)
{
	if(IsHardForkActivated(blocktime))
	{
		return consensusParams.nPowTargetTimespanV2;
	}
	else
	{
		return consensusParams.nPowTargetTimespan;
	}
}

int64_t GetPoWTargetTimeSpan(uint32_t blocktime)
{
	const Consensus::Params& consensusParams = Params().GetConsensus();
	return GetPoWTargetTimeSpan(blocktime, consensusParams);
}

int64_t GetPoWTargetSpacing(uint32_t blocktime, const Consensus::Params& consensusParams)
{
	if(IsHardForkActivated(blocktime))
	{
		return consensusParams.nPowTargetSpacingV2;
	}
	else
	{
		return consensusParams.nPowTargetSpacing;
	}
}

int64_t GetPoWTargetSpacing(uint32_t blocktime)
{
	const Consensus::Params& consensusParams = Params().GetConsensus();
	return GetPoWTargetSpacing(blocktime, consensusParams);
}
