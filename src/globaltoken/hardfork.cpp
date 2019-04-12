// Copyright (c) 2018-2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/hardfork.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>

#include <sstream>
#include <string>

bool CHardforkProperties::IsActivated(uint32_t nTimeCheck) const
{
    return (nTimeCheck >= nActivationTime);
}

std::string GetCoinbaseFeeString(int type)
{
    std::stringstream strStream;
    const CChainParams &MainnetParams = CreateNetworkParams(CBaseChainParams::MAIN);
    const CChainParams &TestnetParams = CreateNetworkParams(CBaseChainParams::TESTNET);
    const CChainParams &RegtestParams = CreateNetworkParams(CBaseChainParams::REGTEST);
    if(type == DIVIDEDPAYMENTS_BLOCK_WARNING)
    {
        strStream << "Warning (Divided Coinbase): You tried to mine a block, but did not agreed to pay the coinbase fees..\nIt is required to pay the following fees from the Coinbase:\n\n"
        << "Network: " << MainnetParams.NetworkIDString() << "    | Founders-Reward: " << MainnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << MainnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - MainnetParams.GetConsensus().nMasternodePayeeReward - MainnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << TestnetParams.NetworkIDString() << "    | Founders-Reward: " << TestnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << TestnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - TestnetParams.GetConsensus().nMasternodePayeeReward - TestnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << RegtestParams.NetworkIDString() << " | Founders-Reward: " << RegtestParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << RegtestParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - RegtestParams.GetConsensus().nMasternodePayeeReward - RegtestParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "\nThe fees will be deducted automatically from your mined block, if you mine directly in your wallet.\n"
        << "\nTo agree, you must start the wallet with the -acceptdividedcoinbase argument or add acceptdividedcoinbase=1 to your globaltoken.conf file.\n";
        return strStream.str();
    }
    else if(type == DIVIDEDPAYMENTS_GENERATE_WARNING)
    {
        strStream << "You are not able to mine new coins right now.\n"
        << "\nSince the hardfork is active, you must pay Founders-Reward and Masternode-Reward\n"
        << "\nCurrently, you did not agreed to pay it, but it is needed to mine new Coins.\n"
        << "\nThe payment amount is displayed underneath, for each network:\n\n"
        << "Network: " << MainnetParams.NetworkIDString() << "    | Founders-Reward: " << MainnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << MainnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - MainnetParams.GetConsensus().nMasternodePayeeReward - MainnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << TestnetParams.NetworkIDString() << "    | Founders-Reward: " << TestnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << TestnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - TestnetParams.GetConsensus().nMasternodePayeeReward - TestnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << RegtestParams.NetworkIDString() << " | Founders-Reward: " << RegtestParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << RegtestParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - RegtestParams.GetConsensus().nMasternodePayeeReward - RegtestParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "\nDetails:\n\n"
        << "Your found blocks will automatically pay the fees, there are no additional steps for you.\n"
        << "\nAgreement:\n"
        << "You can agree to pay the fees by the following way:\n"
        << "\n- Always start the wallet with the -acceptdividedcoinbase argument\n"
        << "- Add acceptdividedcoinbase=1 to your globaltoken.conf file and restart the wallet.\n"
        << "\nIf you don't agree to pay the fees, you will not be able to mine GlobalTokens and your blocks will be rejected.\n";
        return strStream.str();
    }
    else if(type == DIVIDEDPAYMENTS_BLOCKTEMPLATE_WARNING)
    {
        strStream << "You are not able to mine new coins right now.\n"
        << "\nSince the hardfork is active, you must pay Founders-Reward and Masternode-Reward\n"
        << "\nCurrently, you did not agreed to pay it, but it is needed to mine new Coins.\n"
        << "\nThe payment amount is displayed underneath, for each network:\n\n"
        << "Network: " << MainnetParams.NetworkIDString() << "    | Founders-Reward: " << MainnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << MainnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - MainnetParams.GetConsensus().nMasternodePayeeReward - MainnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << TestnetParams.NetworkIDString() << "    | Founders-Reward: " << TestnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << TestnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - TestnetParams.GetConsensus().nMasternodePayeeReward - TestnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << RegtestParams.NetworkIDString() << " | Founders-Reward: " << RegtestParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << RegtestParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - RegtestParams.GetConsensus().nMasternodePayeeReward - RegtestParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "\nDetails:\n\n"
        << "You need to pay the founders reward, by adding the treasury details to your coinbase transaction.\n"
        << "In the RPC Result of getblocktemplate you will find a JSON-Object called 'treasury'.\n"
        << "You must add the 'address' or 'scriptPubKey' and 'amount' as a receiver of your coinbase transaction.\n"
        << "If you want, you can use the 'hex' value and add it to your coinbase, it is a ready raw transaction output of the founders reward.\n"
        << "Same thing for masternode rewards. Get the 'payee' or 'script' and 'amount' from the 'masternode' JSON-Object, and include them into your coinbase.\n"
        << "Additionally it is important to dedecude the amounts from the raw coinbase reward. (coinbasevalue - treasuryamount - masternodeamount = your block reward)\n"
        << "The amount and addresses will change every block, so always take the current output from getblocktemplate!\n"
        << "\nAgreement:\n\n"
        << "You can agree to pay the fees by the following way:\n"
        << "\n- Always start the wallet with the -acceptdividedcoinbase argument\n"
        << "- Add acceptdividedcoinbase=1 to your globaltoken.conf file and restart the wallet.\n"
        << "\nIf you don't agree to pay the treasury, you will not be able to mine GlobalTokens and your blocks will be rejected.\n";
        return strStream.str();
    }
    else if(type == DIVIDEDPAYMENTS_AUXPOW_WARNING)
    {
        strStream << "You are not able to mine new coins right now.\n"
        << "\nSince the hardfork is active, you must pay Founders-Reward and Masternode-Reward\n"
        << "\nCurrently, you did not agreed to pay it, but it is needed to mine new Coins.\n"
        << "\nThe payment amount is displayed underneath, for each network:\n\n"
        << "Network: " << MainnetParams.NetworkIDString() << "    | Founders-Reward: " << MainnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << MainnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - MainnetParams.GetConsensus().nMasternodePayeeReward - MainnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << TestnetParams.NetworkIDString() << "    | Founders-Reward: " << TestnetParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << TestnetParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - TestnetParams.GetConsensus().nMasternodePayeeReward - TestnetParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "Network: " << RegtestParams.NetworkIDString() << " | Founders-Reward: " << RegtestParams.GetConsensus().nTreasuryAmount << "% of blockreward. | Masternode-Reward: " << RegtestParams.GetConsensus().nMasternodePayeeReward << "% of blockreward. | Your mining Reward: " << (100 - RegtestParams.GetConsensus().nMasternodePayeeReward - RegtestParams.GetConsensus().nTreasuryAmount) << "% of blockreward.\n"
        << "\nDetails:\n\n"
        << "Your found auxpow blocks will automatically pay the fees, there are no additional steps for you.\n"
        << "\nAgreement:\n"
        << "You can agree to pay the fees by the following way:\n"
        << "\n- Always start the wallet with the -acceptdividedcoinbase argument\n"
        << "- Add acceptdividedcoinbase=1 to your globaltoken.conf file and restart the wallet.\n"
        << "\nIf you don't agree to pay fees, you will not be able to mine GlobalTokens and your blocks will be rejected.\n";
        return strStream.str();
    }
    else
    {
        // Should not occur
        strStream << "";
    }
    return strStream.str();
}