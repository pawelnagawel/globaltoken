// Copyright (c) 2019 The BeeGroup developers are EternityGroup
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HONEYCOMB_HASH_H
#define HONEYCOMB_HASH_H

#include <uint256.h>

#include <crypto/algos/honeycomb/facet_one.h>
#include <crypto/algos/honeycomb/facet_two.h>
#include <crypto/algos/honeycomb/facet_three.h>
#include <crypto/algos/honeycomb/facet_four.h>
#include <crypto/algos/honeycomb/facet_five.h>
#include <crypto/algos/honeycomb/facet_six.h>

inline uint512 HoneyBee( unsigned char *in, unsigned int sz )
{
	uint512 result;
	memcpy( &result.begin()[ 0], &in[0],     36 );
	memcpy( &result.begin()[36], &in[sz-28], 28 );
	return result;    
}

/* ----------- Beenode Hash ------------------------------------------------ */
//--.
template<typename T1> 
inline uint256 HashHoneyComb( const T1 pbegin, const T1 pend )
{	
    facet_one_context		ctx_one;
    facet_two_context		ctx_two;
    facet_three_context     ctx_three;
    facet_four_context		ctx_four;
    facet_five_context		ctx_five;
    facet_six_context     	ctx_six;
    static unsigned char pblank[1];
    uint512 hash[12];
    uint512 honey;
    honey = HoneyBee( (unsigned char*)static_cast<const void*>(&pbegin[0]), (pend-pbegin) * sizeof(pbegin[0]) );
    facet_one_init(&ctx_one);
    facet_one(&ctx_one, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]) );
    facet_one_close(&ctx_one, static_cast<void*>(&hash[0]));
    facet_four_init(&ctx_four);
    facet_four(&ctx_four, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    facet_four_close(&ctx_four, static_cast<void*>(&hash[1]));
    hash[2] = honey^hash[1];
    hash[3] = hash[0]^hash[2];	
    facet_two_init( &ctx_two );
    facet_two( &ctx_two, static_cast<const void*>(&hash[3]), 64 );
    facet_two_close( &ctx_two, static_cast<void*>(&hash[4]) );
    facet_five_init(&ctx_five);
    facet_five (&ctx_five, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    facet_five_close(&ctx_five, static_cast<void*>(&hash[5]));
    hash[6] = honey^hash[5];
    hash[7] = hash[4]^hash[6];	
    facet_three_init(  &ctx_three  );
    facet_three(  &ctx_three, static_cast<const void*>(&hash[7]), 64   );
    facet_three_close(   &ctx_three, static_cast<void*>( &hash[8] )   );
    facet_six_init(&ctx_six);
    facet_six( &ctx_six, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]) );
    facet_six_close(&ctx_six, static_cast<void*>(&hash[9]));
    hash[10] = honey^hash[9];
    hash[11] = hash[8]^hash[10];	
    return hash[11].trim256();
}

#endif // HONEYCOMB_HASH_H