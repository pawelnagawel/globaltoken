// Copyright (c) 2018 The UraniumX Developers
// Copyright (c) 2019 The Glboaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "argon2.h"
#include "hashargon.h"

#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <assert.h>

int cpu23R_hash_argon2i(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {

    argon2_context context;

    /* Detect and reject overflowing sizes */
    /* TODO: This should probably be fixed in the function signature */
    if (inlen > UINT32_MAX) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (outlen > UINT32_MAX) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (saltlen > UINT32_MAX) {
        return ARGON2_SALT_TOO_LONG;
    }
    
    context.version         = ARGON2_VERSION_13;

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)outlen;
    context.pwd = (uint8_t *)in;
    context.pwdlen = (uint32_t)inlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = 1;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    return argon2_ctx(&context, Argon2_i);
}

int cpu23R_hash_argon2d(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost) {
    argon2_context context;

    /* Detect and reject overflowing sizes */
    /* TODO: This should probably be fixed in the function signature */
    if (inlen > UINT32_MAX) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (outlen > UINT32_MAX) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (saltlen > UINT32_MAX) {
        return ARGON2_SALT_TOO_LONG;
    }
    
    context.version         = ARGON2_VERSION_13;

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)outlen;
    context.pwd = (uint8_t *)in;
    context.pwdlen = (uint32_t)inlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = 1;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    return argon2_ctx(&context, Argon2_d);
}

void Argon2dHash (const void* input, const size_t inlen, const void* output, const size_t outlen, const void *salthash, const size_t salthashlen, const void *secrethash, const size_t secrethashlen)
{
    argon2_context ctx;

    ctx.version         = ARGON2_VERSION_13;
    ctx.flags           = ARGON2_DEFAULT_FLAGS;

    ctx.out             = (uint8_t*) output;
    ctx.outlen          = outlen;
    ctx.pwd             = (uint8_t*) input;
    ctx.pwdlen          = inlen;
    ctx.salt            = (uint8_t*) salthash;
    ctx.saltlen         = salthashlen;
    
    ctx.secret          = (uint8_t*) secrethash;
    ctx.secretlen       = secrethashlen;
    ctx.ad              = nullptr;
    ctx.adlen           = 0;

    ctx.m_cost          = 16384;
    ctx.t_cost          = 2;
    ctx.lanes           = 2;
    ctx.threads         = 1;

    ctx.allocate_cbk    = nullptr;
    ctx.free_cbk        = nullptr;

    const int result = argon2_ctx (&ctx, Argon2_d);
    assert (result == ARGON2_OK);
}

void Argon2iHash (const void* input, const size_t inlen, const void* output, const size_t outlen, const void *salthash, const size_t salthashlen, const void *secrethash, const size_t secrethashlen)
{
    argon2_context ctx;

    ctx.version         = ARGON2_VERSION_13;
    ctx.flags           = ARGON2_DEFAULT_FLAGS;

    ctx.out             = (uint8_t*) output;
    ctx.outlen          = outlen;
    ctx.pwd             = (uint8_t*) input;
    ctx.pwdlen          = inlen;
    ctx.salt            = (uint8_t*) salthash;
    ctx.saltlen         = salthashlen;
    
    ctx.secret          = (uint8_t*) secrethash;
    ctx.secretlen       = secrethashlen;
    ctx.ad              = nullptr;
    ctx.adlen           = 0;

    ctx.m_cost          = 8192;
    ctx.t_cost          = 4;
    ctx.lanes           = 6;
    ctx.threads         = 1;

    ctx.allocate_cbk    = nullptr;
    ctx.free_cbk        = nullptr;

    const int result = argon2_ctx (&ctx, Argon2_i);
    assert (result == ARGON2_OK);
}