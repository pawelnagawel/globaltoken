// Copyright (c) 2018 The UraniumX Developers
// Copyright (c) 2019 The Glboaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HASH_ARGON_H
#define HASH_ARGON_H

#include <cstdint>

void Argon2dHash(uint8_t* input, uint8_t* output, uint8_t *salthash, uint8_t *secrethash);
void Argon2iHash(uint8_t* input, uint8_t* output, uint8_t *salthash, uint8_t *secrethash);

/**
 * Function to hash the inputs in the memory-hard fashion (uses Argon2i)
 * @param  out  Pointer to the memory where the hash digest will be written
 * @param  outlen Digest length in bytes
 * @param  in Pointer to the input (password)
 * @param  inlen Input length in bytes
 * @param  salt Pointer to the salt
 * @param  saltlen Salt length in bytes
 * @pre    @a out must have at least @a outlen bytes allocated
 * @pre    @a in must be at least @inlen bytes long
 * @pre    @a saltlen must be at least @saltlen bytes long
 * @return Zero if successful, 1 otherwise.
 */
int cpu23R_hash_argon2i(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost);

/* same for MMXVId */
int cpu23R_hash_argon2d(void *out, size_t outlen, const void *in, size_t inlen,
                 const void *salt, size_t saltlen, unsigned int t_cost,
                 unsigned int m_cost);

#endif // HASH_ARGON_H