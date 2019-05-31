// Copyright (c) 2018 The UraniumX Developers
// Copyright (c) 2019 The Glboaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HASH_ARGON_H
#define HASH_ARGON_H

#include <cstdint>

int Argon2Init();
void Argon2Deinit();
void Argon2dHash(const char* input, const char* output, const int64_t nTime);

#endif // HASH_ARGON_H