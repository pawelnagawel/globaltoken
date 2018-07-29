// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef EQUIHASH_PARAMS_H
#define EQUIHASH_PARAMS_H

#include <atomic>
#include <mutex>
#include <string>

struct AtomicCounter {
    std::atomic<uint64_t> value;

    AtomicCounter() : value {0} { }

    void increment(){
        ++value;
    }

    void decrement(){
        --value;
    }
    
    void SetNull(){
        value.store(0);
    }
    
    void set(uint64_t newvalue){
        value.store(newvalue);
    }

    uint64_t get() const {
        return value.load();
    }
};

AtomicCounter ehSolverRuns;
AtomicCounter solutionTargetChecks;

#endif // EQUIHASH_PARAMS_H