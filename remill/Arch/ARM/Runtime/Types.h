/*
 * Types.h
 *
 *  Created on: May 9, 2017
 *      Author: akshayk
 */

#ifndef REMILL_ARCH_ARM_RUNTIME_TYPES_H_
#define REMILL_ARCH_ARM_RUNTIME_TYPES_H_

// define 32 bit and 64 registers types
// TODO: Check how arm accesses the 8/16 bits of registers;
// Add new registers type as and when needed by semantics

typedef RnW<IF_64BIT_ELSE(uint64_t, uint32_t)> R32W;
typedef RnW<uint64_t> R64W;

typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;

typedef RVn<vec32_t> V32;
typedef RVn<vec64_t> V64;

typedef RVnW<IF_64BIT_ELSE(vec64_t, vec32_t)> V32W;
typedef RVnW<vec64_t> V64W;

typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;


typedef MVnW<vec32_t> MV32W;
typedef MVnW<vec64_t> MV64W;

typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;

typedef MVn<vec32_t> MV32;
typedef MVn<vec64_t> MV64;

typedef In<uint32_t> I32;
typedef In<uint64_t> I64;

typedef In<addr_t> PC;

#endif /* REMILL_ARCH_ARM_RUNTIME_TYPES_H_ */
