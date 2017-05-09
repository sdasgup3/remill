/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef REMILL_ARCH_ARM_RUNTIME_STATE_H_
#define REMILL_ARCH_ARM_RUNTIME_STATE_H_

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

struct Reg final {
  union {
    alignas(4) uint32_t dword;
    IF_64BIT(alignas(8) uint64_t qword;)
  } __attribute__((packed));

  IF_32BIT(uint32_t _padding0;)
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg),
              "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");
IF_64BIT(static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");)


struct alignas(8) GPR final {
  // Prevents LLVM from casting a `GPR` into an `i64` to access `rax`.
  volatile uint64_t _0;
  Reg R0;
  volatile uint64_t _1;
  Reg R1;
  volatile uint64_t _2;
  Reg R2;
  volatile uint64_t _3;
  Reg R3;
  volatile uint64_t _4;
  Reg R4;
  volatile uint64_t _5;
  Reg R5;
  volatile uint64_t _6;
  Reg R6;
  volatile uint64_t _7;
  Reg R7;
  volatile uint64_t _8;
  Reg R8;
  volatile uint64_t _9;
  Reg R9;
  volatile uint64_t _10;
  Reg R10;
  volatile uint64_t _11;
  Reg R11;
  volatile uint64_t _12;
  Reg R12;
  volatile uint64_t _13;
  Reg R13;
  volatile uint64_t _14;
  Reg R14;
  volatile uint64_t _15;
  Reg R15;
  volatile uint64_t _16;
  Reg R16;
  volatile uint64_t _17;
  Reg R17;
  volatile uint64_t _18;
  Reg R18;
  volatile uint64_t _19;
  Reg R19;
  volatile uint64_t _20;
  Reg R20;
  volatile uint64_t _21;
  Reg R21;
  volatile uint64_t _22;
  Reg R22;
  volatile uint64_t _23;
  Reg R23;
  volatile uint64_t _24;
  Reg R24;
  volatile uint64_t _25;
  Reg R25;
  volatile uint64_t _26;
  Reg R26;
  volatile uint64_t _27;
  Reg R27;
  volatile uint64_t _28;
  Reg R28;
  volatile uint64_t _29;
  Reg R29;
  volatile uint64_t _30;
  Reg R30;

  // Reg 31 is called zero registers;
  volatile uint64_t _31;
  Reg R31;

  // Program counter of the CURRENT instruction!
  Reg rip;
} __attribute__((packed));

static_assert(520 == sizeof(GPR), "Invalid structure packing of `GPR`.");


union alignas(8) ProcState final {
  uint64_t flat;
  struct {
                    //  bit 0
    uint32_t N:1;   //  Negative condition flag
    uint32_t Z:1;   //  Zero condition flag
    uint32_t C:1;   //  Carry condition flag
    uint32_t V:1;   //  Overflow condition flag

                    //  bit 4
    uint32_t D:1;   //  Debug mask bit [AArch64 only]
    uint32_t A:1;   //  Asynchronous abort mask bit
    uint32_t I:1;   //  IRQ mask bit
    uint32_t F:1;   //  FIQ mask bit

                    //  bit 8
    uint32_t SS:1;  //  Single-step bit
    uint32_t IL:1;  //  Illegal state bit
    uint32_t EL:2;  //  Exception Level (see above)

                    //  bit 12
    uint32_t nRW:1; //  not Register Width: 0=64, 1=32
    uint32_t SP:1;  //  Stack pointer select: 0=SP0, 1=SPx [AArch64 only]
    uint32_t Q:1;   //  Cumulative saturation flag [AArch32 only]
    uint32_t GE:4;  //  Greater than or Equal flags [AArch32 only]

                    // bit 19
    uint32_t IT:8;  // If-then state [AArch32 only]
    uint32_t J:1;   // Jazelle state [AArch32 only]
    uint32_t T:1;   // Thumb state [AArch32 only]
    uint32_t E:1;   // Endian state [AArch32 only]
    uint32_t M:5;   // Mode field (see above) [AArch32 only]
    uint32_t reserved_flags:29;  // bits 34-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(ProcState), "Invalid structure packing of `Flags`.");

struct alignas(16) State final : public ArchState {
  ProcState sflag;  // 8 bytes.
  GPR gpr;          // 520 bytes
  uint8_t _0[16];
} __attribute__((packed));

static_assert((544 + 16) == sizeof(State),
              "Invalid packing of `struct State`");

#endif /* REMILL_ARCH_ARM_RUNTIME_STATE_H_ */
