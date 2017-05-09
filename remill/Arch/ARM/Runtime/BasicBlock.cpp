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

#include "remill/Arch/ARM/Runtime/State.h"

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"

// Method that will implement a basic block. We will clone this method for
// each basic block in the code being lifted.
[[gnu::used]]
Memory *__remill_basic_block(Memory *memory, State &state, addr_t curr_pc) {

  bool branch_taken = false;
  addr_t zero = 0;

  // Note: These variables MUST be defined for all architectures.
  auto &STATE = state;
  auto &MEMORY = *memory;
  auto &PC = state.gpr.rip.IF_64BIT_ELSE(qword, dword);
  auto &BRANCH_TAKEN = branch_taken;

  // `PC` should already have the correct value, but it's nice to make sure
  // that `curr_pc` is used throughout, as it helps with certain downstream
  // uses to be able to depend on the optimizer not eliminating `curr_pc`.
  PC = curr_pc;

  // We will reference these variables from the bitcode side of things so that,
  // given a decoded register name and an operation type (read or write),
  // we can map the register to a specific field in the State structure.
  auto &W0 = state.gpr.R0.dword;
  auto &W1 = state.gpr.R1.dword;
  auto &W2 = state.gpr.R2.dword;
  auto &W3 = state.gpr.R3.dword;

  auto &W4 = state.gpr.R4.dword;
  auto &W5 = state.gpr.R5.dword;
  auto &W6 = state.gpr.R6.dword;
  auto &W7 = state.gpr.R7.dword;

  auto &W8 = state.gpr.R8.dword;
  auto &W9 = state.gpr.R9.dword;
  auto &W10 = state.gpr.R10.dword;
  auto &W11 = state.gpr.R11.dword;

  auto &W12 = state.gpr.R12.dword;
  auto &W13 = state.gpr.R13.dword;
  auto &W14 = state.gpr.R14.dword;
  auto &W15 = state.gpr.R15.dword;

  auto &W16 = state.gpr.R16.dword;
  auto &W17 = state.gpr.R17.dword;
  auto &W18 = state.gpr.R18.dword;
  auto &W19 = state.gpr.R19.dword;

  auto &W20 = state.gpr.R20.dword;
  auto &W21 = state.gpr.R21.dword;
  auto &W22 = state.gpr.R22.dword;
  auto &W23 = state.gpr.R23.dword;

  auto &W24 = state.gpr.R24.dword;
  auto &W25 = state.gpr.R25.dword;
  auto &W26 = state.gpr.R26.dword;
  auto &W27 = state.gpr.R27.dword;

  auto &W28 = state.gpr.R28.dword;
  auto &W29 = state.gpr.R29.dword;
  auto &W30 = state.gpr.R30.dword;

  auto &WZR = state.gpr.R31.dword;
  auto &WIP = state.gpr.rip.dword;

#if 64 == ADDRESS_SIZE_BITS
  auto &X0 = state.gpr.R0.qword;
  auto &X1 = state.gpr.R1.qword;
  auto &X2 = state.gpr.R2.qword;
  auto &X3 = state.gpr.R2.qword;

  auto &X4 = state.gpr.R4.qword;
  auto &X5 = state.gpr.R5.qword;
  auto &X6 = state.gpr.R6.qword;
  auto &X7 = state.gpr.R7.qword;

  auto &X8 = state.gpr.R8.qword;
  auto &X9 = state.gpr.R9.qword;
  auto &X10 = state.gpr.R10.qword;
  auto &X11 = state.gpr.R11.qword;

  auto &X12 = state.gpr.R12.qword;
  auto &X13 = state.gpr.R13.qword;
  auto &X14 = state.gpr.R14.qword;
  auto &X15 = state.gpr.R15.qword;

  auto &X16 = state.gpr.R16.qword;
  auto &X17 = state.gpr.R17.qword;
  auto &X18 = state.gpr.R18.qword;
  auto &X19 = state.gpr.R19.qword;

  auto &X20 = state.gpr.R20.qword;
  auto &X21 = state.gpr.R21.qword;
  auto &X22 = state.gpr.R22.qword;
  auto &X23 = state.gpr.R23.qword;

  auto &X24 = state.gpr.R24.qword;
  auto &X25 = state.gpr.R25.qword;
  auto &X26 = state.gpr.R26.qword;
  auto &X27 = state.gpr.R27.qword;

  auto &X28 = state.gpr.R28.qword;
  auto &X29 = state.gpr.R29.qword;
  auto &X30 = state.gpr.R30.qword;

  auto &XZR = state.gpr.R31.qword;
  auto &XIP = state.gpr.rip.dword;
#endif
#if 0
  // Arithmetic flags. Data-flow analyses will clear these out ;-)
  auto &AF = state.aflag.af;
  auto &CF = state.aflag.cf;
  auto &DF = state.aflag.df;
  auto &OF = state.aflag.of;
  auto &PF = state.aflag.pf;
  auto &SF = state.aflag.sf;
  auto &ZF = state.aflag.zf;
#endif
  // Lifted code will be placed here in clones versions of this function.
  return nullptr;
}

#pragma clang diagnostic pop

}  // extern C

#include "remill/Arch/Runtime/Intrinsics.cpp"
