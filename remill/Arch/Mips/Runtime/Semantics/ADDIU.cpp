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

#include "remill/Arch/Mips/Runtime/Common.h"

#ifndef REMILL_ARCH_MIPS_SEMANTICS_ADDIU_H_
#define REMILL_ARCH_MIPS_SEMANTICS_ADDIU_H_

namespace {

/*
  Format
    001001 rs rt immediate

  Pseudo code
    if NotWordValue(GPR[rs]) then
      UNPREDICTABLE
    endif

    temp <- GPR[rs] + sign_extend(immediate)
    GPR[rt] <- sign_extend(temp_31..0)

  Notes
    The immediate is always 16-bits long. The semantic name
    is generated from the remill's instruction operands, meaning
    that immediate values are always 64 bits.
*/

template <typename D, typename S1, typename S2>
DEF_SEM(ADDIU, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  Write(dst, sum);
  return memory;
}

#if ADDRESS_SIZE_BITS == 32
DEF_ISEL(ADDIU_R32_R32_UI64) = ADDIU<R32W, R32, I32>;
#else
DEF_ISEL(ADDIU_R64_R64_UI64) = ADDIU<R64W, R64, I64>;
#endif

}  // namespace

#endif  // REMILL_ARCH_MIPS_SEMANTICS_ADDIU_H_
