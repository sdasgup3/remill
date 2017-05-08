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

#ifndef REMILL_ARCH_MIPS_SEMANTICS_ADD_H_
#define REMILL_ARCH_MIPS_SEMANTICS_ADD_H_

namespace {

/*
  if NotWordValue(GPR[rs]) or NotWordValue(GPR[rt]) then
    UNPREDICTABLE
  endif

  temp ← GPR[rs] + GPR[rt]
  GPR[rd] ← sign_extend(temp 31..0)
*/

template <typename D, typename S1, typename S2>
DEF_SEM(ADDU_IMPL, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  WriteZExt(dst, sum);
  return memory;
}

DEF_ISEL_MnW_Mn_Rn(ADDU, ADDU_IMPL);

/*
  if NotWordValue(GPR[rs]) or NotWordValue(GPR[rt]) then
    UNPREDICTABLE
  endif

  temp ← (GPR[rs] 31 ||GPR[rs] 31..0) + (GPR[rt] 31 ||GPR[rt] 31..0)
  if temp 32 ≠ temp 31 then
    SignalException(IntegerOverflow)
  else
    GPR[rd] ← sign_extend(temp 31..0)
  endif
*/

template <typename D, typename S1, typename S2>
DEF_SEM(ADD_IMPL, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);

  RaiseException(((sum >> 31) & 1) != ((sum >> 30) & 1), IntegerOverflow);

  WriteZExt(dst, sum);
  return memory;
}

DEF_ISEL_MnW_Mn_Rn(ADD, ADD_IMPL);

}  // namespace

#endif  // REMILL_ARCH_MIPS_SEMANTICS_ADD_H_
