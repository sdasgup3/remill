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

namespace {

DEF_SEM(RET) {
  Write(REG_PC, Read(ReadPtr<addr_t>(REG_W30)));
  return memory;
}

template <typename S>
DEF_SEM(RET_REG, S src) {
  auto call_pc = Read(src);
  Write(REG_PC, call_pc);
  return memory;
}

template <typename S>
DEF_SEM(BL, S src) {
  auto pc = Read(ReadPtr<addr_t>(REG_PC));
  auto next_pc = Read(src);
  Write(REG_LR, pc);
  Write(REG_PC, next_pc);
  return memory;
}


template <typename D, typename S>
DEF_SEM(BL, D dst, S src) {
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(STP, D dst, S1 src1, S2 src2) {
  return memory;
}

template <typename D, typename S1>
DEF_SEM(STUR, D dst, S1 src1) {
  return memory;
}

template <typename S>
DEF_SEM(B, S dst) {
  return memory;
}

}


DEF_ISEL(RET) = RET;
DEF_ISEL(RET_R64) = RET_REG<R64>;
DEF_ISEL(BL_I64) = BL<I64>;

DEF_ISEL(NOP) = RET;
DEF_ISEL(STP_R64_R64) = STP<R64W, R64, R64>;
DEF_ISEL(STP_R32_R32) = STP<R64W, R64, R64>;
DEF_ISEL(CMP_R64_Ii64) = STP<R64W, R64, I64>;
DEF_ISEL(CBZ_R64_Ii64) = STP<R64W, R64, R64>;
DEF_ISEL(CBNZ_R64_Ii64) = STP<R64W, R64, R64>;
DEF_ISEL(STUR_R64) = STUR<R64W, R64>;
DEF_ISEL(STR_R64) = STUR<R64W, R64>;
DEF_ISEL(BLR_R64) = STUR<R64W, R64>;
DEF_ISEL(B_Ii64) = B<I64>;
DEF_ISEL(BLS_Ii64) = B<I64>;
