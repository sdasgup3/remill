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

} // namespace

DEF_ISEL(RET) = RET;
DEF_ISEL(RET_R64) = RET_REG<R64>;

namespace {

template <typename S>
DEF_SEM(B, S dst) {
  return memory;
}

template <typename S>
DEF_SEM(BL, S src) {
  auto pc = Read(ReadPtr<addr_t>(REG_PC));
  auto next_pc = Read(src);
  WriteZExt(REG_LR, pc);
  WriteZExt(REG_PC, next_pc);
  return memory;
}

template <typename S>
DEF_SEM(BR, S src) {
  return memory;
}


template <typename D, typename S>
DEF_SEM(BL, D dst, S src) {
  return memory;
}

template <typename S>
DEF_SEM(BLR, S src) {
  return memory;
}

template <typename S>
DEF_SEM(BLS, S src) {
  return memory;
}

template <typename S>
DEF_SEM(BNE, S src) {
  auto zf =  ZExtTo<S>(Unsigned(Read(FLAG_ZF)));
  if(UCmpEq(zf, decltype(zf)(0))) {
    auto pc = Read(ReadPtr<addr_t>(REG_PC));
    auto next_pc = Read(src);
    WriteZExt(REG_LR, pc);
    WriteZExt(REG_PC, next_pc);
  }
  return memory;
}

}

DEF_ISEL(B_I64) = B<I64>;
DEF_ISEL(B_I32) = B<I32>;

DEF_ISEL(BL_I64) = BL<I64>;
DEF_ISEL(BL_I32) = BL<I32>;

DEF_ISEL(BR_R64) = BR<R64>;

DEF_ISEL(BLS_I64) = BLS<I64>;
DEF_ISEL(BLS_I32) = BLS<I32>;
DEF_ISEL(BLR_R64) = BLR<R64>;

DEF_ISEL(BNE_I64) = BNE<I64>;
DEF_ISEL(BNE_I32) = BNE<I32>;
namespace {

DEF_SEM(NOP) {
  return memory;
}

}

DEF_ISEL(NOP) = NOP;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(STP, D dst, S1 src1, S2 src2) {
  return memory;
}

}

DEF_ISEL(STP_R64_R64_M64) = STP<R64W, R64, M64>;
DEF_ISEL(STP_R32_R32) = STP<R64W, R64, R64>;
