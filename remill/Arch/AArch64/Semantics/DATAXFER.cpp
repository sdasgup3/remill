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

template <typename D, typename S>
DEF_SEM(MOV_WITH_ZEXT, D dst, S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename D, typename S>
DEF_SEM(MOVN_WITH_ZEXT, D dst, S src) {
  WriteZExt(dst, UNot(Read(src)));
  return memory;
}

template <typename D, typename S, typename ExtType>
DEF_SEM(MOV_WITH_SEXT, D dst, S src) {
  WriteZExt(dst, SExtTo<ExtType>(Read(src)));
  return memory;
}

}  // namespace

DEF_ISEL(MOV_R64W_R64) = MOV_WITH_ZEXT<R64W, R64>;
DEF_ISEL(MOV_R32W_R32) = MOV_WITH_ZEXT<R32W, R32>;

// Shifts on the immediate are handled by the lifter.
DEF_ISEL(MOVZ_R64W_U) = MOV_WITH_ZEXT<R64W, I64>;
DEF_ISEL(MOVZ_R32W_U) = MOV_WITH_ZEXT<R32W, I32>;

DEF_ISEL(MOVN_R64W_U) = MOVN_WITH_ZEXT<R64W, I64>;
DEF_ISEL(MOVN_R32W_U) = MOVN_WITH_ZEXT<R32W, I32>;

// For `LDR X0, [X1]` and its variants, Capstone reports the address `X1` as
// being a register operand instead of a memory operand with the base register
// being `X1`. The way that Remill passes registers is such that the value
// of the register can be transparently treated as the address in a memory
// operand. The same is true of absolute values of addresses.

DEF_ISEL(LDR_R64W_M) = MOV_WITH_ZEXT<R64W, M64>;
DEF_ISEL(LDR_R64W_U) = MOV_WITH_ZEXT<R64W, M64>;
DEF_ISEL(LDR_R64W_R64) = MOV_WITH_ZEXT<R64W, M64>;

DEF_ISEL(LDRW_R32W_M) = MOV_WITH_ZEXT<R32W, M32>;
DEF_ISEL(LDRSW_R32W_M32) = MOV_WITH_SEXT<R32W, M32, uint64_t>;

DEF_ISEL(LDR_R32W_M) = MOV_WITH_ZEXT<R32W, M32>;
DEF_ISEL(LDR_R32W_U) = MOV_WITH_ZEXT<R32W, M32>;
DEF_ISEL(LDR_R32W_R64) = MOV_WITH_ZEXT<R32W, M32>;

DEF_ISEL(LDRH_R32W_M) = MOV_WITH_ZEXT<R32W, M16>;
DEF_ISEL(LDRH_R32W_R64) = MOV_WITH_ZEXT<R32W, M16>;

DEF_ISEL(LDRSH_R32W_M) = MOV_WITH_SEXT<R32W, M16, uint32_t>;
DEF_ISEL(LDRSH_R32W_R64) = MOV_WITH_SEXT<R32W, M16, uint32_t>;

DEF_ISEL(LDRB_R32W_M) = MOV_WITH_ZEXT<R32W, M8>;
DEF_ISEL(LDRB_R32W_R64) = MOV_WITH_ZEXT<R32W, M8>;
DEF_ISEL(LDRSB_R32W_M) = MOV_WITH_SEXT<R32W, M8, uint32_t>;
DEF_ISEL(LDRSB_R32W_R64) = MOV_WITH_SEXT<R32W, M8, uint32_t>;

namespace {

template <typename S1, typename S2>
DEF_SEM(STORE, S1 src, S2 dst) {
  Write(dst, Read(src));
  return memory;
}

}  // namespace

// Store to memory. The format of this is approximately `STR X0, [X1]`,
// where it is interpreted as write `X0` into the memory at address `X1`.

DEF_ISEL(STR_R64_R64) = STORE<R64, M64W>;
DEF_ISEL(STR_R64_M) = STORE<R64, M64W>;

// These do implicit truncation of the source register. Remill passes the
// register values as `addr_t` vals, and the backing "store" value of the
// `Rn<T>` types is also an `addr_t`, so specifying things slightly
// incorrectly is fine.
DEF_ISEL(STR_R32_R32) = STORE<R32, M32W>;
DEF_ISEL(STR_R32_M) = STORE<R32, M32W>;

DEF_ISEL(STRH_R32_R64) = STORE<R16, M16W>;
DEF_ISEL(STRH_R32_M) = STORE<R16, M16W>;

DEF_ISEL(STRB_R32_R64) = STORE<R8, M8W>;
DEF_ISEL(STRB_R32_M) = STORE<R8, M8W>;

namespace {

DEF_SEM(STORE_PAIR_32, R32 src1, R32 src2, MV64W dst) {
  uint32v2_t vec = {};
  vec = UInsertV32(vec, 0, Read(src1));
  vec = UInsertV32(vec, 1, Read(src2));
  UWriteV32(dst, vec);
  return memory;
}

DEF_SEM(STORE_PAIR_64, R64 src1, R64 src2, MV128W dst) {
  uint64v2_t vec = {};
  vec = UInsertV64(vec, 0, Read(src1));
  vec = UInsertV64(vec, 1, Read(src2));
  UWriteV64(dst, vec);
  return memory;
}

}  // namespace

DEF_ISEL(STP_R32_R32_M) = STORE_PAIR_64;
DEF_ISEL(STP_R64_R64_M) = STORE_PAIR_64;

namespace {

DEF_SEM(LOAD_PAIR_32_DISP, R32W dst1, R32W dst2, MV64 src, I64 disp) {
  auto vec = UReadV32(DisplaceAddress(src, Read(disp)));
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  return memory;
}

DEF_SEM(LOAD_PAIR_64_DISP, R64W dst1, R64W dst2, MV128 src, I64 disp) {
  auto vec = UReadV64(DisplaceAddress(src, Read(disp)));
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  return memory;
}

DEF_SEM(LOAD_PAIR_32, R32W dst1, R32W dst2, MV64 src) {
  auto vec = UReadV32(src);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  return memory;
}

DEF_SEM(LOAD_PAIR_64, R64W dst1, R64W dst2, MV128 src) {
  auto vec = UReadV64(src);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_R64W_R64W_M_U) = LOAD_PAIR_64_DISP;
DEF_ISEL(LDP_R32W_R32W_M_U) = LOAD_PAIR_32_DISP;

DEF_ISEL(LDP_R64W_R64W_M) = LOAD_PAIR_64;
DEF_ISEL(LDP_R32W_R32W_M) = LOAD_PAIR_32;
