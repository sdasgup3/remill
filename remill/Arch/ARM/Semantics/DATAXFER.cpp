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
DEF_SEM(MOV, D dst, const S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename D, typename S>
DEF_SEM(MOVZ, D dst, const S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

}

DEF_ISEL(MOV_R32_R32) = MOV<R32W, R32>;
DEF_ISEL(MOV_R64_R64) = MOV<R64W, R64>;
DEF_ISEL(MOVZ_R64_I64) = MOVZ<R64W, I64>;
DEF_ISEL(MOVZ_R32_I32) = MOVZ<R32W, I32>;


namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(LDP, D dst, const S1 src1, const S2 src2) {
  //TODO: LDP has three variant of instructions post-index, pre-index and signed offset
  // What are the differences and how can it be recognized at sematincs level?? Check ??
  static_cast<void>(dst);
  static_cast<void>(src1);
  static_cast<void>(src2);
  return memory;
}

template <typename D, typename S1, typename S2, typename S3>
DEF_SEM(LDP, D dst, const S1 src1, const S2 src2, const S3 src3) {
  //TODO: LDP has three variant of instructions post-index, pre-index and signed offset
  // What are the differences and how can it be recognized at sematincs level?? Check ??
  static_cast<void>(dst);
  static_cast<void>(src1);
  static_cast<void>(src2);
  static_cast<void>(src3);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(LDR, D dst, const S1 src1, const S2 src2) {
  //TODO: LDR has three variant of instructions post-index, pre-index and signed offset
  // What are the differences and how can it be recognized at sematincs level?? Check ??
  static_cast<void>(dst);
  static_cast<void>(src1);
  static_cast<void>(src2);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(LDR, D dst, const S1 src1) {
  //TODO: LDR has three variant of instructions post-index, pre-index and signed offset
  // What are the differences and how can it be recognized at sematincs level?? Check ??
  static_cast<void>(dst);
  static_cast<void>(src1);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(LDRB, D dst, const S1 src1) {
  //TODO: LDRB has three variant of instructions post-index, pre-index and signed offset
  // What are the differences and how can it be recognized at sematincs level?? Check ??
  static_cast<void>(dst);
  static_cast<void>(src1);
  return memory;
}

}

DEF_ISEL(LDP_R64_R64_R64) = LDP<R64W, R64, R64>;
DEF_ISEL(LDP_R64_R64_I64) = LDP<R64W, R64, I64>;
DEF_ISEL(LDP_R64_R64_M64) = LDP<R64W, R64, M64>;
DEF_ISEL(LDP_R64_R64_M64_I64) = LDP<R64W, R64, M64, I64>;

DEF_ISEL(LDR_R64_R64_I64) = LDR<R64W, R64, I64>;
DEF_ISEL(LDR_R64_M64) = LDR<R64W, M64>;
DEF_ISEL(LDR_R32_M32) = LDR<R32W, M32>;
DEF_ISEL(LDR_R64_R64) = LDR<R64W, R64>;
DEF_ISEL(LDR_R32_R32) = LDR<R32W, R32>;
DEF_ISEL(LDR_R64_I64) = LDR<R64W, I64>;
DEF_ISEL(LDR_R32_I32) = LDR<R32W, I32>;

DEF_ISEL(LDRB_R32_M32) = LDR<R32W, M32>;

namespace {

template <typename D, typename S>
DEF_SEM(STUR, D dst, S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename D, typename S>
DEF_SEM(STR, D dst, S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename D, typename S>
DEF_SEM(STRB, D dst, S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

}

DEF_ISEL(STUR_R64_M64) = STUR<R64W, M64>;
DEF_ISEL(STR_R64_M64) = STR<R64W, M64>;
DEF_ISEL(STRB_R32_M32) = STR<R32W, M32>;
