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
  return memory;
}

}

DEF_ISEL(MOV_R64_R64) = MOV<M64W, R64>;
DEF_ISEL(LDP_R64_R64) = MOV<M64W, R64>;
DEF_ISEL(LDR_R64_R64) = MOV<M64W, R64>;
DEF_ISEL(MOVZ_R64_Ii64) = MOV<M64W, R64>;

DEF_ISEL(BR_R64) = BL<R64W, R64>;
DEF_ISEL(BNE_Ii64) = MOV<M64W, R64>;
DEF_ISEL(LDR_R64) = MOV<M64W, R64>;
DEF_ISEL(LDRB_R64) = MOV<M64W, R64>;
DEF_ISEL(STRB_R64) = MOV<M64W, R64>;
DEF_ISEL(LDR_R64_Ii64) = MOV<M64W, I64>;
