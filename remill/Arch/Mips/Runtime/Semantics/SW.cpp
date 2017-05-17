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

#ifndef REMILL_ARCH_MIPS_SEMANTICS_SW_H_
#define REMILL_ARCH_MIPS_SEMANTICS_SW_H_

namespace {

/*
  Format
    101011 base rt offset

  Pseudo code
    vAddr <- sign_extend(offset) + GPR[base]
    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    pAddr <- pAddrPSIZE-1..3 || (pAddr2..0 xor (ReverseEndian || 02))
    bytesel <- vAddr2..0 xor (BigEndianCPU || 02)
    datadoubleword <- GPR[rt]63-8*bytesel..0 || 08*bytesel
    StoreMemory (CCA, WORD, datadoubleword, pAddr, vAddr, DATA)

  Notes
    In short, this is what happens:
      memory[base_register + offset] = rt_register
*/

template <typename D, typename S>
DEF_SEM(MOV, D dst, const S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

#if ADDRESS_SIZE_BITS == 32
DEF_ISEL(SW_R32_M32) = MOV<M32W, R32>;
#else
DEF_ISEL(SW_R64_M64) = MOV<M64W, R64>;
#endif

}  // namespace

#endif  // REMILL_ARCH_MIPS_SEMANTICS_SW_H_
