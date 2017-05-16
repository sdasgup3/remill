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

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"

#include "remill/Arch/ARM/Runtime/State.h"
#include "remill/Arch/ARM/Runtime/Types.h"
#include "remill/Arch/ARM/Runtime/Operators.h"

#include <algorithm>
#include <bitset>
#include <fenv.h>
#include <cmath>

#define REG_PC state.gpr.rip.qword

#define REG_WZR state.gpr.R31.dword
#define REG_XZR state.gpr.R31.qword

#define REG_WSP state.gpr.R31.dword
#define REG_SP  state.gpr.R31.qword

#define REG_LR state.gpr.R30.qword

#define REG_W0 state.gpr.R0.dword
#define REG_W1 state.gpr.R1.dword
#define REG_W2 state.gpr.R2.dword
#define REG_W3 state.gpr.R3.dword

#define REG_W4 state.gpr.R4.dword
#define REG_W5 state.gpr.R5.dword
#define REG_W6 state.gpr.R6.dword
#define REG_W7 state.gpr.R7.dword

#define REG_W8 state.gpr.R8.dword
#define REG_W9 state.gpr.R9.dword
#define REG_W10 state.gpr.R10.dword
#define REG_W11 state.gpr.R11.dword

#define REG_W12 state.gpr.R12.dword
#define REG_W13 state.gpr.R13.dword
#define REG_W14 state.gpr.R14.dword
#define REG_W15 state.gpr.R15.dword

#define REG_W16 state.gpr.R16.dword
#define REG_W17 state.gpr.R17.dword
#define REG_W18 state.gpr.R18.dword
#define REG_W19 state.gpr.R19.dword

#define REG_W20 state.gpr.R20.dword
#define REG_W21 state.gpr.R21.dword
#define REG_W22 state.gpr.R22.dword
#define REG_W23 state.gpr.R23.dword

#define REG_W24 state.gpr.R24.dword
#define REG_W25 state.gpr.R25.dword
#define REG_W26 state.gpr.R26.dword
#define REG_W27 state.gpr.R27.dword

#define REG_W28 state.gpr.R28.dword
#define REG_W29 state.gpr.R29.dword
#define REG_W30 state.gpr.R30.dword

#define REG_X0 state.gpr.R0.qword
#define REG_X1 state.gpr.R1.qword
#define REG_X2 state.gpr.R2.qword
#define REG_X3 state.gpr.R3.qword

#define REG_X4 state.gpr.R4.qword
#define REG_X5 state.gpr.R5.qword
#define REG_X6 state.gpr.R6.qword
#define REG_X7 state.gpr.R7.qword

#define REG_X8 state.gpr.R8.qword
#define REG_X9 state.gpr.R9.qword
#define REG_X10 state.gpr.R10.qword
#define REG_X11 state.gpr.R11.qword

#define REG_X12 state.gpr.R12.qword
#define REG_X13 state.gpr.R13.qword
#define REG_X14 state.gpr.R14.qword
#define REG_X15 state.gpr.R15.qword

#define REG_X16 state.gpr.R16.qword
#define REG_X17 state.gpr.R17.qword
#define REG_X18 state.gpr.R18.qword
#define REG_X19 state.gpr.R19.qword

#define REG_X20 state.gpr.R20.qword
#define REG_X21 state.gpr.R21.qword
#define REG_X22 state.gpr.R22.qword
#define REG_X23 state.gpr.R23.qword

#define REG_X24 state.gpr.R24.qword
#define REG_X25 state.gpr.R25.qword
#define REG_X26 state.gpr.R26.qword
#define REG_X27 state.gpr.R27.qword

#define REG_X28 state.gpr.R28.qword
#define REG_X29 state.gpr.R29.qword
#define REG_X30 state.gpr.R30.qword

#define FLAG_NF state.sflag.nf
#define FLAG_ZF state.sflag.zf
#define FLAG_CF state.sflag.cf
#define FLAG_VF state.sflag.vf

#include "remill/Arch/ARM/Semantics/FLAGS.cpp"
#include "remill/Arch/ARM/Semantics/BINARY.cpp"
#include "remill/Arch/ARM/Semantics/CALL_RET.cpp"
#include "remill/Arch/ARM/Semantics/DATAXFER.cpp"
