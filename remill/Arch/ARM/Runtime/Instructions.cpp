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

#define REG_RIP state.gpr.rip.qword
#define REG_XZR state.gpr.R31.qword

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

