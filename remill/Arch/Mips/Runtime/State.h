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

#ifndef REMILL_ARCH_MIPS_RUNTIME_STATE_H_
#define REMILL_ARCH_MIPS_RUNTIME_STATE_H_

// !!! RULES FOR STATE STRUCTURE TYPES !!!
//
//  (1) Never use a type that has a different allocation size on a different
//      architecture. This includes things like pointers or architecture-
//      specific floating point types (e.g. `long double`).
//
//  (2) Never depend on implicit padding or alignment, even if you explicitly
//      specify it. Always "fill" structures to the desired alignment with
//      explicit structure fields.
//
//  (3) Trust but verify the `static_assert`s that try to verify the sizes of
//      structures. Clang will LIE to you! This happens if you compile a file
//      to bitcode for one architecture, then change its `DataLayout` to
//      match another architecture.

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

// For remill-opt's register alias analysis, we don't want 32-bit lifted
// code to look like operations on 64-bit registers, because then every
// (bitcasted from 64 bit) store of a 32-bit value will look like a false-
// dependency on the (bitcasted from 64 bit) full 64-bit quantity.
struct Reg final {
  union {
    alignas(4) uint32_t dword;
    IF_64BIT(alignas(8) uint64_t qword;)
  } __attribute__((packed));

  IF_32BIT(uint32_t _padding0;)
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg), "Invalid packing of `Reg`.");

static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");
IF_64BIT(static_assert(0 == __builtin_offsetof(Reg, qword),
                       "Invalid packing of `Reg::qword`.");)

// Named the same way as the 64-bit version to keep names the same
// across architectures. All registers are here, even the 64-bit ones. The
// 64-bit ones are inaccessible in lifted 32-bit code because they will
// not be referenced by named variables in the `__remill_basic_block`
// function.

/// \todo this is completely broken, i know; regs should be split in the right
/// categories
/// \todo mips32 and mips64 register are all mixed up...
struct alignas(8) GPR final {
  // Prevents LLVM from casting a `GPR` into an `i64` to access `rax`.
  volatile uint64_t _0;
  Reg A0;

  volatile uint64_t _1;
  Reg A0_64;

  volatile uint64_t _2;
  Reg A1;

  volatile uint64_t _3;
  Reg A1_64;

  volatile uint64_t _4;
  Reg A2;

  volatile uint64_t _5;
  Reg A2_64;

  volatile uint64_t _6;
  Reg A3;

  volatile uint64_t _7;
  Reg A3_64;

  volatile uint64_t _8;
  Reg AC0;

  volatile uint64_t _9;
  Reg AC0_64;

  volatile uint64_t _10;
  Reg AC1;

  volatile uint64_t _11;
  Reg AC2;

  volatile uint64_t _12;
  Reg AC3;

  volatile uint64_t _13;
  Reg AT;

  volatile uint64_t _14;
  Reg AT_64;

  volatile uint64_t _15;
  Reg COP00;

  volatile uint64_t _16;
  Reg COP01;

  volatile uint64_t _17;
  Reg COP010;

  volatile uint64_t _18;
  Reg COP011;

  volatile uint64_t _19;
  Reg COP012;

  volatile uint64_t _20;
  Reg COP013;

  volatile uint64_t _21;
  Reg COP014;

  volatile uint64_t _22;
  Reg COP015;

  volatile uint64_t _23;
  Reg COP016;

  volatile uint64_t _24;
  Reg COP017;

  volatile uint64_t _25;
  Reg COP018;

  volatile uint64_t _26;
  Reg COP019;

  volatile uint64_t _27;
  Reg COP02;

  volatile uint64_t _28;
  Reg COP020;

  volatile uint64_t _29;
  Reg COP021;

  volatile uint64_t _30;
  Reg COP022;

  volatile uint64_t _31;
  Reg COP023;

  volatile uint64_t _32;
  Reg COP024;

  volatile uint64_t _33;
  Reg COP025;

  volatile uint64_t _34;
  Reg COP026;

  volatile uint64_t _35;
  Reg COP027;

  volatile uint64_t _36;
  Reg COP028;

  volatile uint64_t _37;
  Reg COP029;

  volatile uint64_t _38;
  Reg COP03;

  volatile uint64_t _39;
  Reg COP030;

  volatile uint64_t _40;
  Reg COP031;

  volatile uint64_t _41;
  Reg COP04;

  volatile uint64_t _42;
  Reg COP05;

  volatile uint64_t _43;
  Reg COP06;

  volatile uint64_t _44;
  Reg COP07;

  volatile uint64_t _45;
  Reg COP08;

  volatile uint64_t _46;
  Reg COP09;

  volatile uint64_t _47;
  Reg COP20;

  volatile uint64_t _48;
  Reg COP21;

  volatile uint64_t _49;
  Reg COP210;

  volatile uint64_t _50;
  Reg COP211;

  volatile uint64_t _51;
  Reg COP212;

  volatile uint64_t _52;
  Reg COP213;

  volatile uint64_t _53;
  Reg COP214;

  volatile uint64_t _54;
  Reg COP215;

  volatile uint64_t _55;
  Reg COP216;

  volatile uint64_t _56;
  Reg COP217;

  volatile uint64_t _57;
  Reg COP218;

  volatile uint64_t _58;
  Reg COP219;

  volatile uint64_t _59;
  Reg COP22;

  volatile uint64_t _60;
  Reg COP220;

  volatile uint64_t _61;
  Reg COP221;

  volatile uint64_t _62;
  Reg COP222;

  volatile uint64_t _63;
  Reg COP223;

  volatile uint64_t _64;
  Reg COP224;

  volatile uint64_t _65;
  Reg COP225;

  volatile uint64_t _66;
  Reg COP226;

  volatile uint64_t _67;
  Reg COP227;

  volatile uint64_t _68;
  Reg COP228;

  volatile uint64_t _69;
  Reg COP229;

  volatile uint64_t _70;
  Reg COP23;

  volatile uint64_t _71;
  Reg COP230;

  volatile uint64_t _72;
  Reg COP231;

  volatile uint64_t _73;
  Reg COP24;

  volatile uint64_t _74;
  Reg COP25;

  volatile uint64_t _75;
  Reg COP26;

  volatile uint64_t _76;
  Reg COP27;

  volatile uint64_t _77;
  Reg COP28;

  volatile uint64_t _78;
  Reg COP29;

  volatile uint64_t _79;
  Reg COP30;

  volatile uint64_t _80;
  Reg COP31;

  volatile uint64_t _81;
  Reg COP310;

  volatile uint64_t _82;
  Reg COP311;

  volatile uint64_t _83;
  Reg COP312;

  volatile uint64_t _84;
  Reg COP313;

  volatile uint64_t _85;
  Reg COP314;

  volatile uint64_t _86;
  Reg COP315;

  volatile uint64_t _87;
  Reg COP316;

  volatile uint64_t _88;
  Reg COP317;

  volatile uint64_t _89;
  Reg COP318;

  volatile uint64_t _90;
  Reg COP319;

  volatile uint64_t _91;
  Reg COP32;

  volatile uint64_t _92;
  Reg COP320;

  volatile uint64_t _93;
  Reg COP321;

  volatile uint64_t _94;
  Reg COP322;

  volatile uint64_t _95;
  Reg COP323;

  volatile uint64_t _96;
  Reg COP324;

  volatile uint64_t _97;
  Reg COP325;

  volatile uint64_t _98;
  Reg COP326;

  volatile uint64_t _99;
  Reg COP327;

  volatile uint64_t _100;
  Reg COP328;

  volatile uint64_t _101;
  Reg COP329;

  volatile uint64_t _102;
  Reg COP33;

  volatile uint64_t _103;
  Reg COP330;

  volatile uint64_t _104;
  Reg COP331;

  volatile uint64_t _105;
  Reg COP34;

  volatile uint64_t _106;
  Reg COP35;

  volatile uint64_t _107;
  Reg COP36;

  volatile uint64_t _108;
  Reg COP37;

  volatile uint64_t _109;
  Reg COP38;

  volatile uint64_t _110;
  Reg COP39;

  volatile uint64_t _111;
  Reg D0;

  volatile uint64_t _112;
  Reg D0_64;

  volatile uint64_t _113;
  Reg D1;

  volatile uint64_t _114;
  Reg D10;

  volatile uint64_t _115;
  Reg D10_64;

  volatile uint64_t _116;
  Reg D11;

  volatile uint64_t _117;
  Reg D11_64;

  volatile uint64_t _118;
  Reg D12;

  volatile uint64_t _119;
  Reg D12_64;

  volatile uint64_t _120;
  Reg D13;

  volatile uint64_t _121;
  Reg D13_64;

  volatile uint64_t _122;
  Reg D14;

  volatile uint64_t _123;
  Reg D14_64;

  volatile uint64_t _124;
  Reg D15;

  volatile uint64_t _125;
  Reg D15_64;

  volatile uint64_t _126;
  Reg D16_64;

  volatile uint64_t _127;
  Reg D17_64;

  volatile uint64_t _128;
  Reg D18_64;

  volatile uint64_t _129;
  Reg D19_64;

  volatile uint64_t _130;
  Reg D1_64;

  volatile uint64_t _131;
  Reg D2;

  volatile uint64_t _132;
  Reg D20_64;

  volatile uint64_t _133;
  Reg D21_64;

  volatile uint64_t _134;
  Reg D22_64;

  volatile uint64_t _135;
  Reg D23_64;

  volatile uint64_t _136;
  Reg D24_64;

  volatile uint64_t _137;
  Reg D25_64;

  volatile uint64_t _138;
  Reg D26_64;

  volatile uint64_t _139;
  Reg D27_64;

  volatile uint64_t _140;
  Reg D28_64;

  volatile uint64_t _141;
  Reg D29_64;

  volatile uint64_t _142;
  Reg D2_64;

  volatile uint64_t _143;
  Reg D3;

  volatile uint64_t _144;
  Reg D30_64;

  volatile uint64_t _145;
  Reg D31_64;

  volatile uint64_t _146;
  Reg D3_64;

  volatile uint64_t _147;
  Reg D4;

  volatile uint64_t _148;
  Reg D4_64;

  volatile uint64_t _149;
  Reg D5;

  volatile uint64_t _150;
  Reg D5_64;

  volatile uint64_t _151;
  Reg D6;

  volatile uint64_t _152;
  Reg D6_64;

  volatile uint64_t _153;
  Reg D7;

  volatile uint64_t _154;
  Reg D7_64;

  volatile uint64_t _155;
  Reg D8;

  volatile uint64_t _156;
  Reg D8_64;

  volatile uint64_t _157;
  Reg D9;

  volatile uint64_t _158;
  Reg D9_64;

  volatile uint64_t _159;
  Reg DSPCCond;

  volatile uint64_t _160;
  Reg DSPCarry;

  volatile uint64_t _161;
  Reg DSPEFI;

  volatile uint64_t _162;
  Reg DSPOutFlag;

  volatile uint64_t _163;
  Reg DSPOutFlag16_19;

  volatile uint64_t _164;
  Reg DSPOutFlag20;

  volatile uint64_t _165;
  Reg DSPOutFlag21;

  volatile uint64_t _166;
  Reg DSPOutFlag22;

  volatile uint64_t _167;
  Reg DSPOutFlag23;

  volatile uint64_t _168;
  Reg DSPPos;

  volatile uint64_t _169;
  Reg DSPSCount;

  volatile uint64_t _170;
  Reg F0;

  volatile uint64_t _171;
  Reg F1;

  volatile uint64_t _172;
  Reg F10;

  volatile uint64_t _173;
  Reg F11;

  volatile uint64_t _174;
  Reg F12;

  volatile uint64_t _175;
  Reg F13;

  volatile uint64_t _176;
  Reg F14;

  volatile uint64_t _177;
  Reg F15;

  volatile uint64_t _178;
  Reg F16;

  volatile uint64_t _179;
  Reg F17;

  volatile uint64_t _180;
  Reg F18;

  volatile uint64_t _181;
  Reg F19;

  volatile uint64_t _182;
  Reg F2;

  volatile uint64_t _183;
  Reg F20;

  volatile uint64_t _184;
  Reg F21;

  volatile uint64_t _185;
  Reg F22;

  volatile uint64_t _186;
  Reg F23;

  volatile uint64_t _187;
  Reg F24;

  volatile uint64_t _188;
  Reg F25;

  volatile uint64_t _189;
  Reg F26;

  volatile uint64_t _190;
  Reg F27;

  volatile uint64_t _191;
  Reg F28;

  volatile uint64_t _192;
  Reg F29;

  volatile uint64_t _193;
  Reg F3;

  volatile uint64_t _194;
  Reg F30;

  volatile uint64_t _195;
  Reg F31;

  volatile uint64_t _196;
  Reg F4;

  volatile uint64_t _197;
  Reg F5;

  volatile uint64_t _198;
  Reg F6;

  volatile uint64_t _199;
  Reg F7;

  volatile uint64_t _200;
  Reg F8;

  volatile uint64_t _201;
  Reg F9;

  volatile uint64_t _202;
  Reg FCC0;

  volatile uint64_t _203;
  Reg FCC1;

  volatile uint64_t _204;
  Reg FCC2;

  volatile uint64_t _205;
  Reg FCC3;

  volatile uint64_t _206;
  Reg FCC4;

  volatile uint64_t _207;
  Reg FCC5;

  volatile uint64_t _208;
  Reg FCC6;

  volatile uint64_t _209;
  Reg FCC7;

  volatile uint64_t _210;
  Reg FCR0;

  volatile uint64_t _211;
  Reg FCR1;

  volatile uint64_t _212;
  Reg FCR10;

  volatile uint64_t _213;
  Reg FCR11;

  volatile uint64_t _214;
  Reg FCR12;

  volatile uint64_t _215;
  Reg FCR13;

  volatile uint64_t _216;
  Reg FCR14;

  volatile uint64_t _217;
  Reg FCR15;

  volatile uint64_t _218;
  Reg FCR16;

  volatile uint64_t _219;
  Reg FCR17;

  volatile uint64_t _220;
  Reg FCR18;

  volatile uint64_t _221;
  Reg FCR19;

  volatile uint64_t _222;
  Reg FCR2;

  volatile uint64_t _223;
  Reg FCR20;

  volatile uint64_t _224;
  Reg FCR21;

  volatile uint64_t _225;
  Reg FCR22;

  volatile uint64_t _226;
  Reg FCR23;

  volatile uint64_t _227;
  Reg FCR24;

  volatile uint64_t _228;
  Reg FCR25;

  volatile uint64_t _229;
  Reg FCR26;

  volatile uint64_t _230;
  Reg FCR27;

  volatile uint64_t _231;
  Reg FCR28;

  volatile uint64_t _232;
  Reg FCR29;

  volatile uint64_t _233;
  Reg FCR3;

  volatile uint64_t _234;
  Reg FCR30;

  volatile uint64_t _235;
  Reg FCR31;

  volatile uint64_t _236;
  Reg FCR4;

  volatile uint64_t _237;
  Reg FCR5;

  volatile uint64_t _238;
  Reg FCR6;

  volatile uint64_t _239;
  Reg FCR7;

  volatile uint64_t _240;
  Reg FCR8;

  volatile uint64_t _241;
  Reg FCR9;

  volatile uint64_t _242;
  Reg FP;

  volatile uint64_t _243;
  Reg FP_64;

  volatile uint64_t _244;
  Reg F_HI0;

  volatile uint64_t _245;
  Reg F_HI1;

  volatile uint64_t _246;
  Reg F_HI10;

  volatile uint64_t _247;
  Reg F_HI11;

  volatile uint64_t _248;
  Reg F_HI12;

  volatile uint64_t _249;
  Reg F_HI13;

  volatile uint64_t _250;
  Reg F_HI14;

  volatile uint64_t _251;
  Reg F_HI15;

  volatile uint64_t _252;
  Reg F_HI16;

  volatile uint64_t _253;
  Reg F_HI17;

  volatile uint64_t _254;
  Reg F_HI18;

  volatile uint64_t _255;
  Reg F_HI19;

  volatile uint64_t _256;
  Reg F_HI2;

  volatile uint64_t _257;
  Reg F_HI20;

  volatile uint64_t _258;
  Reg F_HI21;

  volatile uint64_t _259;
  Reg F_HI22;

  volatile uint64_t _260;
  Reg F_HI23;

  volatile uint64_t _261;
  Reg F_HI24;

  volatile uint64_t _262;
  Reg F_HI25;

  volatile uint64_t _263;
  Reg F_HI26;

  volatile uint64_t _264;
  Reg F_HI27;

  volatile uint64_t _265;
  Reg F_HI28;

  volatile uint64_t _266;
  Reg F_HI29;

  volatile uint64_t _267;
  Reg F_HI3;

  volatile uint64_t _268;
  Reg F_HI30;

  volatile uint64_t _269;
  Reg F_HI31;

  volatile uint64_t _270;
  Reg F_HI4;

  volatile uint64_t _271;
  Reg F_HI5;

  volatile uint64_t _272;
  Reg F_HI6;

  volatile uint64_t _273;
  Reg F_HI7;

  volatile uint64_t _274;
  Reg F_HI8;

  volatile uint64_t _275;
  Reg F_HI9;

  volatile uint64_t _276;
  Reg GP;

  volatile uint64_t _277;
  Reg GP_64;

  volatile uint64_t _278;
  Reg HI0;

  volatile uint64_t _279;
  Reg HI0_64;

  volatile uint64_t _280;
  Reg HI1;

  volatile uint64_t _281;
  Reg HI2;

  volatile uint64_t _282;
  Reg HI3;

  volatile uint64_t _283;
  Reg HWR0;

  volatile uint64_t _284;
  Reg HWR1;

  volatile uint64_t _285;
  Reg HWR10;

  volatile uint64_t _286;
  Reg HWR11;

  volatile uint64_t _287;
  Reg HWR12;

  volatile uint64_t _288;
  Reg HWR13;

  volatile uint64_t _289;
  Reg HWR14;

  volatile uint64_t _290;
  Reg HWR15;

  volatile uint64_t _291;
  Reg HWR16;

  volatile uint64_t _292;
  Reg HWR17;

  volatile uint64_t _293;
  Reg HWR18;

  volatile uint64_t _294;
  Reg HWR19;

  volatile uint64_t _295;
  Reg HWR2;

  volatile uint64_t _296;
  Reg HWR20;

  volatile uint64_t _297;
  Reg HWR21;

  volatile uint64_t _298;
  Reg HWR22;

  volatile uint64_t _299;
  Reg HWR23;

  volatile uint64_t _300;
  Reg HWR24;

  volatile uint64_t _301;
  Reg HWR25;

  volatile uint64_t _302;
  Reg HWR26;

  volatile uint64_t _303;
  Reg HWR27;

  volatile uint64_t _304;
  Reg HWR28;

  volatile uint64_t _305;
  Reg HWR29;

  volatile uint64_t _306;
  Reg HWR3;

  volatile uint64_t _307;
  Reg HWR30;

  volatile uint64_t _308;
  Reg HWR31;

  volatile uint64_t _309;
  Reg HWR4;

  volatile uint64_t _310;
  Reg HWR5;

  volatile uint64_t _311;
  Reg HWR6;

  volatile uint64_t _312;
  Reg HWR7;

  volatile uint64_t _313;
  Reg HWR8;

  volatile uint64_t _314;
  Reg HWR9;

  volatile uint64_t _315;
  Reg K0;

  volatile uint64_t _316;
  Reg K0_64;

  volatile uint64_t _317;
  Reg K1;

  volatile uint64_t _318;
  Reg K1_64;

  volatile uint64_t _319;
  Reg LO0;

  volatile uint64_t _320;
  Reg LO0_64;

  volatile uint64_t _321;
  Reg LO1;

  volatile uint64_t _322;
  Reg LO2;

  volatile uint64_t _323;
  Reg LO3;

  volatile uint64_t _324;
  Reg MPL0;

  volatile uint64_t _325;
  Reg MPL1;

  volatile uint64_t _326;
  Reg MPL2;

  volatile uint64_t _327;
  Reg MSAAccess;

  volatile uint64_t _328;
  Reg MSACSR;

  volatile uint64_t _329;
  Reg MSAIR;

  volatile uint64_t _330;
  Reg MSAMap;

  volatile uint64_t _331;
  Reg MSAModify;

  volatile uint64_t _332;
  Reg MSARequest;

  volatile uint64_t _333;
  Reg MSASave;

  volatile uint64_t _334;
  Reg MSAUnmap;

  volatile uint64_t _335;
  Reg P0;

  volatile uint64_t _336;
  Reg P1;

  volatile uint64_t _337;
  Reg P2;

  volatile uint64_t _338;
  Reg PC;

  volatile uint64_t _339;
  Reg RA;

  volatile uint64_t _340;
  Reg RA_64;

  volatile uint64_t _341;
  Reg S0;

  volatile uint64_t _342;
  Reg S0_64;

  volatile uint64_t _343;
  Reg S1;

  volatile uint64_t _344;
  Reg S1_64;

  volatile uint64_t _345;
  Reg S2;

  volatile uint64_t _346;
  Reg S2_64;

  volatile uint64_t _347;
  Reg S3;

  volatile uint64_t _348;
  Reg S3_64;

  volatile uint64_t _349;
  Reg S4;

  volatile uint64_t _350;
  Reg S4_64;

  volatile uint64_t _351;
  Reg S5;

  volatile uint64_t _352;
  Reg S5_64;

  volatile uint64_t _353;
  Reg S6;

  volatile uint64_t _354;
  Reg S6_64;

  volatile uint64_t _355;
  Reg S7;

  volatile uint64_t _356;
  Reg S7_64;

  volatile uint64_t _357;
  Reg SP;

  volatile uint64_t _358;
  Reg SP_64;

  volatile uint64_t _359;
  Reg T0;

  volatile uint64_t _360;
  Reg T0_64;

  volatile uint64_t _361;
  Reg T1;

  volatile uint64_t _362;
  Reg T1_64;

  volatile uint64_t _363;
  Reg T2;

  volatile uint64_t _364;
  Reg T2_64;

  volatile uint64_t _365;
  Reg T3;

  volatile uint64_t _366;
  Reg T3_64;

  volatile uint64_t _367;
  Reg T4;

  volatile uint64_t _368;
  Reg T4_64;

  volatile uint64_t _369;
  Reg T5;

  volatile uint64_t _370;
  Reg T5_64;

  volatile uint64_t _371;
  Reg T6;

  volatile uint64_t _372;
  Reg T6_64;

  volatile uint64_t _373;
  Reg T7;

  volatile uint64_t _374;
  Reg T7_64;

  volatile uint64_t _375;
  Reg T8;

  volatile uint64_t _376;
  Reg T8_64;

  volatile uint64_t _377;
  Reg T9;

  volatile uint64_t _378;
  Reg T9_64;

  volatile uint64_t _379;
  Reg V0;

  volatile uint64_t _380;
  Reg V0_64;

  volatile uint64_t _381;
  Reg V1;

  volatile uint64_t _382;
  Reg V1_64;

  volatile uint64_t _383;
  Reg W0;

  volatile uint64_t _384;
  Reg W1;

  volatile uint64_t _385;
  Reg W10;

  volatile uint64_t _386;
  Reg W11;

  volatile uint64_t _387;
  Reg W12;

  volatile uint64_t _388;
  Reg W13;

  volatile uint64_t _389;
  Reg W14;

  volatile uint64_t _390;
  Reg W15;

  volatile uint64_t _391;
  Reg W16;

  volatile uint64_t _392;
  Reg W17;

  volatile uint64_t _393;
  Reg W18;

  volatile uint64_t _394;
  Reg W19;

  volatile uint64_t _395;
  Reg W2;

  volatile uint64_t _396;
  Reg W20;

  volatile uint64_t _397;
  Reg W21;

  volatile uint64_t _398;
  Reg W22;

  volatile uint64_t _399;
  Reg W23;

  volatile uint64_t _400;
  Reg W24;

  volatile uint64_t _401;
  Reg W25;

  volatile uint64_t _402;
  Reg W26;

  volatile uint64_t _403;
  Reg W27;

  volatile uint64_t _404;
  Reg W28;

  volatile uint64_t _405;
  Reg W29;

  volatile uint64_t _406;
  Reg W3;

  volatile uint64_t _407;
  Reg W30;

  volatile uint64_t _408;
  Reg W31;

  volatile uint64_t _409;
  Reg W4;

  volatile uint64_t _410;
  Reg W5;

  volatile uint64_t _411;
  Reg W6;

  volatile uint64_t _412;
  Reg W7;

  volatile uint64_t _413;
  Reg W8;

  volatile uint64_t _414;
  Reg W9;

  volatile uint64_t _415;
  Reg ZERO;

  volatile uint64_t _416;
  Reg ZERO_64;

  volatile uint64_t _417;
  Reg pc;

  volatile uint8_t _418[16];
} __attribute__((packed));

static_assert(6704 == sizeof(GPR), "Invalid structure packing of `GPR`.");

struct alignas(16) State final : public ArchState {
  // ArchState occupies 16 bytes.
  GPR gpr;  // 6704 bytes.
} __attribute__((packed));

static_assert((6704 + 16) == sizeof(State),
              "Invalid packing of `struct State`");

#pragma clang diagnostic pop

#endif  // REMILL_ARCH_MIPS_RUNTIME_STATE_H_
