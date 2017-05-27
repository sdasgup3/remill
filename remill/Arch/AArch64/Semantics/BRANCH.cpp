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

static inline bool CondGE(const State &state) {
  return UCmpNeq(state.state.GE, 0);
}

static inline bool CondLT(const State &state) {
  return !CondGE(state);
}

static inline bool CondEQ(const State &state) {
  return UCmpNeq(state.state.Z, 0);
}

static inline bool CondGT(const State &state) {
  return CondGE(state) && !CondEQ(state);
}

static inline bool CondLE(const State &state) {
  return CondLT(state) || CondEQ(state);
}

static inline bool CondCS(const State &state) {
  return UCmpNeq(state.state.C, 0);
}

static inline bool CondMI(const State &state) {
  return UCmpNeq(state.state.N, 0);
}

static inline bool CondVS(const State &state) {
  return UCmpNeq(state.state.V, 0);
}

static inline bool CondHI(const State &state) {
  return CondCS(state) && !CondEQ(state);
}

template <bool (*check_cond)(const State &)>
static bool NotCond(const State &state) {
  return !check_cond(state);
}

}  // namespace

DEF_COND(GE) = CondGE;
DEF_COND(GT) = CondGT;
DEF_COND(LE) = CondLE;
DEF_COND(LT) = CondLT;

DEF_COND(EQ) = CondEQ;
DEF_COND(NE) = NotCond<CondEQ>;

DEF_COND(CS) = CondCS;
DEF_COND(CC) = NotCond<CondCS>;

DEF_COND(MI) = CondMI;
DEF_COND(PL) = NotCond<CondMI>;

DEF_COND(VS) = CondVS;
DEF_COND(VC) = NotCond<CondVS>;

DEF_COND(HI) = CondHI;
DEF_COND(LS) = NotCond<CondHI>;

namespace {

DEF_SEM(DoDirectBranch, PC target_pc) {
  Write(REG_PC, Read(target_pc));
  return memory;
}

DEF_SEM(DoIndirectBranch, R64W, PC dst) {
  Write(REG_PC, Read(dst));
  return memory;
}

template <bool (*check_cond)(const State &)>
DEF_SEM(DirectCondBranch, R8W cond, PC taken, PC not_taken) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  auto take_branch = check_cond(state);
  Write(cond, take_branch);
  Write(REG_PC, Select<addr_t>(take_branch, taken_pc, not_taken_pc));
  return memory;
}

}  // namespace

DEF_ISEL(B_U64) = DoDirectBranch;

DEF_ISEL(B_LS_R8W_U64_U64) = DirectCondBranch<NotCond<CondHI>>;

DEF_ISEL(B_EQ_R8W_U64_U64) = DirectCondBranch<CondEQ>;
DEF_ISEL(B_NE_R8W_U64_U64) = DirectCondBranch<NotCond<CondEQ>>;

DEF_ISEL(B_GE_R8W_U64_U64) = DirectCondBranch<CondGE>;
DEF_ISEL(B_GT_R8W_U64_U64) = DirectCondBranch<CondGT>;

DEF_ISEL(B_LE_R8W_U64_U64) = DirectCondBranch<CondLE>;
DEF_ISEL(B_LT_R8W_U64_U64) = DirectCondBranch<CondLT>;

DEF_ISEL(BR_R64W_R64) = DoIndirectBranch;

namespace {

DEF_SEM(DoCall, PC target, PC return_addr) {
  Write(REG_PC, Read(target));
  Write(REG_LP, Read(return_addr));
  return memory;
}

}  // namespace

DEF_ISEL(BL_U64_U64) = DoCall;
