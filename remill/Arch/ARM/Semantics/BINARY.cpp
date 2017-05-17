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

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsIncDec(State &state, T lhs, T rhs, T res) {
  FLAG_ZF = ZeroFlag(res);
  FLAG_NF = SignFlag(res);
  FLAG_VF = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsAddSub(State &state, T lhs, T rhs, T res) {
  FLAG_CF = Carry<Tag>::Flag(lhs, rhs, res);
  WriteFlagsIncDec<Tag>(state, lhs, rhs, res);
}
}

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  // TODO: Assuming the instruction condition is AL
  // S bit is disabled; flags will not get updated
  // TODO: how to check sub_op bit from instruction?
  // Carry depends on sub_op bits (bit[30])
  WriteZExt(dst, sum);
  return memory;
}


template <typename D, typename S1, typename S2>
DEF_SEM(SUB, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = USub(lhs, rhs);
  // TODO: Assuming the instruction condition is AL
  // S bit is disabled; flags will not get updated
  // TODO: how to check sub_op bit from instruction?
  // Carry depends on sub_op bits (bit[30])
  WriteZExt(dst, sum);
  return memory;
}

}

DEF_ISEL(ADD_R64_R64_R64) = ADD<R64W, R64, R64>;
DEF_ISEL(ADD_R32_R32_R32) = ADD<R32W, R32, R32>;
DEF_ISEL(ADD_R64_R64_I64) = ADD<R64W, R64, I64>;

DEF_ISEL(SUB_R64_R64_R64) = SUB<R64W, R64, R64>;
DEF_ISEL(SUB_R32_R32_R32) = SUB<R32W, R32, R32>;
DEF_ISEL(SUB_R64_R64_I64) = SUB<R64W, R64, I64>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(ASR, D dst, S1 src1, S2 src2) {
  static_cast<void>(dst);
  static_cast<void>(src1);
  static_cast<void>(src2);
  return memory;
}

}

DEF_ISEL(ASR_R64_R64_I64) = ASR<R64W, R64, I64>;

namespace {

template <typename TagT, typename T>
ALWAYS_INLINE static bool CarryFlag(T a, T b, T ab, T c, T abc) {
  static_assert(std::is_unsigned<T>::value, "Invalid specialization of `CarryFlag` for addition.");
  return Carry<TagT>::Flag(a, b, ab) || Carry<TagT>::Flag(ab, c, abc);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADC, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  WriteZExt(dst, res);
  Write(FLAG_CF, CarryFlag<tag_add>(lhs, rhs, sum, carry, res));
  WriteFlagsIncDec<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SBB, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto borrow = ZExtTo<S1>(Unsigned(Read(FLAG_CF)));
  auto sum = USub(lhs, rhs);
  auto res = USub(sum, borrow);
  WriteZExt(dst, res);
  Write(FLAG_CF, CarryFlag<tag_sub>(lhs, rhs, sum, borrow, res));
  WriteFlagsIncDec<tag_sub>(state, lhs, rhs, res);
  return memory;
}

}  // namespace

namespace {

template <typename S1, typename S2>
DEF_SEM(CMP, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = USub(lhs, rhs);
  WriteFlagsAddSub<tag_sub>(state, lhs, rhs, sum);
  return memory;
}

template <typename S1, typename S2>
DEF_SEM(CMPS, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = USub(lhs, rhs);
  WriteFlagsAddSub<tag_sub>(state, lhs, rhs, sum);
  return memory;
}

template <typename S1, typename S2>
DEF_SEM(CBZ, S1 src1, S2 src2) {
  static_cast<void>(src1);
  static_cast<void>(src2);
  return memory;
}

template <typename S1, typename S2>
DEF_SEM(CBNZ, S1 src1, S2 src2) {
  static_cast<void>(src1);
  static_cast<void>(src2);
  return memory;
}

}  // namespace

DEF_ISEL(CMP_R64_R64) = CMP<R64, R64>;
DEF_ISEL(CMP_R64_I64) = CMP<R64, I64>;

DEF_ISEL(CMPS_R64_R64) = CMPS<R64, R64>;
DEF_ISEL(CMPS_R64_I64) = CMPS<R64, I64>;
DEF_ISEL(CBZ_R64_I64) = CBZ<R64, I64>;
DEF_ISEL(CBNZ_R64_I64) = CBNZ<R64, I64>;
DEF_ISEL(CBNZ_R32_I32) = CBNZ<R32, I32>;

DEF_ISEL(ADRP_R64_I64) = SUB<R64W, R64, I64>;
DEF_ISEL(SUB_R64_R64) = SUB<R64W, R64, R64>;
