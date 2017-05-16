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

// Zero flags, tells us whether or not a value is zero.
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool ZeroFlag(T res) {
  return T(0) == res;
}

// Zero flags, tells us whether or not a value is zero.
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool NotZeroFlag(T res) {
  return T(0) != res;
}

// Sign flag, tells us if a result is signed or unsigned.
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool SignFlag(T res) {
  return 0 > Signed(res);
}

// Auxiliary carry flag. This is used for binary coded decimal operations and
// is the 5th bit (where each binary decimal is 4 bits).
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool AuxCarryFlag(T lhs, T rhs, T res) {
  return ((res ^ lhs ^ rhs) & T(0x10));
}

// Auxiliary carry flag. This is used for binary coded decimal operations and
// is the 5th bit (where each binary decimal is 4 bits).
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool AuxCarryFlag(T lhs, T rhs, T carry, T res) {
  return ((res ^ lhs ^ carry ^ rhs) & T(0x10));
}


struct tag_add {};
struct tag_sub {};
struct tag_div {};
struct tag_mul {};

// Generic overflow flag.
template <typename T>
struct Overflow;

// Computes an overflow flag when two numbers are added together.
template <>
struct Overflow<tag_add> {
  template <typename T>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for addition.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_res) + (sign_rhs ^ sign_res);
  }
};


// Computes an overflow flag when one number is subtracted from another.
template <>
struct Overflow<tag_sub> {
  template <typename T>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
  static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for "
                  "subtraction.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_rhs) + (sign_lhs ^ sign_res);
  }
};

// Computes an overflow flag when one number is multiplied with another.
template <>
struct Overflow<tag_mul> {

  // Integer multiplication overflow check, where result is twice the width of
  // the operands.
  template <typename T, typename R>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(
      T, T, R res,
      typename std::enable_if<sizeof(T) < sizeof(R),int>::type=0) {

    return static_cast<R>(static_cast<T>(res)) != res;
  }

  // Signed integer multiplication overflow check, where the result is
  // truncated to the size of the operands.
  template <typename T>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(
      T lhs, T rhs, T,
      typename std::enable_if<std::is_signed<T>::value,int>::type=0) {
    auto lhs_wide = SExt(lhs);
    auto rhs_wide = SExt(rhs);
    return Flag<T, decltype(lhs_wide)>(lhs, rhs, lhs_wide * rhs_wide);
  }
};

// Generic carry flag.
template <typename Tag>
struct Carry;

// Computes an carry flag when two numbers are added together.
template <>
struct Carry<tag_add> {
  template <typename T>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    return res < lhs || res < rhs;
  }
};

// Computes an carry flag when one number is subtracted from another.
template <>
struct Carry<tag_sub> {
  template <typename T>
  [[gnu::const]]
  ALWAYS_INLINE static bool Flag(T lhs, T rhs, T) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    return lhs < rhs;
  }
};

}

#define ClearArithFlags() \
    do { \
      state.sflag.nf = __remill_undefined_8(); \
      state.sflag.zf = __remill_undefined_8(); \
      state.sflag.cf = __remill_undefined_8(); \
      state.sflag.vf = __remill_undefined_8(); \
    } while (false)



