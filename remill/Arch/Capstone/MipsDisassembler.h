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

#ifndef REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_

#include <memory>
#include <string>
#include <vector>

#include "remill/Arch/Capstone/CapstoneDisassembler.h"

namespace remill {

class MipsDisassembler final : public CapstoneDisassembler {
 public:
  explicit MipsDisassembler(bool is_64_bits);
  virtual ~MipsDisassembler();

 private:

  //
  // CapstoneDisassembler hook interface and APIs
  //
 protected:
  std::string SemFuncName(
      const CapInstrPtr &cap_instr,
      const std::vector<Operand> &op_list) const override;

 public:

  std::string RegName(uint64_t reg_id) const override;
  uint64_t RegSize(uint64_t reg_id) const override;

  std::vector<Operand> InstrOps(const CapInstrPtr &cap_instr) const override;
  std::size_t AddressSize(void) const override;
  Instruction::Category InstrCategory(
      const CapInstrPtr &cap_instr) const override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  MipsDisassembler &operator=(const MipsDisassembler &other) = delete;
  MipsDisassembler(const MipsDisassembler &other) = delete;
  MipsDisassembler(void) = delete;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_
