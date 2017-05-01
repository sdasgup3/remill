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

#ifndef REMILL_ARCH_MIPS_ARCH_H_
#define REMILL_ARCH_MIPS_ARCH_H_

#include "remill/Arch/Arch.h"
#include <memory>
#include <capstone/capstone.h>

namespace remill {

class MipsArch : public Arch {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  MipsArch(OSName os_name_, ArchName arch_name_);
  MipsArch(void) = delete;
  virtual ~MipsArch(void);

  //
  // remill::Arch interface
  //

  void PrepareModule(llvm::Module *mod) const override;
  uint64_t ProgramCounter(const ArchState *state) const override;
  Instruction *DecodeInstruction(uint64_t address, const std::string &instr_bytes) const override;

 private:
  /// This is a cs_insn wrapper with an automatic releaser (cs_free)
  typedef std::unique_ptr<cs_insn, std::function<void (cs_insn *)>> CapstoneInstruction;

  /// Disassembles the specified buffer trying to return exactly one opcode.
  CapstoneInstruction DisassembleInstruction(std::uint64_t address, const std::string &buffer) const noexcept;

  /// Generates the semantic function name associated with the Capstone instruction by enumerating the operand types.
  std::string GetSemanticFunctionName(const CapstoneInstruction &capstone_instr) const noexcept;

  /// Converts the specified instruction to string
  bool ConvertToRemillInstruction(const std::unique_ptr<remill::Instruction> &remill_instr, const CapstoneInstruction &capstone_instr) const noexcept;

  /// Returns the instruction category (see Instruction::Category) used by Remill to understand how the instruction should behave.
  Instruction::Category GetCapstoneInstructionCategory(const CapstoneInstruction &capstone_instr) const noexcept;

  // Fills the given vector with the instruction operands
  bool GetCapstoneInstructionOperands(const CapstoneInstruction &capstone_instr, std::vector<remill::Operand> &operands) const noexcept;
};

}  // namespace remill

#endif  // REMILL_ARCH_MIPS_ARCH_H_
