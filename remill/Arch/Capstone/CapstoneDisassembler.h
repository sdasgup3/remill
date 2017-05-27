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

#ifndef REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_

#include <capstone/capstone.h>
#include <remill/Arch/Instruction.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace remill {

/// This is a cs_insn wrapper with an automatic deallocator (cs_free).
typedef std::unique_ptr<cs_insn, std::function<void(cs_insn *)>> CapInstrPtr;

// Wrapper around a `remill::Instruction`.
typedef std::unique_ptr<remill::Instruction> RemInstrPtr;

/// This class is abstract and can't be used directly; you will have to inherit
/// from this and specialize it for your architecture
class CapstoneDisassembler {
 public:
  CapstoneDisassembler(cs_arch arch, cs_mode mode);

  virtual ~CapstoneDisassembler(void);

  /// Decodes exactly one instruction from the specified buffer.
  void Decode(const RemInstrPtr &rem_instr, uint64_t vaddr,
              const std::string &instr_bytes) const;

  /// Disassembles the specified buffer trying to return exactly one opcode.
  CapInstrPtr Disassemble(std::uint64_t vaddr, const std::uint8_t *buf,
                          std::size_t size) const;

  /**
    Converts a CapstoneInstruction to a remill::Instruction object.
    \param rem_instr The Remill's Instruction object. This is passed as an
    reference because the constructor is protected.
  */

  void ConvertToRemInstr(const RemInstrPtr &rem_instr,
                         const CapInstrPtr &cap_instr) const;

  virtual bool CanReadRegister(const CapInstrPtr &cap_instr, uint64_t reg_id,
                               unsigned op_num) const = 0;

  virtual bool CanWriteRegister(const CapInstrPtr &cap_instr, uint64_t reg_id,
                                unsigned op_num) const = 0;

  //
  // Architecture-specific customizations
  //

  // Virtual functions
  // Override if the default implementation does not suffice.

  /// Returns the semantic function name for the specified instruction.
  virtual std::string SemFuncName(
      const RemInstrPtr &rem_instr,
      const CapInstrPtr &cap_instr) const = 0;

  // Hooks
  // Hooks are mandatory and must be implemented.

 protected:
  /// returns the capstone handle
  csh GetCapstoneHandle(void) const;

  // APIs
  // APIs are mandatory and must be implemented.
 public:
  /**
    This method is called when a register id needs to be converted to string.
  */

  virtual std::string RegName(uint64_t reg_id) const = 0;

  /**
    This method is called when the class needs to obtain the size of the
    specified register.
  */

  virtual uint64_t RegSize(uint64_t reg_id) const = 0;

  /**
    This method is called when the disassembler needs the opcode operands
    \return True to continue processing the current instruction, or false to
    abort it.
  */

  virtual void FillInstrOps(
      const RemInstrPtr &rem_instr,
      const CapInstrPtr &cap_instr) const = 0;

  /// Returns the address size, in bits
  virtual std::size_t AddressSize(void) const = 0;

  /// Returns the instruction category
  virtual Instruction::Category InstrCategory(
      const CapInstrPtr &cap_instr) const = 0;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  CapstoneDisassembler(const CapstoneDisassembler &other) = delete;
  CapstoneDisassembler &operator=(const CapstoneDisassembler &other) = delete;
  CapstoneDisassembler(void) = delete;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_
