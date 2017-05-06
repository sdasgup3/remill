#ifndef REMILL_ARCH_MIPS_DISASSEMBLER_H_
#define REMILL_ARCH_MIPS_DISASSEMBLER_H_

#include <capstone/capstone.h>
#include <remill/Arch/Instruction.h>

#include <memory>
#include <string>
#include <cstdint>

namespace remill {

/// This is a cs_insn wrapper with an automatic deallocator (cs_free).
typedef std::unique_ptr<cs_insn, std::function<void (cs_insn *)>> CapstoneInstruction;

class MipsDisassembler final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  MipsDisassembler(const MipsDisassembler &other) = delete;
  MipsDisassembler &operator=(const MipsDisassembler &other) = delete;
  MipsDisassembler() = delete;

public:
  MipsDisassembler(bool mips64);
  ~MipsDisassembler();

  /// returns the specified register name.
  std::string RegisterName(unsigned int id) const noexcept;

  /// returns the specified register id.
  unsigned int RegisterId(const std::string &name) const noexcept;

  /// decodes exactly one instruction from the specified buffer.
  bool Decode(const std::unique_ptr<Instruction> &remill_instr, uint64_t address, const std::string &instr_bytes) const noexcept;

  /// Disassembles the specified buffer trying to return exactly one opcode.
  CapstoneInstruction Disassemble(std::uint64_t address, const std::uint8_t *buffer, std::size_t buffer_size) const noexcept;

  /// Returns the semantic function name for the specified instruction.
  std::string SemanticFunctionName(const CapstoneInstruction &capstone_instr) const noexcept;

  /**
    Converts a CapstoneInstruction to a remill::Instruction object.
    \param remill_instr The Remill's Instruction object. This is passed as an reference because the constructor is protected.
  */

  bool ConvertToRemillInstruction(const std::unique_ptr<Instruction> &remill_instr, const CapstoneInstruction &capstone_instr) const noexcept;

  /// Returns the Remill's instruction category.
  Instruction::Category InstructionCategory(const CapstoneInstruction &capstone_instr) const noexcept;

  /// returns the action type for the specified register.
  Operand::Action RegisterAccessType(unsigned int register_id, const CapstoneInstruction &capstone_instr) const noexcept;
};

}  // namespace remill

#endif  // REMILL_ARCH_MIPS_DISASSEMBLER_H_
