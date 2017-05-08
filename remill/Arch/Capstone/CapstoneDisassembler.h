#ifndef REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_

#include <capstone/capstone.h>
#include <remill/Arch/Instruction.h>

#include <cstdint>
#include <memory>
#include <string>

namespace remill {

/// This is a cs_insn wrapper with an automatic deallocator (cs_free).
typedef std::unique_ptr<cs_insn, std::function<void(cs_insn *)>>
    CapstoneInstructionPtr;

/// This class is abstract and can't be used directly; you will have to inherit
/// from this and specialize it for your architecture
class CapstoneDisassembler {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  CapstoneDisassembler(const CapstoneDisassembler &other) = delete;
  CapstoneDisassembler &operator=(const CapstoneDisassembler &other) = delete;
  CapstoneDisassembler() = delete;

 public:
  CapstoneDisassembler(cs_arch architecture, cs_mode mode);
  virtual ~CapstoneDisassembler();

  /// decodes exactly one instruction from the specified buffer.
  bool Decode(const std::unique_ptr<Instruction> &remill_instr,
              uint64_t address, const std::string &instr_bytes) const noexcept;

  /// Disassembles the specified buffer trying to return exactly one opcode.
  CapstoneInstructionPtr Disassemble(std::uint64_t address,
                                     const std::uint8_t *buffer,
                                     std::size_t buffer_size) const noexcept;

  /**
    Converts a CapstoneInstruction to a remill::Instruction object.
    \param remill_instr The Remill's Instruction object. This is passed as an
    reference because the constructor is protected.
  */

  bool ConvertToRemillInstruction(
      const std::unique_ptr<Instruction> &remill_instr,
      const CapstoneInstructionPtr &capstone_instr) const noexcept;

  /// Returns the action type for the specified register.
  Operand::Action RegisterAccessType(
      unsigned int register_id,
      const CapstoneInstructionPtr &capstone_instr) const noexcept;

  //
  // Architecture-specific customizations
  //

  // Virtual functions
  // Override if the default implementation does not suffice.

  /// Returns the semantic function name for the specified instruction.
  virtual std::string SemanticFunctionName(
      const CapstoneInstructionPtr &capstone_instr,
      const std::vector<Operand> &operand_list) const noexcept;

  // Hooks
  // Hooks are mandatory and must be implemented.

 protected:
  /**
    This hook is called just after the instruction has been disassembled by
    capstone and before it is converted to remill::Instruction.
    \return True to continue processing the current instruction, or false to
    abort it.
  */

  virtual bool PostDisasmHook(
      const CapstoneInstructionPtr &capstone_instr) const noexcept = 0;

  /**
    This hook is called after the capstone instruction has been converted to
    remill::Instruction.
    \return True to continue processing the current instruction, or false to
    abort it.
  */

  virtual bool PostDecodeHook(
      const std::unique_ptr<Instruction> &remill_instr,
      const CapstoneInstructionPtr &capstone_instr) const noexcept = 0;

  // APIs
  // APIs are mandatory and must be implemented.
 public:
  /**
    This method is called when a register id needs to be converted to string.
    \return True to continue processing the current instruction, or false to
    abort it.
  */

  virtual bool RegisterName(std::string &name, std::uintmax_t id) const
      noexcept = 0;

  /**
    This method is called when the class needs to obtain the size of the
    specified register
    \return True to continue processing the current instruction, or false abort
    it.
  */

  virtual bool RegisterSize(std::size_t &size, const std::string &name) const
      noexcept = 0;

  /**
    This method is called when the disassembler needs the opcode operands
    \return True to continue processing the current instruction, or false to
    abort it.
  */

  virtual bool InstructionOperands(
      std::vector<Operand> &operand_list,
      const CapstoneInstructionPtr &capstone_instr) const noexcept = 0;

  /// Returns the address size, in bits
  virtual std::size_t AddressSize() const noexcept = 0;

  /// Returns the instruction category
  virtual Instruction::Category InstructionCategory(
      const CapstoneInstructionPtr &capstone_instr) const noexcept = 0;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_CAPSTONEDISASSEMBLER_H_
