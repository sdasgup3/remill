#ifndef REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_

#include "CapstoneDisassembler.h"

namespace remill {

class ARMDisassembler final : public CapstoneDisassembler {

  ARMDisassembler &operator=(const ARMDisassembler &other) = delete;
  ARMDisassembler(const ARMDisassembler &other) = delete;
  ARMDisassembler() = delete;

public:
  // TODO: thumb mode, endianness
  ARMDisassembler(bool is_64_bits);
  virtual ~ARMDisassembler();

  // Decode ARM instructions one at a time.
  bool Decode(const std::unique_ptr<Instruction> &remill_instr, uint64_t address, const std::string &instr_bytes) const noexcept;
  bool ConvertToRemillInstruction(const std::unique_ptr<Instruction> &remill_instr, const CapstoneInstructionPtr &caps_instr) const noexcept;
  std::string SemanticFunctionName(const CapstoneInstructionPtr &caps_instr, const std::vector<Operand> &operand_list) const noexcept;
  bool DecodeOperands(const CapstoneInstructionPtr &caps_instr, std::vector<Operand> &oprnds) const noexcept;

  std::string InstructionPredicate(const CapstoneInstructionPtr &caps_instr) const noexcept;
  bool  DecodeOpBits(const CapstoneInstructionPtr &cap_instr) const noexcept;
public:
  virtual bool RegisterSize(std::size_t &size, const std::string &name) const noexcept;
  virtual bool InstructionOperands(std::vector<Operand> &operand_list, const CapstoneInstructionPtr &capstone_instr) const noexcept;
  virtual std::size_t AddressSize() const noexcept;
  virtual Instruction::Category InstructionCategory(const CapstoneInstructionPtr &capstone_instr) const noexcept;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
