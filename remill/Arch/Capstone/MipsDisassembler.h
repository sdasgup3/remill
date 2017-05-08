#ifndef REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_

#include "CapstoneDisassembler.h"

namespace remill {

class MipsDisassembler final : public CapstoneDisassembler {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  MipsDisassembler &operator=(const MipsDisassembler &other) = delete;
  MipsDisassembler(const MipsDisassembler &other) = delete;
  MipsDisassembler() = delete;

 public:
  MipsDisassembler(bool is_64_bits);
  virtual ~MipsDisassembler();

 private:
  std::string RegisterName(std::uintmax_t id) const noexcept;

  //
  // CapstoneDisassembler hook interface and APIs
  //
 protected:
  virtual bool PostDisasmHook(
      const CapstoneInstructionPtr &capstone_instr) const noexcept;
  virtual bool PostDecodeHook(
      const std::unique_ptr<Instruction> &remill_instr,
      const CapstoneInstructionPtr &capstone_instr) const noexcept;

 public:
  virtual bool RegisterName(std::string &name, std::uintmax_t id) const
      noexcept;
  virtual bool RegisterSize(std::size_t &size, const std::string &name) const
      noexcept;
  virtual bool InstructionOperands(
      std::vector<Operand> &operand_list,
      const CapstoneInstructionPtr &capstone_instr) const noexcept;
  virtual std::size_t AddressSize() const noexcept;
  virtual Instruction::Category InstructionCategory(
      const CapstoneInstructionPtr &capstone_instr) const noexcept;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_MIPSDISASSEMBLER_H_
