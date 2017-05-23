#ifndef REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_

#include "CapstoneDisassembler.h"

namespace remill {

class ARMDisassembler final : public CapstoneDisassembler {
 public:
  ARMDisassembler(bool is_64_bits);
  virtual ~ARMDisassembler();

  void EnableThumbMode(bool enabled) noexcept;

 private:
  std::string RegName(std::uintmax_t reg_id) const noexcept;
  std::string InstructionPredicate(const CapInstrPtr &caps_instr) const
      noexcept;

  //
  // CapstoneDisassembler hook interface and APIs
  //
 protected:
  virtual bool PostDisasmHook(const CapInstrPtr &cap_instr) const
      noexcept override;
  virtual bool PostDecodeHook(const std::unique_ptr<Instruction> &rem_instr,
                              const CapInstrPtr &cap_instr) const
      noexcept override;

 public:
  virtual bool RegName(std::string &name, std::uintmax_t reg_id) const
      noexcept override;
  virtual bool RegSize(std::size_t &size, const std::string &name) const
      noexcept override;
  virtual bool InstrOps(std::vector<Operand> &op_list,
                        const CapInstrPtr &cap_instr) const noexcept override;
  virtual std::size_t AddressSize() const noexcept override;
  virtual Instruction::Category InstrCategory(
      const CapInstrPtr &cap_instr) const noexcept override;

  virtual std::string SemFuncName(const CapInstrPtr &cap_instr,
                                  const std::vector<Operand> &op_list) const
      noexcept override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ARMDisassembler &operator=(const ARMDisassembler &other) = delete;
  ARMDisassembler(const ARMDisassembler &other) = delete;
  ARMDisassembler() = delete;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
