#ifndef REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
#define REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_

#include "CapstoneDisassembler.h"

namespace remill {

class ARMDisassembler final : public CapstoneDisassembler {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  /// \todo thumb mode, endianness
  ARMDisassembler(bool is_64_bits);
  virtual ~ARMDisassembler();

 private:
  std::string RegName(std::uintmax_t reg_id) const noexcept;

  //
  // CapstoneDisassembler hook interface and APIs
  //
 protected:
  virtual bool PostDisasmHook(const CapInstrPtr &cap_instr) const noexcept;
  virtual bool PostDecodeHook(const std::unique_ptr<Instruction> &rem_instr,
                              const CapInstrPtr &cap_instr) const noexcept;

 public:
  virtual bool RegName(std::string &name, std::uintmax_t reg_id) const noexcept;
  virtual bool RegSize(std::size_t &size, const std::string &name) const
      noexcept;
  virtual bool InstrOps(std::vector<Operand> &op_list,
                        const CapInstrPtr &cap_instr) const noexcept;
  virtual std::size_t AddressSize() const noexcept;
  virtual Instruction::Category InstrCategory(
      const CapInstrPtr &cap_instr) const noexcept;

 private:
  ARMDisassembler &operator=(const ARMDisassembler &other) = delete;
  ARMDisassembler(const ARMDisassembler &other) = delete;
  ARMDisassembler() = delete;
};

}  // namespace remill

#endif  // REMILL_ARCH_CAPSTONE_ARMDISASSEMBLER_H_
