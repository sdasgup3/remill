#include "ARMDisassembler.h"

namespace remill {

struct ARMDisassembler::PrivateData final {
  std::size_t address_size;
};

ARMDisassembler::ARMDisassembler(bool is_64_bits)
    : CapstoneDisassembler(is_64_bits ? CS_ARCH_ARM : CS_ARCH_ARM64,
                           is_64_bits ? CS_MODE_LITTLE_ENDIAN : CS_MODE_ARM),
      d(new PrivateData) {
  d->address_size = (is_64_bits ? 64 : 32);
}

ARMDisassembler::~ARMDisassembler() {}

std::string ARMDisassembler::RegisterName(std::uintmax_t id) const noexcept {
  return "";
}

bool ARMDisassembler::PostDisasmHook(
    const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

bool ARMDisassembler::PostDecodeHook(
    const std::unique_ptr<Instruction> &remill_instr,
    const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

bool ARMDisassembler::RegisterName(std::string &name, std::uintmax_t id) const
    noexcept {
  name = RegisterName(id);
  if (name.empty()) return false;

  return true;
}

bool ARMDisassembler::RegisterSize(std::size_t &size,
                                   const std::string &name) const noexcept {
  return false;
}

bool ARMDisassembler::InstructionOperands(
    std::vector<Operand> &operand_list,
    const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

std::size_t ARMDisassembler::AddressSize() const noexcept {
  return d->address_size;
}

Instruction::Category ARMDisassembler::InstructionCategory(
    const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return Instruction::kCategoryInvalid;
}

}  //  namespace remill
