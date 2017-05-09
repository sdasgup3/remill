#include "ARMDisassembler.h"

namespace remill {

struct ARMDisassembler::PrivateData final {
  std::size_t address_size;
};

/// \todo this looks horrible
ARMDisassembler::ARMDisassembler(bool is_64_bits, bool thumb_mode)
    : CapstoneDisassembler(is_64_bits ? CS_ARCH_ARM64 : CS_ARCH_ARM,
                           is_64_bits
                               ? CS_MODE_LITTLE_ENDIAN
                               : thumb_mode ? CS_MODE_THUMB : CS_MODE_ARM),
      d(new PrivateData) {
  d->address_size = (is_64_bits ? 64 : 32);
}

ARMDisassembler::~ARMDisassembler() {}

std::string ARMDisassembler::RegName(std::uintmax_t reg_id) const noexcept {
  return "";
}

bool ARMDisassembler::PostDisasmHook(const CapInstrPtr &cap_instr) const
    noexcept {
  return true;
}

bool ARMDisassembler::PostDecodeHook(
    const std::unique_ptr<Instruction> &rem_instr,
    const CapInstrPtr &cap_instr) const noexcept {
  return true;
}

bool ARMDisassembler::RegName(std::string &name, std::uintmax_t reg_id) const
    noexcept {
  name = RegName(reg_id);
  if (name.empty()) return false;

  return true;
}

bool ARMDisassembler::RegSize(std::size_t &size, const std::string &name) const
    noexcept {
  return true;
}

/// \todo this is the bare minimum to get 'testdec' to work
bool ARMDisassembler::InstrOps(std::vector<Operand> &op_list,
                               const CapInstrPtr &cap_instr) const noexcept {
  Operand op = {};
  op.type = Operand::kTypeImmediate;
  op.imm.is_signed = false;

  // arm
  if (d->address_size == 32) {
    auto instr_details = cap_instr->detail->arm;
    if (instr_details.op_count == 1 &&
        instr_details.operands[0].type == ARM_OP_IMM) {
      op.imm.val = instr_details.operands[0].imm;
    }

    // arm64
  } else {
    auto instr_details = cap_instr->detail->arm64;
    if (instr_details.op_count == 1 &&
        instr_details.operands[0].type == ARM64_OP_IMM)
      op.imm.val = instr_details.operands[0].imm;
  }

  if (op.imm.val != 0) op_list.push_back(op);

  return true;
}

std::size_t ARMDisassembler::AddressSize() const noexcept {
  return d->address_size;
}

Instruction::Category ARMDisassembler::InstrCategory(
    const CapInstrPtr &cap_instr) const noexcept {
  // arm
  if (d->address_size == 32) {
    auto instr_details = cap_instr->detail->arm;

    if (cap_instr->id == ARM_INS_BL || cap_instr->id == ARM_INS_BLX)
      return Instruction::kCategoryDirectFunctionCall;

    else if (cap_instr->id == ARM_INS_BX &&
             instr_details.operands[0].type == ARM_OP_REG &&
             instr_details.operands[0].reg == ARM_REG_LR)
      return Instruction::kCategoryFunctionReturn;

    // arm64
  } else {
    if (cap_instr->id == ARM64_INS_BL)
      return Instruction::kCategoryDirectFunctionCall;

    else if (cap_instr->id == ARM64_INS_RET)
      return Instruction::kCategoryFunctionReturn;
  }
  return Instruction::kCategoryInvalid;
}

}  //  namespace remill
