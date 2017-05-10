
#include <iostream>
#include <sstream>
#include <algorithm>
#include "ARMDisassembler.h"

#include <glog/logging.h>
#include <remill/Arch/Name.h>

namespace remill {

ARMDisassembler::ARMDisassembler(bool is_64_bits) :
    CapstoneDisassembler(is_64_bits ? CS_ARCH_ARM64 : CS_ARCH_ARM, CS_MODE_ARM)
{
  data_->address_space = (is_64_bits ? 64 : 32);
}

ARMDisassembler::~ARMDisassembler() {
}

std::string ARMDisassembler::RegisterName(std::uintmax_t id) const noexcept {
  return "";
}

bool ARMDisassembler::PostDisasmHook(const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

bool ARMDisassembler::PostDecodeHook(const std::unique_ptr<Instruction> &remill_instr, const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

bool ARMDisassembler::RegisterName(std::string &name, std::uintmax_t id) const noexcept {
  name = RegisterName(id);
  if (name.empty())
    return false;

  return true;
}

bool ARMDisassembler::RegisterSize(std::size_t &size, const std::string &name) const noexcept {
  return false;
}

bool ARMDisassembler::InstructionOperands(std::vector<Operand> &operand_list, const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

std::size_t
ARMDisassembler::AddressSize() const noexcept {
  return data_->address_space;
}

Instruction::Category
ARMDisassembler::InstructionCategory(const CapstoneInstructionPtr &cap_instr) const noexcept {
  if(data_->address_space == 32){
    if(cap_instr->id == ARM_INS_BL || cap_instr->id == ARM_INS_BLX)
      return Instruction::kCategoryDirectFunctionCall;

    else if (cap_instr->id == ARM_INS_BX)
      return Instruction::kCategoryFunctionReturn;

  } else if(data_->address_space == 64) {
    if(cap_instr->id == ARM64_INS_BL)
      return Instruction::kCategoryDirectFunctionCall;

    else if (cap_instr->id == ARM64_INS_RET)
      return Instruction::kCategoryFunctionReturn;

  }
  return Instruction::kCategoryNormal;
}

bool
ARMDisassembler::Decode(const std::unique_ptr<Instruction> &remill_instr, uint64_t address,
                        const std::string &instr_bytes) const noexcept {
  CapstoneInstructionPtr capstone_instr = Disassemble(address, reinterpret_cast<const std::uint8_t *>(instr_bytes.data()), instr_bytes.size());
  if (!capstone_instr) return false;

  if (!ConvertToRemillInstruction(remill_instr, capstone_instr))
    return false;

  return true;
}


bool ARMDisassembler::ConvertToRemillInstruction(const std::unique_ptr<remill::Instruction> &remill_instr, const CapstoneInstructionPtr &capstone_instr) const noexcept {
  std::stringstream disassembly;

  disassembly << capstone_instr->mnemonic << " " << capstone_instr->op_str;
  remill_instr->disassembly = disassembly.str();
  std::cout << "ConvertToRemillInstruction 2\n" << capstone_instr->mnemonic <<std::endl;

  if (data_->architecture == CS_ARCH_ARM)
    remill_instr->arch_name = kArchARM;
  else if (data_->architecture == CS_ARCH_ARM64)
    remill_instr->arch_name = kArchARM64;

  remill_instr->pc = capstone_instr->address;
  remill_instr->next_pc = remill_instr->pc + capstone_instr->size;
  remill_instr->operand_size = AddressSize() / 8;
  remill_instr->category = InstructionCategory(capstone_instr);
  remill_instr->branch_taken_pc = 0;
  remill_instr->branch_not_taken_pc = 0;
  remill_instr->is_atomic_read_modify_write = false;

  remill_instr->operands.clear();
//  CHECK(InstructionOperands(remill_instr->operands, capstone_instr))
//      << "Unsupported instruction operand encountered";

  remill_instr->function = SemanticFunctionName(capstone_instr, remill_instr->operands);
  return true;
}

std::string
ARMDisassembler::SemanticFunctionName(const CapstoneInstructionPtr &cap_instr,
                                      const std::vector<Operand> &operand_list) const noexcept
{
  std::string mnemonic = cap_instr->mnemonic;
  std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::toupper);

  std::stringstream function_name;
  function_name << mnemonic;

  for (const Operand &operand : operand_list) {
    switch (operand.type) {
      case Operand::kTypeInvalid: {
        LOG(FATAL) << "Invalid operand type";
      }

      case Operand::kTypeRegister: {
        function_name << "_R" << (operand.reg.size * 8);
        break;
      }

      case Operand::kTypeImmediate: {
        function_name << "_I" << (operand.imm.is_signed ? "i" : "u") << "64";
        break;
      }

      case Operand::kTypeAddress: {
        function_name << "_M" << (operand.addr.address_size * 8);
        break;
      }
    }
  }

  return function_name.str();
}


}  //  namespace remill
