
#include <iostream>
#include <sstream>
#include <algorithm>
#include <glog/logging.h>

#include "ARMDisassembler.h"
#include <remill/Arch/Name.h>

namespace remill {

void StripInstructionName(std::string &str) {
  size_t pos = str.find('.');
  if(pos != std::string::npos) {
    str.erase(str.begin() + pos, str.end());
  }
}

ARMDisassembler::ARMDisassembler(bool is_64_bits) :
    CapstoneDisassembler(is_64_bits ? CS_ARCH_ARM64 : CS_ARCH_ARM, CS_MODE_ARM)
{
  data_->address_space = (is_64_bits ? 64 : 32);
}

ARMDisassembler::~ARMDisassembler() {
}

bool ARMDisassembler::RegisterSize(std::size_t &size, const std::string &name) const noexcept {
  return false;
}

bool ARMDisassembler::InstructionOperands(std::vector<Operand> &operand_list,
                                          const CapstoneInstructionPtr &capstone_instr) const noexcept {
  return false;
}

std::string
ARMDisassembler::InstructionPredicate(const CapstoneInstructionPtr &caps_instr) const noexcept {
  uint32_t cond_code = 0;

  if(data_->address_space == 32) {
    auto arm = &(caps_instr->detail->arm);
    cond_code = static_cast<uint32_t>(arm->cc);
  } else {
    auto arm64 = &(caps_instr->detail->arm64);
    cond_code = static_cast<uint32_t>(arm64->cc);
  }

  switch(cond_code) {
    case ARM64_CC_INVALID:
      return "";
    case ARM64_CC_EQ:
      return "EQ";
    case ARM64_CC_NE:
      return "NE";
    case ARM64_CC_HS:
      return "HS";
    case ARM64_CC_LO:
      return "LO";
    case ARM64_CC_MI:
      return "MI";
    case ARM64_CC_PL:
      return "PL";
    case ARM64_CC_VS:
      return "VS";
    case ARM64_CC_VC:
      return "VC";
    case ARM64_CC_HI:
      return "HI";
    case ARM64_CC_LS:
      return "LS";
    case ARM64_CC_GE:
      return "GE";
    case ARM64_CC_LT:
      return "LT";
    case ARM64_CC_GT:
      return "GT";
    case ARM64_CC_LE:
      return "LE";
    case ARM64_CC_AL:
      return "AL";
    case ARM64_CC_NV:
      return "";
    default:
      return "";
  }

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


bool
ARMDisassembler::ConvertToRemillInstruction(const std::unique_ptr<remill::Instruction> &remill_instr,
                                            const CapstoneInstructionPtr &cap_instr) const noexcept {
  std::stringstream disassembly;

  disassembly << cap_instr->mnemonic << " " << cap_instr->op_str;
  remill_instr->disassembly = disassembly.str();
  std::cout << cap_instr->mnemonic <<std::endl;

  if (data_->architecture == CS_ARCH_ARM)
    remill_instr->arch_name = kArchARM;
  else if (data_->architecture == CS_ARCH_ARM64)
    remill_instr->arch_name = kArchARM64;

  remill_instr->pc = cap_instr->address;
  remill_instr->next_pc = remill_instr->pc + cap_instr->size;
  remill_instr->operand_size = AddressSize() / 8;
  remill_instr->category = InstructionCategory(cap_instr);
  remill_instr->branch_taken_pc = 0;
  remill_instr->branch_not_taken_pc = 0;
  remill_instr->is_atomic_read_modify_write = false;

  remill_instr->operands.clear();
  DecodeOperands(cap_instr, remill_instr->operands);
  remill_instr->function = SemanticFunctionName(cap_instr, remill_instr->operands);
  return true;
}

std::string
ARMDisassembler::SemanticFunctionName(const CapstoneInstructionPtr &cap_instr,
                                      const std::vector<Operand> &operand_list) const noexcept
{
  bool sbit = false;
  std::string mnemonic = cap_instr->mnemonic;
  std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::toupper);
  StripInstructionName(mnemonic);
  std::stringstream function_name;
  function_name << mnemonic;
  function_name << InstructionPredicate(cap_instr);

  if(data_->address_space == 32) {
    auto arm = &(cap_instr->detail->arm);
    sbit = arm->update_flags;
  } else {
    auto arm64 = &(cap_instr->detail->arm64);
    sbit = arm64->update_flags;
  }

  // Add S bit state with the function name
  if(sbit) function_name << "_S1";

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

bool
ARMDisassembler::DecodeOperands(const CapstoneInstructionPtr &caps_instr,
                                std::vector<Operand> &oprnds) const noexcept
{
  if (data_->address_space == 32) {
      auto arm_ = &(caps_instr->detail->arm);
      auto num_operands = arm_->op_count;

      for (auto i = 0U; i < num_operands; ++i) {
        auto arm_operand = arm_->operands[i];
        switch(arm_operand.type) {
          case ARM_OP_INVALID:
            break;
          case ARM_OP_REG:
            break;
          case ARM_OP_IMM:
            break;
          case ARM_OP_MEM:
            break;
          case ARM_OP_FP:
            break;
          case ARM_OP_CIMM:
            break;
          case ARM_OP_PIMM:
            break;
          case ARM_OP_SETEND:
            break;
          case ARM_OP_SYSREG:
            break;
        }
      }
    } else if (data_->address_space == 64){
      auto arm64_ = &(caps_instr->detail->arm64);
      auto num_operands = arm64_->op_count;

      for (auto i = 0U; i < num_operands; ++i) {
        auto arm64_operand = arm64_->operands[i];

        switch(arm64_operand.type) {
          case  ARM64_OP_INVALID:   // = CS_OP_INVALID (Uninitialized).
            break;
          case ARM64_OP_REG: {
            Operand op;
            op.type = Operand::kTypeRegister;
            op.size = 8;
            op.reg.size = 8;
            op.reg.name = RegisterName(arm64_operand.reg);
            std::transform(op.reg.name.begin(), op.reg.name.end(), op.reg.name.begin(), ::toupper);
            oprnds.push_back(op);
            break;
          }
          case ARM64_OP_IMM: { // = CS_OP_IMM (Immediate operand).
            Operand op;
            op.type = Operand::kTypeImmediate;
            op.action = Operand::kActionRead;
            op.size = 64;
            op.imm.is_signed = true;
            op.imm.val = arm64_operand.imm;
            oprnds.push_back(op);
            break;
          }
          case ARM64_OP_MEM: { // = CS_OP_MEM (Memory operand).
            Operand op;
            op.type = Operand::kTypeAddress;
            op.size = 64;
            op.addr.base_reg.name = RegisterName(arm64_operand.mem.base);
            op.addr.index_reg.name = RegisterName(arm64_operand.mem.index);
            op.addr.displacement = arm64_operand.mem.disp;

            break;
          }
          case ARM64_OP_FP:  // = CS_OP_FP (Floating-Point operand).
            break;
          case ARM64_OP_CIMM:
            break;
          case ARM64_OP_REG_MRS: // MRS register operand.
            break;
          case ARM64_OP_REG_MSR: // MSR register operand.
            break;
          case ARM64_OP_PSTATE: // PState operand.
            break;
          case ARM64_OP_SYS: // SYS operand for IC/DC/AT/TLBI instructions.
            break;
          case ARM64_OP_PREFETCH: // Prefetch operand (PRFM).
            break;
          case ARM64_OP_BARRIER: // Memory barrier operand (ISB/DMB/DSB instructions).
            break;
        }
      }
  }

  return true;
}

}  //  namespace remill
