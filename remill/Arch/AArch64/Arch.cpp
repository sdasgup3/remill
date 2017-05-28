/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/AArch64/Arch.h"
#include "remill/Arch/Capstone/CapstoneDisassembler.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace {

class ARMDisassembler final : public CapstoneDisassembler {
 public:
  explicit ARMDisassembler(bool is_64_bits);

  virtual ~ARMDisassembler(void);

  void EnableThumbMode(bool enabled);

 private:
//  std::string InstructionPredicate(const CapInstrPtr &caps_instr) const;

 public:
  bool CanReadRegister(const CapInstrPtr &cap_instr, uint64_t reg_id,
                         unsigned op_num) const override;
  bool CanWriteRegister(const CapInstrPtr &cap_instr, uint64_t reg_id,
                        unsigned op_num) const override;

  std::string RegName(uint64_t reg_id) const override;

  uint64_t RegSize(uint64_t reg_id) const override;

  void FillInstrOps(const RemInstrPtr &rem_instr,
                    const CapInstrPtr &cap_instr) const override;

  std::size_t AddressSize(void) const override;

  Instruction::Category InstrCategory(const CapInstrPtr &cap_instr) const
      override;

  std::string SemFuncName(
      const RemInstrPtr &rem_instr,
      const CapInstrPtr &cap_instr) const override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  std::string SanitizeName(const char *mnemonic) const;

  void DecodeRegister(const CapInstrPtr &cap_instr,
                      std::vector<Operand> &op_list,
                      uint64_t op_num) const;

  void DecodeImmediate(const CapInstrPtr &cap_instr,
                       const RemInstrPtr &rem_instr,
                       uint64_t op_num) const;

  void DecodeMemory(const CapInstrPtr &cap_instr,
                    std::vector<Operand> &op_list,
                    uint64_t op_num) const;

  void DecodeBranchTaken(std::vector<Operand> &op_list) const;


  ARMDisassembler &operator=(const ARMDisassembler &other) = delete;
  ARMDisassembler(const ARMDisassembler &other) = delete;
  ARMDisassembler(void) = delete;
};

struct ARMDisassembler::PrivateData final {
  std::size_t address_size;
};

/// \todo this looks horrible
ARMDisassembler::ARMDisassembler(bool is_64_bits)
    : CapstoneDisassembler(is_64_bits ? CS_ARCH_ARM64 : CS_ARCH_ARM,
                           is_64_bits ? CS_MODE_LITTLE_ENDIAN : CS_MODE_ARM),
      d(new PrivateData) {
  d->address_size = (is_64_bits ? 64 : 32);
}

ARMDisassembler::~ARMDisassembler(void) {}

std::string ARMDisassembler::SanitizeName(const char *mnemonic) const {
  std::stringstream ss;

  for (auto i = 0; mnemonic[i]; ++i) {
    if (!isalnum(mnemonic[i])) {
      ss << "_";
    } else {
      ss << static_cast<char>(toupper(mnemonic[i]));
    }
  }
  return ss.str();
}

std::string ARMDisassembler::RegName(uint64_t reg_id) const {
  if (ARM64_REG_INVALID == reg_id || ARM64_REG_ENDING == reg_id) {
    return "";

  } else {
    auto reg_name = cs_reg_name(
        GetCapstoneHandle(), static_cast<unsigned>(reg_id));

    CHECK(reg_name != nullptr)
        << "Cannot get name for register " << reg_id;

    return SanitizeName(reg_name);
  }
}

uint64_t ARMDisassembler::RegSize(uint64_t reg_id) const {
  switch (static_cast<arm64_reg>(reg_id)) {
    case ARM64_REG_X0: case ARM64_REG_X1: case ARM64_REG_X2:
    case ARM64_REG_X3: case ARM64_REG_X4: case ARM64_REG_X5:
    case ARM64_REG_X6: case ARM64_REG_X7: case ARM64_REG_X8:
    case ARM64_REG_X9: case ARM64_REG_X10: case ARM64_REG_X11:
    case ARM64_REG_X12: case ARM64_REG_X13: case ARM64_REG_X14:
    case ARM64_REG_X15: case ARM64_REG_X16: case ARM64_REG_X17:
    case ARM64_REG_X18: case ARM64_REG_X19: case ARM64_REG_X20:
    case ARM64_REG_X21: case ARM64_REG_X22: case ARM64_REG_X23:
    case ARM64_REG_X24: case ARM64_REG_X25: case ARM64_REG_X26:
    case ARM64_REG_X27: case ARM64_REG_X28: case ARM64_REG_X29:
    case ARM64_REG_X30: case ARM64_REG_SP: case ARM64_REG_XZR:
      return 64;
    case ARM64_REG_W0: case ARM64_REG_W1: case ARM64_REG_W2:
    case ARM64_REG_W3: case ARM64_REG_W4: case ARM64_REG_W5:
    case ARM64_REG_W6: case ARM64_REG_W7: case ARM64_REG_W8:
    case ARM64_REG_W9: case ARM64_REG_W10: case ARM64_REG_W11:
    case ARM64_REG_W12: case ARM64_REG_W13: case ARM64_REG_W14:
    case ARM64_REG_W15: case ARM64_REG_W16: case ARM64_REG_W17:
    case ARM64_REG_W18: case ARM64_REG_W19: case ARM64_REG_W20:
    case ARM64_REG_W21: case ARM64_REG_W22: case ARM64_REG_W23:
    case ARM64_REG_W24: case ARM64_REG_W25: case ARM64_REG_W26:
    case ARM64_REG_W27: case ARM64_REG_W28: case ARM64_REG_W29:
    case ARM64_REG_W30: case ARM64_REG_WSP: case ARM64_REG_WZR:
      return 32;
    case ARM64_REG_INVALID: case ARM64_REG_ENDING:
      return 0;
    default:
      LOG(FATAL)
          << "Cannot get size of unrecognized register "
          << RegName(reg_id);
  }
  return d->address_size;
}

//std::string ARMDisassembler::InstructionPredicate(
//    const CapInstrPtr &caps_instr) const {
//
//  auto arm64 = &(caps_instr->detail->arm64);
//  switch (arm64->cc) {
//    case ARM64_CC_INVALID:
//      return "";
//    case ARM64_CC_EQ:
//      return "EQ";
//    case ARM64_CC_NE:
//      return "NE";
//    case ARM64_CC_HS:
//      return "HS";
//    case ARM64_CC_LO:
//      return "LO";
//    case ARM64_CC_MI:
//      return "MI";
//    case ARM64_CC_PL:
//      return "PL";
//    case ARM64_CC_VS:
//      return "VS";
//    case ARM64_CC_VC:
//      return "VC";
//    case ARM64_CC_HI:
//      return "HI";
//    case ARM64_CC_LS:
//      return "LS";
//    case ARM64_CC_GE:
//      return "GE";
//    case ARM64_CC_LT:
//      return "LT";
//    case ARM64_CC_GT:
//      return "GT";
//    case ARM64_CC_LE:
//      return "LE";
//    case ARM64_CC_AL:
//      return "AL";
//    case ARM64_CC_NV:
//      return "NV";
//    default:
//      return "";
//  }
//}

bool ARMDisassembler::CanReadRegister(
    const CapInstrPtr &cap_instr, uint64_t reg_id,
    unsigned op_num) const {
  return true;
}

bool ARMDisassembler::CanWriteRegister(
    const CapInstrPtr &cap_instr, uint64_t reg_id,
    unsigned op_num) const {

  if (!op_num) {
    return true;
  }

  if (op_num < cap_instr->detail->arm64.op_count) {
    return false;
  }

  const auto regs_write = cap_instr->detail->regs_write;
  auto num_write_regs = cap_instr->detail->regs_write_count;

  for (uint8_t i = 0; i < num_write_regs; i++) {
    if (static_cast<uint64_t>(regs_write[i]) == reg_id) {
      return true;
    }
  }
  return false;
}

void ARMDisassembler::DecodeRegister(const CapInstrPtr &cap_instr,
                                     std::vector<Operand> &op_list,
                                     uint64_t op_num) const {
  auto arm64_ = &(cap_instr->detail->arm64);
  const auto &arm64_operand = arm64_->operands[op_num];

  Operand op;
  op.type = Operand::kTypeRegister;
  op.size = RegSize(arm64_operand.reg);
  op.reg.size = RegSize(arm64_operand.reg);
  op.reg.name = RegName(arm64_operand.reg);

  op.shift_reg.reg.size = op.reg.size;  // Note: there is no overlap.
  op.shift_reg.reg.name = op.reg.name;
  op.shift_reg.shift_size = arm64_operand.shift.value;

  if (ARM64_SFT_INVALID != arm64_operand.shift.type ||
      ARM64_EXT_INVALID != arm64_operand.ext) {

    op.type = Operand::kTypeShiftRegister;

    switch (arm64_operand.shift.type) {
      case ARM64_SFT_INVALID:
        break;
      case ARM64_SFT_LSL:
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithZeroes;
        break;
      case ARM64_SFT_MSL:
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithOnes;
        break;
      case ARM64_SFT_LSR:
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
        break;
      case ARM64_SFT_ASR:
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftSignedRight;
        break;
      case ARM64_SFT_ROR:
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftRightAround;
        break;
    }

    switch (arm64_operand.ext) {
      case ARM64_EXT_INVALID:
        break;
      case ARM64_EXT_UXTB:
        op.shift_reg.extract_size = 8;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;
        break;
      case ARM64_EXT_UXTH:
        op.shift_reg.extract_size = 16;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;
        break;
      case ARM64_EXT_UXTW:
        op.shift_reg.extract_size = 32;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;
        break;
      case ARM64_EXT_UXTX:
        op.shift_reg.extract_size = 64;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;
        break;
      case ARM64_EXT_SXTB:
        op.shift_reg.extract_size = 8;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendSigned;
        break;
      case ARM64_EXT_SXTH:
        op.shift_reg.extract_size = 16;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendSigned;
        break;
      case ARM64_EXT_SXTW:
        op.shift_reg.extract_size = 32;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendSigned;
        break;
      case ARM64_EXT_SXTX:
        op.shift_reg.extract_size = 64;
        op.shift_reg.extend_op = Operand::ShiftRegister::kExtendSigned;
        break;
    }
  }

  if (CanWriteRegister(cap_instr, arm64_operand.reg, op_num)) {
    op.action = Operand::kActionWrite;
    auto old_op = op;

    // Writes to 32-bit GPRs zero extend to writes to 64 bits.
    if (32 == op.reg.size && 'W' == op.reg.name[0]) {
      op.size = 64;
      op.reg.size = 64;
      op.reg.name[0] = 'X';
    }

    op_list.push_back(op);
    op = old_op;
  }

  if (CanReadRegister(cap_instr, arm64_operand.reg, op_num)) {
    op.action = Operand::kActionRead;
    op_list.push_back(op);
  }

  CHECK(op.action != Operand::kActionInvalid)
      << "Register " << op.reg.name << " is neither read nor written "
      << "in instruction " << std::hex << cap_instr->address;
}

void ARMDisassembler::DecodeImmediate(const CapInstrPtr &cap_instr,
                                      const RemInstrPtr &rem_instr,
                                      uint64_t op_num) const {
  auto arm64_ = &(cap_instr->detail->arm64);
  const auto &arm64_operand = arm64_->operands[op_num];

  Operand op;
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;
  op.size = 64;
  op.imm.is_signed = false;  // Capstone doesn't even know :-(
  op.imm.val = static_cast<uint64_t>(arm64_operand.imm);

  auto shift = static_cast<uint64_t>(arm64_operand.shift.value);

  switch (arm64_operand.shift.type) {
    case ARM64_SFT_LSL:
      op.imm.val <<= shift;
      break;

    case ARM64_SFT_INVALID:
      break;

    default:
      LOG(FATAL)
          << "Unsupported shift type for immediate operand "
          << "in instruction " << std::hex << rem_instr->pc;
      break;
  }

  CHECK(arm64_operand.ext == ARM64_EXT_INVALID)
      << "Extract and extend is not supported for immediate operand "
      << "in instruction " << std::hex << rem_instr->pc;

  rem_instr->operands.push_back(op);

  // If this is a conditional branch, then add in another immediate operand
  // representing the not-taken address.
  switch (rem_instr->category) {
    case Instruction::kCategoryConditionalBranch:
      rem_instr->branch_taken_pc = op.imm.val;
      rem_instr->branch_not_taken_pc = rem_instr->next_pc;
      op.imm.val = rem_instr->branch_not_taken_pc;
      rem_instr->operands.push_back(op);
      break;

    case Instruction::kCategoryDirectJump:
      rem_instr->branch_taken_pc = op.imm.val;
      break;

    case Instruction::kCategoryDirectFunctionCall:
      rem_instr->branch_taken_pc = op.imm.val;

      // Pass in the return address as another immediate operand.
      op.imm.val = rem_instr->next_pc;
      rem_instr->operands.push_back(op);
      break;

    default:
      break;
  }
}

void ARMDisassembler::DecodeMemory(const CapInstrPtr &cap_instr,
                                   std::vector<Operand> &op_list,
                                   uint64_t op_num) const {
  auto arm64_ = &(cap_instr->detail->arm64);
  const auto &arm64_operand = arm64_->operands[op_num];

  Operand op;
  op.type = Operand::kTypeAddress;

  // TODO(pag): Capstone doesn't seem to give us this info, so we
  //            will assume that all memory operands are possibly
  //            writes to memory.
  op.action = Operand::kActionWrite;

  // TODO(pag): This should be the size of memory being read or written.
  op.size = 64;
  op.addr.base_reg.size = RegSize(arm64_operand.mem.base);
  op.addr.base_reg.name = RegName(arm64_operand.mem.base);
  op.addr.index_reg.size = RegSize(arm64_operand.mem.index);
  op.addr.index_reg.name = RegName(arm64_operand.mem.index);
  op.addr.displacement = arm64_operand.mem.disp;
  op.addr.address_size = AddressSize();
  op_list.push_back(op);
}

void ARMDisassembler::DecodeBranchTaken(std::vector<Operand> &op_list) const {
  Operand cond_op = {};
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
  op_list.push_back(cond_op);
}

void ARMDisassembler::FillInstrOps(
    const RemInstrPtr &rem_instr,
    const CapInstrPtr &cap_instr) const {

  CHECK(AddressSize() == 64)
      << "Only AArch64 is supported.";

  auto &op_list = rem_instr->operands;

  if (Instruction::kCategoryConditionalBranch == rem_instr->category) {
    DecodeBranchTaken(op_list);
  }

  auto arm64_ = &(cap_instr->detail->arm64);
  auto num_operands = arm64_->op_count;

  for (uint64_t i = 0; i < num_operands; ++i) {
    const auto &arm64_operand = arm64_->operands[i];

    switch (arm64_operand.type) {
      case ARM64_OP_INVALID:  // = CS_OP_INVALID (Uninitialized).
        break;

      case ARM64_OP_REG:
        DecodeRegister(cap_instr, op_list, i);
        break;

      case ARM64_OP_IMM:  // = CS_OP_IMM (Immediate operand).
        DecodeImmediate(cap_instr, rem_instr, i);
        break;

      case ARM64_OP_MEM:  // = CS_OP_MEM (Memory operand).
        DecodeMemory(cap_instr, op_list, i);
        break;

      case ARM64_OP_FP:  // = CS_OP_FP (Floating-Point operand).
        LOG(ERROR)
            << "ARM64_OP_FP not yet supported.";
        break;
      case ARM64_OP_CIMM:
        LOG(ERROR)
            << "ARM64_OP_CIMM not yet supported.";
        break;
      case ARM64_OP_REG_MRS:  // MRS register operand.
        LOG(ERROR)
            << "ARM64_OP_REG_MRS not yet supported.";
        break;
      case ARM64_OP_REG_MSR:  // MSR register operand.
        LOG(ERROR)
            << "ARM64_OP_REG_MSR not yet supported.";
        break;
      case ARM64_OP_PSTATE:  // PState operand.
        LOG(ERROR)
            << "ARM64_OP_PSTATE not yet supported.";
        break;
      case ARM64_OP_SYS:  // SYS operand for IC/DC/AT/TLBI instructions.
        LOG(ERROR)
            << "ARM64_OP_SYS not yet supported.";
        break;
      case ARM64_OP_PREFETCH:  // Prefetch operand (PRFM).
        LOG(ERROR)
            << "ARM64_OP_PREFETCH not yet supported.";
        break;
      case ARM64_OP_BARRIER:  // Memory barrier operand (ISB/DMB/DSB
                              // instructions).
        LOG(ERROR)
            << "ARM64_OP_BARRIER not yet supported.";
        break;
    }
  }
}

std::size_t ARMDisassembler::AddressSize(void) const {
  return d->address_size;
}

Instruction::Category ARMDisassembler::InstrCategory(
    const CapInstrPtr &cap_instr) const {

  CHECK(AddressSize() == 64)
      << "AArch32 is not yet supported";


  switch (cap_instr->id) {
    // TODO(pag): B.cond.
    case ARM64_INS_B:
      if (cap_instr->detail->arm64.cc == ARM64_CC_INVALID) {
        return Instruction::kCategoryDirectJump;
      } else {
        return Instruction::kCategoryConditionalBranch;
      }

    case ARM64_INS_BR:
      return Instruction::kCategoryIndirectJump;

    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      return Instruction::kCategoryConditionalBranch;

    case ARM64_INS_BL:
      return Instruction::kCategoryDirectFunctionCall;

    case ARM64_INS_BLR:
      return Instruction::kCategoryIndirectFunctionCall;

    case ARM64_INS_RET:
      return Instruction::kCategoryFunctionReturn;

    case ARM64_INS_HLT:
      return Instruction::kCategoryError;

    case ARM64_INS_HVC:
    case ARM64_INS_SMC:
    case ARM64_INS_SVC:
      return Instruction::kCategoryAsyncHyperCall;

    case ARM64_INS_NOP:
      return Instruction::kCategoryNoOp;

    case ARM64_INS_INVALID:
      return Instruction::kCategoryInvalid;

    // Note: These are implemented with synchronous hyper calls.
    case ARM64_INS_BRK:
    case ARM64_INS_SYS:
    case ARM64_INS_SYSL:
    case ARM64_INS_IC:
    case ARM64_INS_DC:
    case ARM64_INS_AT:
    case ARM64_INS_TLBI:
      return Instruction::kCategoryNormal;

    default:
      return Instruction::kCategoryNormal;
  }
}

std::string ARMDisassembler::SemFuncName(
    const RemInstrPtr &rem_instr,
    const CapInstrPtr &cap_instr) const {
  CHECK(AddressSize() == 64)
      << "AArch32 is not supported.";

  std::stringstream function_name;
  function_name << SanitizeName(cap_instr->mnemonic);
//  function_name << InstructionPredicate(cap_instr);

  auto arm64 = &(cap_instr->detail->arm64);

  // Add S bit state with the function name.
  if (arm64->update_flags) {
    function_name << "_S1";
  }

  for (const Operand &operand : rem_instr->operands) {
    switch (operand.type) {
      case Operand::kTypeInvalid:
        LOG(FATAL)
            << "Invalid operand type";
        break;

      case Operand::kTypeShiftRegister:
      case Operand::kTypeRegister:
        if (Operand::kActionRead == operand.action) {
          function_name << "_R" << operand.reg.size;
        } else if (Operand::kActionWrite == operand.action) {
          function_name << "_R" << operand.reg.size << "W";
        } else {
          LOG(FATAL)
              << "Invalid action for register operand.";
        }
        break;

      case Operand::kTypeImmediate:
        CHECK(Operand::kActionRead == operand.action)
            << "Invalid action for immediate operand.";

        function_name
            << "_" << (operand.imm.is_signed ? "S" : "U") << "64";
        break;

      case Operand::kTypeAddress:
        function_name << "_M" << operand.addr.address_size * 8;
        break;
    }
  }

  return function_name.str();
}

void ARMDisassembler::EnableThumbMode(bool enabled) {
  cs_option(GetCapstoneHandle(), CS_OPT_MODE,
            enabled ? CS_MODE_THUMB : CS_MODE_ARM);
}

}  // namespace

struct ARMArch::PrivateData final {
  OSName operating_system;
  ArchName architecture;

  std::unique_ptr<CapstoneDisassembler> disassembler;
};

// TODO(pag): We pretend that these are singletons, but they aren't really!
const Arch *Arch::GetAArch64(OSName os_name_, ArchName arch_name_) {
  return new ARMArch(os_name_, arch_name_);
}

ARMArch::ARMArch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_), d(new PrivateData) {

  // TODO(akshay): Support Windows.
  // TODO(pag): What is needed to support Windows?
  CHECK(os_name_ == kOSLinux)
      << "The ARM module does not support the specified operating system";

  switch (arch_name) {
    case kArchAArch64LittleEndian:
      d->operating_system = os_name_;
      d->architecture = arch_name_;
      d->disassembler = llvm::make_unique<ARMDisassembler>(
          true /* is_64_bit */);
      break;
    default:
      LOG(FATAL)
          << "The ARM module does not support the architecture "
          << GetArchName(arch_name);
      break;
  }
}

ARMArch::~ARMArch(void) {}

void ARMArch::PrepareModule(llvm::Module *mod) const {
  std::string dl;
  llvm::Triple triple("aarch64-unknown-unknown-");

  switch (os_name) {
    case kOSLinux:
      triple.setOS(llvm::Triple::Linux);

      switch (arch_name) {
        case kArchAArch64LittleEndian:
          triple.setArch(llvm::Triple::aarch64);
          dl = "e-m:e-i64:64-i128:128-n32:64-S128";
          break;

        default:
          LOG(FATAL)
              << "Cannot prepare AArch64 module for architecture "
              << GetArchName(arch_name);
          break;
      }
      break;

    default:
      LOG(FATAL)
          << "Cannot prepare module for AArch64 code on OS "
          << GetOSName(os_name);
      break;
  }

  mod->setDataLayout(dl);
  mod->setTargetTriple(triple.normalize());

  // Go and remove compile-time attributes added into the semantics. These
  // can screw up later compilation. We purposefully compile semantics with
  // things like auto-vectorization disabled so that it keeps the bitcode
  // to a simpler subset of the available LLVM instruction set. If/when we
  // compile this bitcode back into machine code, we may want to use those
  // features, and clang will complain if we try to do so if these metadata
  // remain present.
  auto &context = mod->getContext();

  llvm::AttributeSet target_attribs;
  target_attribs = target_attribs.addAttribute(
      context, llvm::AttributeSet::FunctionIndex, "target-features");
  target_attribs = target_attribs.addAttribute(
      context, llvm::AttributeSet::FunctionIndex, "target-cpu");

  for (llvm::Function &func : *mod) {
    auto attribs = func.getAttributes();
    attribs = attribs.removeAttributes(
        context, llvm::AttributeSet::FunctionIndex, target_attribs);
    func.setAttributes(attribs);
  }
}

std::unique_ptr<Instruction> ARMArch::DecodeInstruction(
    uint64_t address, const std::string &instr_bytes) const {

  std::unique_ptr<Instruction> remill_instr(new Instruction);
  d->disassembler->Decode(remill_instr, address, instr_bytes);
  return remill_instr;
}

}  // namespace remill
