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
  std::string InstructionPredicate(const CapInstrPtr &caps_instr) const;

 public:
  std::string RegName(uint64_t reg_id) const override;

  uint64_t RegSize(uint64_t reg_id) const override;

  std::vector<Operand> InstrOps(const CapInstrPtr &cap_instr) const override;

  std::size_t AddressSize(void) const override;
  Instruction::Category InstrCategory(const CapInstrPtr &cap_instr) const
      override;

  std::string SemFuncName(
      const CapInstrPtr &cap_instr,
      const std::vector<Operand> &op_list) const override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

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

std::string ARMDisassembler::RegName(uint64_t reg_id) const {
  if (!reg_id) {
    return std::string();
  }

  return cs_reg_name(GetCapstoneHandle(), reg_id);
}

uint64_t ARMDisassembler::RegSize(uint64_t reg_id) const {
  return d->address_size;
}

std::string ARMDisassembler::InstructionPredicate(
    const CapInstrPtr &caps_instr) const {
  uint32_t cond_code = 0;

  if (AddressSize() == 32) {
    auto arm = &(caps_instr->detail->arm);
    cond_code = static_cast<uint32_t>(arm->cc);
  } else {
    auto arm64 = &(caps_instr->detail->arm64);
    cond_code = static_cast<uint32_t>(arm64->cc);
  }

  switch (cond_code) {
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

static std::string CleanMnemonic(const char *mnemonic) {
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

std::vector<Operand> ARMDisassembler::InstrOps(
    const CapInstrPtr &cap_instr) const {

  CHECK(AddressSize() == 64)
      << "Only AArch64 is supported.";

  std::vector<Operand> op_list;

  auto arm64_ = &(cap_instr->detail->arm64);
  auto num_operands = arm64_->op_count;

  for (auto i = 0U; i < num_operands; ++i) {
    auto arm64_operand = arm64_->operands[i];

    switch (arm64_operand.type) {
      case ARM64_OP_INVALID:  // = CS_OP_INVALID (Uninitialized).
        break;
      case ARM64_OP_REG: {
        Operand op;
        op.type = Operand::kTypeRegister;
        op.size = RegSize(arm64_operand.reg);
        op.reg.size = RegSize(arm64_operand.reg);
        op.reg.name = RegName(arm64_operand.reg);
        std::transform(op.reg.name.begin(), op.reg.name.end(),
                       op.reg.name.begin(), ::toupper);
        op_list.push_back(op);
        break;
      }
      case ARM64_OP_IMM: {  // = CS_OP_IMM (Immediate operand).
        Operand op;
        op.type = Operand::kTypeImmediate;
        op.action = Operand::kActionRead;
        op.size = 64;
        op.imm.is_signed = true;
        op.imm.val = arm64_operand.imm;
        op_list.push_back(op);
        break;
      }
      case ARM64_OP_MEM: {  // = CS_OP_MEM (Memory operand).
        Operand op;
        op.type = Operand::kTypeAddress;
        op.size = 64;
        op.addr.base_reg.size = RegSize(arm64_operand.mem.base);
        op.addr.base_reg.name = RegName(arm64_operand.mem.base);
        op.addr.index_reg.size = RegSize(arm64_operand.mem.index);
        op.addr.index_reg.name = RegName(arm64_operand.mem.index);
        op.addr.displacement = arm64_operand.mem.disp;
        op.addr.address_size = 64;
        op_list.push_back(op);
        break;
      }
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

  return op_list;
}

std::size_t ARMDisassembler::AddressSize(void) const {
  return d->address_size;
}

Instruction::Category ARMDisassembler::InstrCategory(
    const CapInstrPtr &cap_instr) const {
  // AArch32.
  if (AddressSize() == 32) {
    auto instr_details = cap_instr->detail->arm;

    if (cap_instr->id == ARM_INS_BL || cap_instr->id == ARM_INS_BLX) {
      return Instruction::kCategoryDirectFunctionCall;

    } else if (cap_instr->id == ARM_INS_BX &&
               instr_details.operands[0].type == ARM_OP_REG &&
               instr_details.operands[0].reg == ARM_REG_LR) {
      return Instruction::kCategoryFunctionReturn;

    } else if (cap_instr->id == ARM_INS_INVALID) {
      return Instruction::kCategoryInvalid;
    }

  // AArch64.
  } else {
    if (cap_instr->id == ARM64_INS_BL) {
      return Instruction::kCategoryDirectFunctionCall;

    } else if (cap_instr->id == ARM64_INS_RET) {
      return Instruction::kCategoryFunctionReturn;

    } else if (cap_instr->id == ARM64_INS_INVALID) {
      return Instruction::kCategoryInvalid;
    }
  }

  return Instruction::kCategoryNormal;
}

std::string ARMDisassembler::SemFuncName(
    const CapInstrPtr &cap_instr, const std::vector<Operand> &op_list) const {
  bool sbit = false;

  std::stringstream function_name;
  function_name << CleanMnemonic(cap_instr->mnemonic);
  function_name << InstructionPredicate(cap_instr);

  if (AddressSize() == 32) {
    auto arm = &(cap_instr->detail->arm);
    sbit = arm->update_flags;
  } else {
    auto arm64 = &(cap_instr->detail->arm64);
    sbit = arm64->update_flags;
  }

  // Add S bit state with the function name.
  if (sbit) {
    function_name << "_S1";
  }

  for (const Operand &operand : op_list) {
    switch (operand.type) {
      case Operand::kTypeInvalid:
        LOG(FATAL)
            << "Invalid operand type";
        break;

      case Operand::kTypeRegister: {
        function_name << "_REG" << operand.reg.size;
        break;
      }

      case Operand::kTypeImmediate: {
        function_name
            << "_" << (operand.imm.is_signed ? "SIMM" : "UIMM") << "64";
        break;
      }

      case Operand::kTypeAddress: {
        function_name << "_MEM" << operand.addr.address_size * 8;
        break;
      }
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
    case kArchAArch64BigEndian:
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
  std::string triple;

  switch (os_name) {
    case kOSLinux:
      switch (arch_name) {
        case kArchAArch64BigEndian:
        case kArchAArch64LittleEndian: {
          // TODO(pag): Are these right for both LE and BE?
          dl = "e-m:e-i64:64-i128:128-n32:64-S128";
          triple = "arm64-unknown";
          break;
        }

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
  mod->setTargetTriple(triple);

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
