#include "CapstoneDisassembler.h"

#include <algorithm>
#include <sstream>

#include <glog/logging.h>
#include <remill/Arch/Name.h>

namespace remill {

void CapstoneInstructionDeleter(cs_insn *instruction) noexcept {
  if (instruction != nullptr) cs_free(instruction, 1);
}

struct CapstoneDisassembler::PrivateData final {
  csh capstone;

  cs_arch arch;
  cs_mode cap_mode;
  std::size_t addr_size;
  bool little_endian;
};

CapstoneDisassembler::CapstoneDisassembler(cs_arch arch, cs_mode mode)
    : d(new PrivateData) {
  d->little_endian = ((mode & CS_MODE_BIG_ENDIAN) == 0);
  d->cap_mode = mode;

  CHECK(cs_open(arch, d->cap_mode, &d->capstone) == CS_ERR_OK)
      << "The MIPS module has failed to initialize the Capstone library";

  switch (arch) {
    case CS_ARCH_ARM64: {
      d->addr_size = 64;
      break;
    }

    case CS_ARCH_ARM: {
      d->addr_size = 32;
      break;
    }

    case CS_ARCH_MIPS: {
      if ((mode & CS_MODE_MIPS64) != 0)
        d->addr_size = 64;
      else
        d->addr_size = 32;

      break;
    }

    default: { CHECK(false) << "Invalid architecture selected"; }
  }

  cs_option(d->capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

CapstoneDisassembler::~CapstoneDisassembler() { cs_close(&d->capstone); }

bool CapstoneDisassembler::Decode(const std::unique_ptr<Instruction> &rem_instr,
                                  uint64_t vaddr, const std::string &size) const
    noexcept {
  CapInstrPtr cap_instr = Disassemble(
      vaddr, reinterpret_cast<const std::uint8_t *>(size.data()), size.size());
  if (!cap_instr) return false;

  if (!ConvertToRemInstr(rem_instr, cap_instr)) return false;

  if (!PostDecodeHook(rem_instr, cap_instr)) return false;

  return true;
}

CapInstrPtr CapstoneDisassembler::Disassemble(std::uint64_t vaddr,
                                              const std::uint8_t *buf,
                                              std::size_t size) const noexcept {
  cs_insn *temp_instr;
  if (cs_disasm(d->capstone, buf, size, vaddr, 1, &temp_instr) != 1)
    return nullptr;

  auto cap_instr = CapInstrPtr(temp_instr, CapstoneInstructionDeleter);
  if (!PostDisasmHook(cap_instr)) return nullptr;

  return cap_instr;
}

std::string CapstoneDisassembler::SemFuncName(
    const CapInstrPtr &cap_instr, const std::vector<Operand> &op_list) const
    noexcept {
  // in the default implementation we don't need to access the capstone
  // instruction
  static_cast<void>(cap_instr);

  std::string mnemonic = cap_instr->mnemonic;
  std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::toupper);

  std::stringstream func_name;
  func_name << mnemonic;

  for (const Operand &operand : op_list) {
    switch (operand.type) {
      case Operand::kTypeInvalid: {
        CHECK(false) << "Invalid operand type";
      }

      case Operand::kTypeRegister: {
        func_name << "_R" << (operand.reg.size * 8);
        break;
      }

      case Operand::kTypeImmediate: {
        func_name << "_I" << (operand.imm.is_signed ? "i" : "u") << "64";
        break;
      }

      case Operand::kTypeAddress: {
        func_name << "_M" << (operand.addr.address_size * 8);
        break;
      }
    }
  }

  return func_name.str();
}

bool CapstoneDisassembler::ConvertToRemInstr(
    const std::unique_ptr<remill::Instruction> &rem_instr,
    const CapInstrPtr &cap_instr) const noexcept {
  std::stringstream disasm;
  disasm << cap_instr->mnemonic << " " << cap_instr->op_str;
  rem_instr->disassembly = disasm.str();

  if (d->arch == CS_ARCH_ARM)
    rem_instr->arch_name = kArchARM;
  else if (d->arch == CS_ARCH_ARM64)
    rem_instr->arch_name = kArchARM64;
  else if (d->arch == CS_ARCH_MIPS) {
    if ((d->cap_mode & CS_MODE_MIPS64) != 0)
      rem_instr->arch_name = kArchMips64;
    else
      rem_instr->arch_name = kArchMips32;
  }

  rem_instr->pc = cap_instr->address;
  rem_instr->next_pc = rem_instr->pc + cap_instr->size;
  rem_instr->operand_size = AddressSize() / 8;
  rem_instr->category = InstrCategory(cap_instr);
  rem_instr->branch_taken_pc = 0;
  rem_instr->branch_not_taken_pc = 0;
  rem_instr->is_atomic_read_modify_write = false;

  //
  // convert the operands
  //

  rem_instr->operands.clear();
  CHECK(InstrOps(rem_instr->operands, cap_instr))
      << "Unsupported instruction operand encountered";

  rem_instr->function = SemFuncName(cap_instr, rem_instr->operands);
  return true;
}

Operand::Action CapstoneDisassembler::RegAccessType(
    unsigned int reg_id, const CapInstrPtr &cap_instr) const noexcept {
  Operand::Action action_type = Operand::kActionInvalid;

  for (uint8_t i = 0; i < cap_instr->detail->regs_read_count; i++) {
    if (cap_instr->detail->regs_read[i] != reg_id) continue;

    action_type = Operand::kActionRead;
    break;
  }

  for (uint8_t i = 0; i < cap_instr->detail->regs_write_count; i++) {
    if (cap_instr->detail->regs_write[i] != reg_id) continue;

    action_type = Operand::kActionWrite;
    break;
  }

  return action_type;
}

}  // remill namespace
