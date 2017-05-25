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

#include "remill/Arch/Capstone/CapstoneDisassembler.h"

#include <algorithm>
#include <sstream>

#include <glog/logging.h>
#include <remill/Arch/Name.h>

namespace remill {
namespace {

static void CapstoneInstructionDeleter(cs_insn *instruction) {
  if (instruction != nullptr) {
    cs_free(instruction, 1);
  }
}

}  // namespace

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
    case CS_ARCH_ARM64:
      d->addr_size = 64;
      break;

    case CS_ARCH_ARM:
      d->addr_size = 32;
      break;

    case CS_ARCH_MIPS:
      if ((mode & CS_MODE_MIPS64) != 0) {
        d->addr_size = 64;
      } else {
        d->addr_size = 32;
      }
      break;

    default:
      LOG(FATAL)
          << "Invalid architecture selected";
      break;
  }

  cs_option(d->capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

CapstoneDisassembler::~CapstoneDisassembler(void) {
  cs_close(&d->capstone);
}

void CapstoneDisassembler::Decode(const std::unique_ptr<Instruction> &rem_instr,
                                  uint64_t vaddr,
                                  const std::string &instr_bytes) const {
  CapInstrPtr cap_instr = Disassemble(
      vaddr, reinterpret_cast<const std::uint8_t *>(instr_bytes.data()),
      instr_bytes.size());

  if (cap_instr) {
    ConvertToRemInstr(rem_instr, cap_instr);
  } else {
    LOG(ERROR)
        << "Capstone failed to decode instruction at "
        << std::hex << vaddr;
  }
}

CapInstrPtr CapstoneDisassembler::Disassemble(std::uint64_t vaddr,
                                              const std::uint8_t *buf,
                                              std::size_t size) const {
  cs_insn *temp_instr = nullptr;
  if (cs_disasm(d->capstone, buf, size, vaddr, 1, &temp_instr) != 1) {
    return nullptr;
  }

  return CapInstrPtr(temp_instr, CapstoneInstructionDeleter);
}

/// returns the capstone handle
csh CapstoneDisassembler::GetCapstoneHandle(void) const {
  return d->capstone;
}

void CapstoneDisassembler::ConvertToRemInstr(
    const std::unique_ptr<remill::Instruction> &rem_instr,
    const CapInstrPtr &cap_instr) const {

  std::stringstream disasm;
  disasm << cap_instr->mnemonic << " " << cap_instr->op_str;
  rem_instr->disassembly = disasm.str();

  if (d->arch == CS_ARCH_ARM64) {
    if (d->little_endian) {
      rem_instr->arch_name = kArchAArch64LittleEndian;
    } else {
      rem_instr->arch_name = kArchAArch64BigEndian;
    }
  } else if (d->arch == CS_ARCH_MIPS) {
    if ((d->cap_mode & CS_MODE_MIPS64) != 0) {
      rem_instr->arch_name = kArchMips64;
    } else {
      rem_instr->arch_name = kArchMips32;
    }
  }

  rem_instr->pc = cap_instr->address;
  rem_instr->next_pc = rem_instr->pc + cap_instr->size;
  rem_instr->operand_size = AddressSize() / 8;
  rem_instr->category = InstrCategory(cap_instr);
  rem_instr->branch_taken_pc = 0;
  rem_instr->branch_not_taken_pc = 0;
  rem_instr->is_atomic_read_modify_write = false;
  rem_instr->operands = InstrOps(cap_instr);
  rem_instr->function = SemFuncName(cap_instr, rem_instr->operands);
}

Operand::Action CapstoneDisassembler::RegAccessType(
    unsigned int reg_id, const CapInstrPtr &cap_instr) const {

  for (uint8_t i = 0; i < cap_instr->detail->regs_read_count; i++) {
    if (cap_instr->detail->regs_read[i] != reg_id) {
      continue;
    }
    return Operand::kActionRead;
  }

  for (uint8_t i = 0; i < cap_instr->detail->regs_write_count; i++) {
    if (cap_instr->detail->regs_write[i] != reg_id) {
      continue;
    }
    return Operand::kActionWrite;
  }

  return Operand::kActionInvalid;
}

}  // namespace remill
