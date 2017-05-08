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

#include <map>
#include <sstream>
#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Capstone/MipsDisassembler.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Mips/Arch.h>
#include <remill/Arch/Mips/Runtime/State.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

namespace remill {

struct MipsArch::PrivateData final {
  OSName operating_system;
  ArchName architecture;

  std::unique_ptr<CapstoneDisassembler> disassembler;
};

// TODO(pag): We pretend that these are singletons, but they aren't really!
const Arch *Arch::GetMips(OSName os_name_, ArchName arch_name_) {
  return new MipsArch(os_name_, arch_name_);
}

MipsArch::MipsArch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_), d(new PrivateData) {
  CHECK(os_name_ == kOSLinux)
      << "The MIPS module does not support the specified operating system";

  CHECK(arch_name_ == kArchMips32 || arch_name_ == kArchMips64)
      << "The MIPS module does not support the specified architecture";

  d->operating_system = os_name_;
  d->architecture = arch_name_;
  d->disassembler =
      llvm::make_unique<MipsDisassembler>(arch_name_ == kArchMips64);
}

MipsArch::~MipsArch(void) {}

void MipsArch::PrepareModule(llvm::Module *mod) const {
  static_cast<void>(mod);
}

uint64_t MipsArch::ProgramCounter(const ArchState *state) const {
  static_cast<void>(state);
  return 0;
}

Instruction *MipsArch::DecodeInstruction(uint64_t address,
                                         const std::string &instr_bytes) const {
  std::unique_ptr<Instruction> remill_instr(new Instruction);
  if (!d->disassembler->Decode(remill_instr, address, instr_bytes))
    return nullptr;

  return remill_instr.release();
}

}  // namespace remill
