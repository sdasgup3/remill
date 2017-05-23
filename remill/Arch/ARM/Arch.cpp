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

#include <remill/Arch/ARM/Arch.h>
#include <remill/Arch/ARM/Runtime/State.h>
#include <remill/Arch/Capstone/ARMDisassembler.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

namespace remill {

struct ARMArch::PrivateData final {
  OSName operating_system;
  ArchName architecture;

  std::unique_ptr<CapstoneDisassembler> disassembler;
};

// TODO(pag): We pretend that these are singletons, but they aren't really!
const Arch *Arch::GetARM(OSName os_name_, ArchName arch_name_) {
  return new ARMArch(os_name_, arch_name_);
}

ARMArch::ARMArch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_), d(new PrivateData) {
  CHECK(os_name_ == kOSLinux)
      << "The ARM module does not support the specified operating system";

  CHECK(arch_name_ == kArchARM || arch_name_ == kArchARM64)
      << "The ARM module does not support the specified architecture";

  d->operating_system = os_name_;
  d->architecture = arch_name_;

  bool is_64_bits = (arch_name_ == kArchARM64);
  d->disassembler = llvm::make_unique<ARMDisassembler>(is_64_bits);
}

ARMArch::~ARMArch(void) {}

void ARMArch::PrepareModule(llvm::Module *mod) const {
  std::string dl;
  std::string triple;

  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
      break;
    case kOSLinux:
      switch (arch_name) {
        case kArchInvalid: {
          LOG(FATAL)
              << "Cannot convert module for an unrecognized architecture.";
          break;
        }

        case kArchARM64: {
          dl = "e-m:e-i64:64-i128:128-n32:64-S128";
          triple = "arm64-unknown";
          break;
        }

        case kArchARM: {
          LOG(FATAL) << "arm is not supported!";
          break;
        }

        default:
          break;
      }
      break;

    default:
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

uint64_t ARMArch::ProgramCounter(const ArchState *state) const {
  auto state_ptr = reinterpret_cast<const State *>(state);
  return (d->architecture == kArchARM) ? state_ptr->gpr.rip.dword
                                       : state_ptr->gpr.rip.qword;

  /* auto instr = new Instruction;
  std::unique_ptr<Instruction> instr(new Instruction);
  Decode(instr, address, instr_bytes);
  std::cout << std::hex << "Decoding ARM instructions done " << instr->next_pc
  << std::endl;
  std::cout << std::hex << instr->function << "\t" << instr->disassembly <<
  std::endl;
  return instr.release();*/
}

Instruction *ARMArch::DecodeInstruction(uint64_t address,
                                        const std::string &instr_bytes) const {
  std::unique_ptr<Instruction> remill_instr(new Instruction);
  if (!d->disassembler->Decode(remill_instr, address, instr_bytes))
    return nullptr;

  return remill_instr.release();
}

}  // namespace remill
