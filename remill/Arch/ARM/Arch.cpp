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
#include <iostream>

#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/ARM/Arch.h"
#include "remill/Arch/ARM/Runtime/State.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"
#include <remill/Arch/Capstone/ARMDisassembler.h>


namespace remill {
namespace {

}


struct ARMArch::PrivateData final {
  OSName os_name_;
  ArchName arch_name_;
  std::unique_ptr<CapstoneDisassembler> disass_;
};

const Arch *Arch::GetARM(
    OSName os_name_, ArchName arch_name_) {
  return new ARMArch(os_name_, arch_name_);
}

ARMArch::ARMArch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_) {
  data->os_name_ = os_name_;
  data->arch_name_ = arch_name_;
  data->disass_ = llvm::make_unique<ARMDisassembler>(arch_name_ == kArchARM64);
}

ARMArch::~ARMArch(void) {}

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
void ARMArch::PrepareModule(llvm::Module *mod) const {
  std::string dl;
  std::string triple;
  std::cout << std::hex << "Prepare module to load " << std::endl;

  switch(os_name){
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
      break;
    case kOSLinux:
      switch (arch_name) {
        case kArchInvalid:
          LOG(FATAL)
              << "Cannot convert module for an unrecognized architecture.";
            break;
        case kArchARM64:
          dl = "e-m:e-i64:64-i128:128-n32:64-S128";
          triple = "arm64-unknown";
          break;
        case kArchARM64_BE:
          LOG(FATAL)
              << "aarch64_be is not supported!";
          break;
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

// Decode ARM instructions.
Instruction *ARMArch::DecodeInstruction(uint64_t address, const std::string &instr_bytes) const {
  auto instr = new Instruction;
  data->disass_->Decode(std::unique_ptr<Instruction> (instr), address, instr_bytes);
  std::cout << std::hex << "Decoding ARM instructions done " << instr->next_pc << std::endl;
  std::cout << std::hex << instr->function << "\t" << instr->disassembly << std::endl;



  //uint64_t app_pc = address;
  //uint64_t next_pc;
  //const uint8_t* code = reinterpret_cast<const uint8_t *>(instr_bytes.data());
  //std::cout << std::hex << "Decoding ARM instructions " << app_pc << std::endl;
 // next_pc = ARMD_Decode(drcontext, code, address, instr);
  instr->arch_name = arch_name;
  instr->pc = address;
  //instr->next_pc = next_pc;
  //std::cout << std::hex << "Decoding ARM instructions done " << next_pc << std::endl;

  return instr;
}


uint64_t ARMArch::ProgramCounter(const ArchState *state_) const {
  auto state = reinterpret_cast<const State *>(state_);
  if (32 == address_size) {
    return state->gpr.rip.dword;
  } else {
    return state->gpr.rip.qword;
  }
}

}
