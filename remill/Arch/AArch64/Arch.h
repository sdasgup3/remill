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

#ifndef REMILL_ARCH_AARCH64_ARCH_H_
#define REMILL_ARCH_AARCH64_ARCH_H_

#include <memory>
#include <string>

#include <capstone/capstone.h>

#include "remill/Arch/Arch.h"

namespace remill {

class ARMArch : public Arch {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

 public:
  ARMArch(OSName os_name_, ArchName arch_name_);
  ARMArch(void) = delete;
  virtual ~ARMArch(void);

  //
  // remill::Arch interface
  //

  void PrepareModule(llvm::Module *mod) const override;

  std::unique_ptr<Instruction> DecodeInstruction(
      uint64_t address, const std::string &instr_bytes) const override;
};

}  // namespace remill

#endif  // REMILL_ARCH_AARCH64_ARCH_H_
