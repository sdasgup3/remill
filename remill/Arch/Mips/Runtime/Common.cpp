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

#include "remill/Arch/Mips/Runtime/Common.h"

namespace {
// Takes the place of an unsupported instruction.
DEF_SEM(HandleUnsupported) {
  return __remill_sync_hyper_call(memory, state,
                                  SyncHyperCall::kMipsEmulateInstruction);
}

// Takes the place of an invalid instruction.
DEF_SEM(HandleInvalidInstruction) {
  HYPER_CALL = AsyncHyperCall::kInvalidInstruction;
  return memory;
}

}  // namespace

// Takes the place of an unsupported instruction.
DEF_ISEL(UNSUPPORTED_INSTRUCTION) = HandleUnsupported;
DEF_ISEL(INVALID_INSTRUCTION) = HandleInvalidInstruction;
