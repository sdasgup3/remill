#ifndef REMILL_TOOLS_TESTSEM_SRC_UTILS_H_
#define REMILL_TOOLS_TESTSEM_SRC_UTILS_H_

#include <memory>
#include <string>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/SourceMgr.h>

typedef std::unique_ptr<llvm::Module> LLVMModulePtr;

bool LoadLLVMBitcode(std::unique_ptr<llvm::Module> &llvm_module,
                     const std::string &path, llvm::LLVMContext &llvm_ctx);

#endif  // REMILL_TOOLS_TESTSEM_SRC_UTILS_H_
