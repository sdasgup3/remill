#include "utils.h"
#include <sstream>

bool LoadLLVMBitcode(std::unique_ptr<llvm::Module> &llvm_module,
                     const std::string &path, llvm::LLVMContext &llvm_ctx) {
  llvm::SMDiagnostic error_output;

  llvm_module = llvm::parseIRFile(path, error_output, llvm_ctx);
  if (!llvm_module) return false;

  auto error = llvm_module->materializeAll();
  if (error) return false;

  return true;
}
