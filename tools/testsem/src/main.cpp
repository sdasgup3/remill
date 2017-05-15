#include "utils.h"

#include <cinttypes>
#include <iostream>
#include <stdexcept>
#include <unordered_map>

#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/iterator_range.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/JITSymbol.h>
#include <llvm/ExecutionEngine/Orc/CompileUtils.h>
#include <llvm/ExecutionEngine/Orc/IRCompileLayer.h>
#include <llvm/ExecutionEngine/Orc/LambdaResolver.h>
#include <llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h>
#include <llvm/ExecutionEngine/RTDyldMemoryManager.h>
#include <llvm/ExecutionEngine/RuntimeDyld.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <capstone/capstone.h>

int main(int argc, char *argv[], char *envp[]) {
  static_cast<void>(argc);
  static_cast<void>(argv);
  static_cast<void>(envp);

  std::string semantics_path =
      "/home/alessandro/Projects/TrailOfBits/"
      "build-remill-Clang_GDB_with_Qt_5_8_0_x64-Debug/remill/Arch/X86/Runtime/"
      "amd64.bc";

  // initialize the x86 target
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmPrinter();
  llvm::InitializeNativeTargetAsmParser();

  // load the instruction semantics and prepare the module set for the jit
  llvm::LLVMContext llvm_context;

  std::vector<std::unique_ptr<llvm::Module>> module_set;
  llvm::Module *llvm_module = nullptr;

  {
    std::unique_ptr<llvm::Module> module;
    if (!LoadLLVMBitcode(module, semantics_path, llvm_context))
      throw std::runtime_error("Failed to load the semantics file");

    llvm_module = module.get();
    module_set.push_back(std::move(module));
  }

  // make a map of the functions we are interested in
  std::unordered_map<std::string, std::string> semantic_function_map;

  for (const auto &global_variable : llvm_module->globals()) {
    std::string isel_name = global_variable.getName().str();
    if (isel_name.find("ISEL_") != 0) continue;

    isel_name = isel_name.substr(5);

    auto isel_variable_value = global_variable.getOperand(0);
    auto lifted_function_name = isel_variable_value->getName();
    if (lifted_function_name.empty()) continue;

    semantic_function_map[isel_name] = lifted_function_name;
  }

  // initialize the jit
  llvm::orc::ObjectLinkingLayer<> obj_linking_Layer;

  llvm::EngineBuilder engine_builder;
  engine_builder.setOptLevel(llvm::CodeGenOpt::Aggressive);

  std::unique_ptr<llvm::TargetMachine> target_machine(
      engine_builder.selectTarget());

  llvm::orc::IRCompileLayer<decltype(obj_linking_Layer)> compile_layer(
      obj_linking_Layer, llvm::orc::SimpleCompiler(*target_machine));

  auto Resolver = llvm::orc::createLambdaResolver(
      [&](const std::string &symbol_name) {
        auto symbol = compile_layer.findSymbol(symbol_name, false);
        if (!symbol) return llvm::JITSymbol(nullptr);

        return symbol;
      },

      [](const std::string &) { return nullptr; });

  compile_layer.addModuleSet(std::move(module_set),
                             llvm::make_unique<llvm::SectionMemoryManager>(),
                             std::move(Resolver));

  // disassemble each semantic function
  csh capstone;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone) != CS_ERR_OK)
    throw std::runtime_error("Failed to initialize capstone");

  for (const auto &sem_func_pair : semantic_function_map) {
    std::string isel_name = sem_func_pair.first;
    std::string lifted_name = sem_func_pair.second;

    auto semantic_function_symbol =
        compile_layer.findSymbol(lifted_name, false);

    const std::uint8_t *function_bytes_ptr =
        reinterpret_cast<const std::uint8_t *>(
            semantic_function_symbol.getAddress());
    if (function_bytes_ptr == nullptr) continue;

    cs_insn *instruction = nullptr;
    cs_disasm(capstone, function_bytes_ptr, 16,
              semantic_function_symbol.getAddress(), 1, &instruction);
    cs_free(instruction, 1);

    std::cout << isel_name << std::endl;
    printf("0x%" PRIx64 ":\t%s\t\t%s\n", instruction->address,
           instruction->mnemonic, instruction->op_str);
  }

  return 0;
}
