/*
  This tool performs (A REALLY STUPID) recursive descent disassembly, checking
  whether the encountered opcodes are implemented inside the given runtime file
  or not.

  The tool requires the architecture module to implement the following two (pure
  virtual) methods:

   > CapstoneDisassembler::InstructionCategory
   > CapstoneDisassembler::InstructionOperands

  You need to support function returns and direct function calls for the first
  method, and immediate operands for the second one. Example: "ret" and "call
  immediate". Take a look at MipsDisassembler.cpp for an example.
*/

#include "elfparser.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <vector>

#include <remill/Arch/Capstone/MipsDisassembler.h>
#include <remill/Arch/Instruction.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/SourceMgr.h>

void PrintCapstoneInstruction(
    std::size_t address_size,
    const remill::CapstoneInstructionPtr &capstone_instr,
    const std::string &semantic_function) noexcept;
std::unique_ptr<llvm::Module> LoadLLVMBitcode(const std::string &path,
                                              llvm::LLVMContext &llvm_context);
bool IsFunctionSemanticsImplemented(
    const std::string &semantic_function,
    const std::unique_ptr<llvm::Module> &llvm_module) noexcept;

int main(int argc, char *argv[], char *envp[]) {
  static_cast<void>(envp);

  if (argc != 3) {
    std::cout << "This is a debugging/development tool for the "
                 "CapstoneDisassembler module of remill.\n\n"
                 "Usage:\n"
                 "\tmipsdec /path/to/executable /path/to/semantics.bc\n";

    return 1;
  }

  const char *image_path = argv[1];
  const char *semantics_path = argv[2];

  std::cout << "Image path: " << image_path << std::endl;
  std::cout << "Semantics: " << semantics_path << std::endl;

  std::cout << "\nOpcodes marked with 'x' are not implemented in the specified "
               "runtime.\n\n";

  try {
    ELFParser elf_parser(image_path);
    switch (elf_parser.architecture()) {
      case EM_ARM:
      case EM_AARCH64:
        throw std::runtime_error("ARM support is not yet implemented");

      case EM_MIPS:
      case EM_MIPS_RS3_LE:
      case EM_MIPS_X:
        break;

      default:
        throw std::runtime_error("Unsupported architecture!");
    }

    llvm::LLVMContext llvm_context;
    auto llvm_module = LoadLLVMBitcode(semantics_path, llvm_context);

    remill::MipsDisassembler disassembler(elf_parser.is64bit());

    std::vector<std::uintmax_t> address_queue = {elf_parser.entryPoint()};
    std::vector<std::uintmax_t> function_list;
    std::size_t address_size = elf_parser.is64bit() ? 8 : 4;

    while (!address_queue.empty()) {
      std::uintmax_t virtual_address = address_queue.back();
      address_queue.pop_back();

      function_list.push_back(virtual_address);

      std::cout << "   proc sub_" << std::hex << virtual_address << std::endl;

      while (true) {
        std::array<std::uint8_t, 32> buffer;
        elf_parser.read(virtual_address, buffer.data(), buffer.size());

        auto capstone_instr = disassembler.Disassemble(
            virtual_address, buffer.data(), buffer.size());

        std::vector<remill::Operand> operand_list;
        if (!disassembler.InstructionOperands(operand_list, capstone_instr))
          throw std::runtime_error(
              "Failed to convert the instruction operands");

        std::string semantic_function =
            disassembler.SemanticFunctionName(capstone_instr, operand_list);

        if (IsFunctionSemanticsImplemented(semantic_function, llvm_module))
          std::cout << "   ";
        else
          std::cout << "x  ";

        PrintCapstoneInstruction(address_size, capstone_instr,
                                 semantic_function);
        virtual_address += capstone_instr->size;

        auto instr_category = disassembler.InstructionCategory(capstone_instr);
        if (instr_category ==
            remill::Instruction::kCategoryDirectFunctionCall) {
          std::vector<remill::Operand> operand_list;
          if (disassembler.InstructionOperands(operand_list, capstone_instr) &&
              operand_list.size() == 1 &&
              operand_list[0].type == remill::Operand::kTypeImmediate) {
            std::uintmax_t call_destination = operand_list[0].imm.val;

            if (std::find(function_list.begin(), function_list.end(),
                          call_destination) == function_list.end())
              address_queue.push_back(call_destination);
          }
        } else if (instr_category ==
                   remill::Instruction::kCategoryFunctionReturn) {
          break;
        }
      }

      std::cout << "   endproc\n\n";
    }

    return 0;
  } catch (const std::exception &exception) {
    std::cerr
        << "An exception has occurred and the program must terminate.\n===\n"
        << exception.what() << std::endl;
    return 1;
  }
}

void PrintCapstoneInstruction(
    std::size_t address_size,
    const remill::CapstoneInstructionPtr &capstone_instr,
    const std::string &semantic_function) noexcept {
  std::cout << "  " << std::hex << std::setfill('0')
            << std::setw(static_cast<int>(address_size * 2))
            << capstone_instr->address << "  ";

  for (std::uint16_t i = 0; i < capstone_instr->size; i++)
    std::cout << std::setfill('0') << std::setw(2) << std::hex
              << static_cast<int>(capstone_instr->bytes[i]);
  std::cout << "  ";

  std::cout << std::setfill(' ') << std::setw(10) << capstone_instr->mnemonic
            << " ";
  std::cout << std::setfill(' ') << std::setw(24) << capstone_instr->op_str
            << "    ";
  std::cout << semantic_function << std::endl;
}

std::unique_ptr<llvm::Module> LoadLLVMBitcode(const std::string &path,
                                              llvm::LLVMContext &llvm_context) {
  llvm::SMDiagnostic error_output;

  auto llvm_module = llvm::parseIRFile(path, error_output, llvm_context);
  if (!llvm_module) {
    std::stringstream error_message;
    error_message << "Failed to parse the bitcode file! Error: "
                  << error_message.str();

    throw std::runtime_error(error_message.str());
  }

  auto error = llvm_module->materializeAll();
  if (error) throw std::runtime_error("Failed to load the bitcode module!");

  return llvm_module;
}

bool IsFunctionSemanticsImplemented(
    const std::string &semantic_function,
    const std::unique_ptr<llvm::Module> &llvm_module) noexcept {
  std::string function_name = std::string("ISEL_") + semantic_function;
  return (llvm_module->getGlobalVariable(function_name, true) != nullptr);
}
