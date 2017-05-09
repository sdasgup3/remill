/*
  This tool performs (A REALLY STUPID) recursive descent disassembly, checking
  whether the encountered opcodes are implemented inside the given runtime file
  or not.

  The tool requires the architecture module to implement the following two (pure
  virtual) methods:

   > CapstoneDisassembler::InstrCategory
   > CapstoneDisassembler::InstrOps

  You need to support function returns and direct function calls for the first
  method, and immediate operands for the second one. Example: "ret" and "call
  immediate". Take a look at MipsDisassembler.cpp for an example.
*/

#include "elfparser.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <vector>

#include <remill/Arch/Capstone/ARMDisassembler.h>
#include <remill/Arch/Capstone/MipsDisassembler.h>
#include <remill/Arch/Instruction.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/SourceMgr.h>

void PrintCapInstr(std::size_t address_size,
                   const remill::CapInstrPtr &cap_instr,
                   const std::string &sem_func) noexcept;
std::unique_ptr<llvm::Module> LoadLLVMBitcode(const std::string &path,
                                              llvm::LLVMContext &llvm_ctx);
bool IsFuncSemImplemented(
    const std::string &sem_func,
    const std::unique_ptr<llvm::Module> &llvm_module) noexcept;

int main(int argc, char *argv[], char *envp[]) {
  static_cast<void>(envp);

  if (argc != 3) {
    std::cout << "This is a debugging/development tool for the "
                 "CapstoneDisassembler module of remill. It is "
                 "best to use it with test executables compiled "
                 "using -nostdlib\n\n"
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
    llvm::LLVMContext llvm_context;
    auto llvm_module = LoadLLVMBitcode(semantics_path, llvm_context);

    ELFParser elf_parser(image_path);
    auto entry_point = elf_parser.entryPoint();
    auto arch = elf_parser.architecture();

    std::unique_ptr<remill::CapstoneDisassembler> disasm;
    if (arch == EM_ARM || arch == EM_AARCH64) {
      bool enable_thumb_mode = false;
      if ((entry_point & 1) != 0) {
        entry_point--;
        enable_thumb_mode = true;
      }

      disasm.reset(
          new remill::ARMDisassembler(elf_parser.is64bit(), enable_thumb_mode));
    } else if (arch == EM_MIPS || arch == EM_MIPS_RS3_LE || arch == EM_MIPS_X) {
      disasm.reset(new remill::MipsDisassembler(elf_parser.is64bit()));
    } else {
      throw std::runtime_error("Unsupported architecture");
    }

    std::cout << "Entry point located at virtual address 0x" << std::hex
              << entry_point << "\n\n";

    std::vector<std::uintmax_t> addr_queue = {entry_point};
    std::vector<std::uintmax_t> func_list;
    std::size_t address_size = elf_parser.is64bit() ? 8 : 4;

    while (!addr_queue.empty()) {
      std::uintmax_t virtual_address = addr_queue.back();
      addr_queue.pop_back();

      func_list.push_back(virtual_address);

      std::cout << "   proc sub_" << std::hex << virtual_address << std::endl;

      while (true) {
        std::array<std::uint8_t, 32> buffer;
        elf_parser.read(virtual_address, buffer.data(), buffer.size());

        auto capstone_instr =
            disasm->Disassemble(virtual_address, buffer.data(), buffer.size());
        if (!capstone_instr) {
          std::cout
              << "     ; Failed to disassemble the instruction at vaddr 0x"
              << std::hex << virtual_address << std::endl;
          break;
        }

        std::vector<remill::Operand> operand_list;
        if (!disasm->InstrOps(operand_list, capstone_instr))
          throw std::runtime_error(
              "Failed to convert the instruction operands");

        std::string semantic_function =
            disasm->SemFuncName(capstone_instr, operand_list);

        if (IsFuncSemImplemented(semantic_function, llvm_module))
          std::cout << "   ";
        else
          std::cout << "x  ";

        PrintCapInstr(address_size, capstone_instr, semantic_function);
        virtual_address += capstone_instr->size;

        auto instr_category = disasm->InstrCategory(capstone_instr);
        if (instr_category ==
            remill::Instruction::kCategoryDirectFunctionCall) {
          std::vector<remill::Operand> op_list;
          if (disasm->InstrOps(op_list, capstone_instr) &&
              op_list.size() == 1 &&
              op_list[0].type == remill::Operand::kTypeImmediate) {
            std::uintmax_t call_dest = op_list[0].imm.val;

            if (std::find(func_list.begin(), func_list.end(), call_dest) ==
                func_list.end())
              addr_queue.push_back(call_dest);
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

void PrintCapInstr(std::size_t address_size,
                   const remill::CapInstrPtr &cap_instr,
                   const std::string &sem_func) noexcept {
  std::cout << "  " << std::hex << std::setfill('0')
            << std::setw(static_cast<int>(address_size * 2))
            << cap_instr->address << "  ";

  std::stringstream instr_bytes;
  for (std::uint16_t i = 0; i < cap_instr->size; i++)
    instr_bytes << std::setfill('0') << std::setw(2) << std::hex
                << static_cast<int>(cap_instr->bytes[i]);
  std::cout << std::setfill(' ') << std::setw(8) << instr_bytes.str() << "  ";

  std::cout << std::setfill(' ') << std::setw(10) << cap_instr->mnemonic << " ";
  std::cout << std::setfill(' ') << std::setw(24) << cap_instr->op_str
            << "    ";
  std::cout << sem_func << std::endl;
}

std::unique_ptr<llvm::Module> LoadLLVMBitcode(const std::string &path,
                                              llvm::LLVMContext &llvm_ctx) {
  llvm::SMDiagnostic error_output;

  auto llvm_module = llvm::parseIRFile(path, error_output, llvm_ctx);
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

bool IsFuncSemImplemented(
    const std::string &sem_func,
    const std::unique_ptr<llvm::Module> &llvm_module) noexcept {
  std::string function_name = std::string("ISEL_") + sem_func;
  return (llvm_module->getGlobalVariable(function_name, true) != nullptr);
}
