#include "elfparser.h"

#include <iostream>
#include <array>
#include <iomanip>

#include <remill/Arch/Instruction.h>
#include <remill/Arch/Mips/Disassembler.h>

int main(int argc, char *argv[], char *envp[]) {
  static_cast<void>(envp);

  if (argc != 2) {
    std::cout << "Usage:\n"
                 "\tmipsdec /path/to/mips-executable\n";

    return 1;
  }

  const char *path = argv[1];

  try {
    ELFParser elf_parser(path);
    remill::MipsDisassembler disassembler(elf_parser.is64bit());

    std::uintmax_t virtual_address = elf_parser.entryPoint();

    for (int i = 0; i < 10; i++) {
      std::array<std::uint8_t, 32> buffer;
      elf_parser.read(virtual_address, buffer.data(), buffer.size());

      auto capstone_instr = disassembler.Disassemble(virtual_address, buffer.data(), buffer.size());

      std::cout << std::setfill('0') << std::setw(16) << virtual_address << "  ";
      std::cout << std::setfill(' ') << std::setw(10) << capstone_instr->mnemonic << " ";
      std::cout << std::setfill(' ') << std::setw(32) << capstone_instr->op_str << "    ";
      std::cout << disassembler.SemanticFunctionName(capstone_instr) << std::endl;

      virtual_address += capstone_instr->size;
    }

    return 0;
  } catch (const std::exception &exception) {
    std::cerr << "An exception has occurred and the program must terminate.\n===\n" << exception.what() << std::endl;
    return 1;
  }
}
