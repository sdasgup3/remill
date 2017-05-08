#include "elfparser.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <list>
#include <vector>

typedef std::unique_ptr<int, void (*)(int *)> FileStream;
typedef std::unique_ptr<Elf, void (*)(Elf *)> ElfObject;

void FileStreamDeleter(int *handle);
void ElfObjectDeleter(Elf *obj);

struct ELFParser::PrivateData final {
  PrivateData()
      : file_stream(nullptr, FileStreamDeleter),
        image_object(nullptr, ElfObjectDeleter) {}

  std::string image_path;

  FileStream file_stream;
  ElfObject image_object;

  GElf_Ehdr image_header;
  std::size_t address_size;
  bool little_endian;
  std::list<GElf_Shdr> section_header_list;

  std::uintmax_t virtual_address;
};

ELFParser::ELFParser(const std::string &image_path) : d(new PrivateData) {
  // open the image and create the base elf object
  d->image_path = image_path;

  int image_file_handle = open(image_path.data(), O_RDONLY, 0);
  if (image_file_handle == -1)
    throw std::runtime_error("ELFParser: Failed to open the input file");

  d->file_stream.reset(reinterpret_cast<int *>(image_file_handle));

  if (elf_version(EV_CURRENT) == EV_NONE)
    throw std::runtime_error("ELFParser: Failed to initialize the ELF library");

  Elf *image_object = elf_begin(image_file_handle, ELF_C_READ, nullptr);
  if (image_object == nullptr)
    throw std::runtime_error("ELFParser: Failed to create the ELF object");

  d->image_object.reset(image_object);

  // attempt to parse the header
  parseHeader();

  if (d->image_header.e_ident[EI_DATA] == ELFDATA2LSB)
    d->little_endian = true;
  else if (d->image_header.e_ident[EI_DATA] == ELFDATA2MSB)
    d->little_endian = false;
  else
    throw std::runtime_error("Unrecognized endianness specified");

  parseSectionList();
  d->virtual_address = 0;
}

ELFParser::~ELFParser() {}

bool ELFParser::is64bit() const noexcept { return (d->address_size == 64); }

bool ELFParser::littleEndian() const noexcept { return d->little_endian; }

std::uint16_t ELFParser::architecture() const noexcept {
  return d->image_header.e_machine;
}

std::uintmax_t ELFParser::entryPoint() const noexcept {
  return static_cast<std::uintmax_t>(d->image_header.e_entry);
}

void ELFParser::read(std::uint8_t *buffer, std::size_t size) const {
  while (size > 0) {
    std::uintmax_t offset;
    std::size_t available_bytes;

    if (!offsetFromVirtualAddress(offset, available_bytes,
                                  d->virtual_address)) {
      std::memset(buffer, 0, size);
      d->virtual_address += size;

      return;
    }

    std::intmax_t file_handle =
        reinterpret_cast<std::intmax_t>(d->file_stream.get());
    if (lseek(static_cast<int>(file_handle), static_cast<off_t>(offset),
              SEEK_SET) == -1)
      throw std::runtime_error(
          "ELFParser: Failed to seek to the required offset");

    std::size_t bytes_to_read = std::min(size, available_bytes);
    if (::read(static_cast<int>(file_handle), buffer, bytes_to_read) == -1)
      throw std::runtime_error(
          "ELFParser: Failed to read the executable image");

    size -= bytes_to_read;
    buffer += bytes_to_read;
  }
}

void ELFParser::read(std::uintmax_t virtual_address, std::uint8_t *buffer,
                     std::size_t size) const {
  seek(virtual_address);
  read(buffer, size);
}

void ELFParser::seek(std::uintmax_t virtual_address) const noexcept {
  d->virtual_address = virtual_address;
}

std::uintmax_t ELFParser::tell() const noexcept { return d->virtual_address; }

std::uint8_t ELFParser::u8() const {
  std::uint8_t value;
  read(&value, sizeof(value));

  return value;
}

std::uint16_t ELFParser::u16() const {
  std::uint16_t value;
  read(reinterpret_cast<std::uint8_t *>(&value), sizeof(value));

  return value;
}

std::uint32_t ELFParser::u32() const {
  std::uint32_t value;
  read(reinterpret_cast<std::uint8_t *>(&value), sizeof(value));

  return value;
}

std::uint64_t ELFParser::u64() const {
  std::uint64_t value;
  read(reinterpret_cast<std::uint8_t *>(&value), sizeof(value));

  return value;
}

std::int8_t ELFParser::i8() const { return static_cast<std::int8_t>(u8()); }

std::int16_t ELFParser::i16() const { return static_cast<std::int16_t>(u16()); }

std::int32_t ELFParser::i32() const { return static_cast<std::int32_t>(u32()); }

std::int64_t ELFParser::i64() const { return static_cast<std::int64_t>(u64()); }

void ELFParser::parseHeader() {
  if (elf_kind(d->image_object.get()) != ELF_K_ELF)
    throw std::runtime_error("ELFParser: Unsupported file.");

  if (gelf_getehdr(d->image_object.get(), &d->image_header) == nullptr)
    throw std::runtime_error("ELFParser: Failed to read the ELF header");

  int elf_class = gelf_getclass(d->image_object.get());
  if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64)
    throw std::runtime_error("ELFParser: Unsupported ELF class");

  d->address_size = (elf_class == ELFCLASS32) ? 32 : 64;
}

void ELFParser::parseSectionList() {
  Elf_Scn *section = nullptr;

  while (true) {
    section = elf_nextscn(d->image_object.get(), section);
    if (section == nullptr) {
      if (d->section_header_list.empty())
        throw std::runtime_error(
            "The section headers have been stripped out of the executable "
            "image!");

      break;
    }

    GElf_Shdr section_header;
    if (gelf_getshdr(section, &section_header) == nullptr)
      throw std::runtime_error(
          "ELFParser: Failed to retrieve the section headers");

    d->section_header_list.push_back(section_header);
  }
}

bool ELFParser::offsetFromVirtualAddress(std::uintmax_t &offset,
                                         std::size_t &available_bytes,
                                         std::uintmax_t virtual_address) const
    noexcept {
  offset = 0;
  available_bytes = 0;

  GElf_Shdr required_section_header = {};

  for (const auto &section_header : d->section_header_list) {
    if (virtual_address >= section_header.sh_addr &&
        virtual_address < section_header.sh_addr + section_header.sh_size) {
      required_section_header = section_header;
      break;
    }
  }

  if (required_section_header.sh_addr == 0) return false;

  offset = required_section_header.sh_offset +
           (virtual_address - required_section_header.sh_addr);
  available_bytes = required_section_header.sh_size - offset;

  return true;
}

void FileStreamDeleter(int *handle) {
  std::intmax_t real_handle =
      reinterpret_cast<std::intmax_t>(handle) & 0xFFFFFFFF;

  if (real_handle != 0) close(static_cast<int>(real_handle));
}

void ElfObjectDeleter(Elf *obj) {
  if (obj != nullptr) elf_end(obj);
}
