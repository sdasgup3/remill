cmake_minimum_required (VERSION 3.2)
project(mips_runtime BC)

set(MIPSRUNTIME_SOURCEFILES
    BasicBlock.cpp
    Common.cpp

    Semantics/ADDIU.cpp
    Semantics/SW.cpp
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

set(MIPSRUNTIME_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

function (add_runtime_helper target_name address_bit_size)
    message(" > Generating runtime target: ${target_name}")

    add_runtime(${target_name} SOURCES ${MIPSRUNTIME_SOURCEFILES} ADDRESS_SIZE ${address_bit_size})
    target_include_directories(${target_name} PRIVATE ${MIPSRUNTIME_INCLUDEDIRECTORIES})
endfunction ()

add_runtime_helper(mips32 32)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_runtime_helper(mips64 64)
endif ()
