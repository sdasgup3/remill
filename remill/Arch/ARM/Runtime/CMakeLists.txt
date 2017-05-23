cmake_minimum_required (VERSION 3.2)
project(arm_runtime BC)

set(ARMRUNTIME_SOURCEFILES
    Instructions.cpp
    BasicBlock.cpp
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

set(ARMRUNTIME_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

function (add_runtime_helper target_name address_bit_size little_endian)
    message(" > Generating runtime target: ${target_name}")

    add_runtime(${target_name} SOURCES ${ARMRUNTIME_SOURCEFILES} ADDRESS_SIZE ${address_bit_size})
    target_include_directories(${target_name} PRIVATE ${ARMRUNTIME_INCLUDEDIRECTORIES})

    if (little_endian)
        target_compile_definitions(${target_name} PRIVATE "LITTLE_ENDIAN=1")
    else ()
        target_compile_definitions(${target_name} PRIVATE "LITTLE_ENDIAN=0")
    endif ()
endfunction ()

add_runtime_helper(arm32be 32 0)
add_runtime_helper(arm32le 32 1)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_runtime_helper(arm64be 64 0)
    add_runtime_helper(arm64le 64 1)
endif ()
