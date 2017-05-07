cmake_minimum_required(VERSION 3.5)
project(mipsdec CXX)

#
# compiler settings
#

# compiler and linker flags
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 14)

set(MIPSDEC_CXXWARNINGS "-pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")
set(MIPSDEC_CXXFLAGS "${GLOBAL_CXXWARNINGS} -fPIC -fvisibility=hidden")

# build type
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebugInfo")
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(MIPSDEC_CXXFLAGS "${MIPSDEC_CXXFLAGS} -gdwarf-2 -g3")
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(MIPSDEC_CXXFLAGS "${MIPSDEC_CXXFLAGS} -O0")
else ()
    set(MIPSDEC_CXXFLAGS "${MIPSDEC_CXXFLAGS} -O3")
endif ()

#
# libraries
#

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

# remill
set(MIPSDEC_SOURCEFILES

    ${CMAKE_SOURCE_DIR}/remill/Arch/Capstone/CapstoneDisassembler.cpp
    ${CMAKE_SOURCE_DIR}/remill/Arch/Capstone/MipsDisassembler.cpp
    ${CMAKE_SOURCE_DIR}/remill/Arch/Capstone/ARMDisassembler.cpp
    ${CMAKE_SOURCE_DIR}/remill/Arch/Instruction.cpp
)

set(MIPSDEC_INCLUDEDIRECTORIES
    ${CMAKE_SOURCE_DIR}
)

# google log module
find_package(glog REQUIRED)
list(APPEND MIPSDEC_LIBRARIES glog::glog)

# todo: capstone
list(APPEND MIPSDEC_LIBRARIES capstone)

# todo: libelf/gelf
list(APPEND MIPSDEC_LIBRARIES elf)

# llvm
if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
endif ()

if (DEFINED LLVM_INSTALL_PREFIX)
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm/")
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake/")

    message(STATUS "Using LLVM_INSTALL_PREFIX hints for find_package(LLVM): ${FINDPACKAGE_LLVM_HINTS}")
endif ()

find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

set(LLVM_LIBRARIES LLVMCore LLVMSupport LLVMIRReader)
list(APPEND MIPSDEC_LIBRARIES ${LLVM_LIBRARIES})

list(APPEND MIPSDEC_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND MIPSDEC_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

#
# target settings
#

set(MIPSDEC_SOURCEFILES
    ${MIPSDEC_SOURCEFILES}

    src/main.cpp

    src/elfparser.h
    src/elfparser.cpp
)

add_executable(${PROJECT_NAME} ${MIPSDEC_SOURCEFILES})

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${MIPSDEC_CXXFLAGS})
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE ${MIPSDEC_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${MIPSDEC_DEFINITIONS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${MIPSDEC_LIBRARIES})

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}/bin")
install(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin)
