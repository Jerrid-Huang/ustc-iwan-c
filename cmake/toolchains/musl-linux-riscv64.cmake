# musl.cc cross toolchain for fully static Linux riscv64 (RISC-V 64-bit).
#   curl -sL https://musl.cc/riscv64-linux-musl-cross.tgz | tar xz -C /opt
#   cmake -B build \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/musl-linux-riscv64.cmake \
#     -DIWAN_MUSL_ROOT=/opt/riscv64-linux-musl-cross \
#     -DIWAN_OPENSSL_DIR=/path/to/musl-openssl -DIWAN_LINUX_STATIC=ON
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES IWAN_MUSL_ROOT)
set(IWAN_MUSL_ROOT "" CACHE PATH "musl.cc toolchain root (dir containing bin/<triplet>-gcc)")
if(NOT IWAN_MUSL_ROOT)
  message(FATAL_ERROR "musl-linux-riscv64.cmake: set -DIWAN_MUSL_ROOT=<musl.cc toolchain root>")
endif()
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)
set(CMAKE_C_COMPILER "${IWAN_MUSL_ROOT}/bin/riscv64-linux-musl-gcc")
