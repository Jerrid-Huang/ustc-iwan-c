# Debian/Ubuntu cross toolchain for Linux riscv64 (RISC-V 64-bit).
#   apt install gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
#   apt install riscv64-linux-gnu-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-riscv64.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv64)
set(CMAKE_C_COMPILER riscv64-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET riscv64-linux-gnu)
