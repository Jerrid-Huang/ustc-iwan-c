# Debian/Ubuntu cross toolchain for Linux aarch64 (ARM64).
#   apt install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
#   apt install aarch64-linux-gnu-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-aarch64.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET aarch64-linux-gnu)
