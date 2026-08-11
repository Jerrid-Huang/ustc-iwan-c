# Debian/Ubuntu cross toolchain for Linux i686 (32-bit x86).
#   apt install gcc-i686-linux-gnu libc6-dev-i386-cross
#   apt install i686-linux-gnu-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-i686.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR i686)
set(CMAKE_C_COMPILER i686-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET i686-linux-gnu)
