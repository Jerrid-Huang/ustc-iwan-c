# Debian/Ubuntu cross toolchain for Linux ppc64le (PowerPC 64-bit LE).
#   apt install gcc-powerpc64le-linux-gnu libc6-dev-ppc64el-cross
#   apt install powerpc64le-linux-gnu-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-ppc64le.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc64le)
set(CMAKE_C_COMPILER powerpc64le-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET powerpc64le-linux-gnu)
