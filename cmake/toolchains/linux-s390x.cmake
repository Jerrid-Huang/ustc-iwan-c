# Debian/Ubuntu cross toolchain for Linux s390x (IBM Z).
#   apt install gcc-s390x-linux-gnu libc6-dev-s390x-cross
#   apt install s390x-linux-gnu-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-s390x.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR s390x)
set(CMAKE_C_COMPILER s390x-linux-gnu-gcc)
set(CMAKE_C_COMPILER_TARGET s390x-linux-gnu)
