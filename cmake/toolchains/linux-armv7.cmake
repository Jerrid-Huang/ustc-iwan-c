# Debian/Ubuntu cross toolchain for Linux armv7 (ARM hard-float, armhf).
#   apt install gcc-arm-linux-gnueabihf libc6-dev-armhf-cross
#   apt install arm-linux-gnueabihf-linux-libc-dev   # optional: BPF headers
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/linux-armv7.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/cross-openssl ...
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR armv7l)
set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_C_COMPILER_TARGET arm-linux-gnueabihf)
