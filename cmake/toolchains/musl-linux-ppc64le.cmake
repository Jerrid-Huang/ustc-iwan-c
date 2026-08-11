# musl.cc cross toolchain for fully static Linux ppc64le (PowerPC 64-bit LE).
#   curl -sL https://musl.cc/powerpc64le-linux-musl-cross.tgz | tar xz -C /opt
#   cmake -B build \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/musl-linux-ppc64le.cmake \
#     -DIWAN_MUSL_ROOT=/opt/powerpc64le-linux-musl-cross \
#     -DIWAN_OPENSSL_DIR=/path/to/musl-openssl -DIWAN_LINUX_STATIC=ON
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES IWAN_MUSL_ROOT)
set(IWAN_MUSL_ROOT "" CACHE PATH "musl.cc toolchain root (dir containing bin/<triplet>-gcc)")
if(NOT IWAN_MUSL_ROOT)
  message(FATAL_ERROR "musl-linux-ppc64le.cmake: set -DIWAN_MUSL_ROOT=<musl.cc toolchain root>")
endif()
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc64le)
set(CMAKE_C_COMPILER "${IWAN_MUSL_ROOT}/bin/powerpc64le-linux-musl-gcc")
