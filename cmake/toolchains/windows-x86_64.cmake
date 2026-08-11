# MinGW-w64 cross toolchain for Windows x86_64 (posix threads model).
#   apt install gcc-mingw-w64-x86-64
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/windows-x86_64.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/mingw-openssl -DIWAN_STATIC=ON
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_C_COMPILER_TARGET x86_64-w64-mingw32)
