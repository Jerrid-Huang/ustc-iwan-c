# MinGW-w64 cross toolchain for Windows i686 / 32-bit x86 (posix threads).
#   apt install gcc-mingw-w64-i686
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/windows-i686.cmake \
#         -DIWAN_OPENSSL_DIR=/path/to/mingw-i686-openssl -DIWAN_STATIC=ON
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i686)
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)
set(CMAKE_C_COMPILER_TARGET i686-w64-mingw32)
