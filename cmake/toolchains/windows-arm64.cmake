# LLVM-MinGW (clang) cross toolchain for Windows ARM64.
# OpenSSL has no mingw-aarch64 Configure target, so use the prebuilt
# MSYS2 clangarm64 package (mingw-w64-clang-aarch64-openssl) as the
# sysroot:
#   curl -sL https://github.com/mstorsjo/llvm-mingw/releases/download/<ver>/llvm-mingw-<ver>-ucrt-ubuntu-20.04-x86_64.tar.xz | tar xJ -C /opt
#   curl -sL https://repo.msys2.org/mingw/clangarm64/mingw-w64-clang-aarch64-openssl-3.5.1-1-any.pkg.tar.zst | tar --zstd -x -C /opt/ossl-arm64
#   export PATH=/opt/llvm-mingw-<ver>-ucrt-ubuntu-20.04-x86_64/bin:$PATH
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/windows-arm64.cmake \
#         -DIWAN_OPENSSL_DIR=/opt/ossl-arm64/clangarm64 -DIWAN_STATIC=ON
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-w64-mingw32-clang)
set(CMAKE_C_COMPILER_TARGET aarch64-w64-mingw32)
