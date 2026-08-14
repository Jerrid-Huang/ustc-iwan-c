cmake_minimum_required(VERSION 3.16)

# iWAN — USTC campus-network VPN client/server (C11).
#
# Replaces the old hand-rolled Makefile. Semantics are preserved 1:1:
#   - Linux (native or cross): iwan-client, iwan-client-oidc, iwan-server.
#   - Windows (MinGW-w64, native or cross): iwan-client.exe,
#     iwan-client-oidc.exe; iwan-server stays Linux-only (TUN/iptables/BPF).
#   - The tun steering eBPF program (src/common/steer_bpf.c) is compiled
#     with clang -target bpf and embedded into the core library; when
#     that is impossible (no clang, no linux/bpf.h, or -DIWAN_BPF=OFF)
#     the build degrades to kernel automq steering (IWAN_NO_STEER_BPF).
#
# Typical invocations (see README "构建"):
#   cmake -B build && cmake --build build -j          # native Linux
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/musl-linux-aarch64.cmake \
#         -DIWAN_MUSL_ROOT=... -DIWAN_OPENSSL_DIR=... -DIWAN_LINUX_STATIC=ON
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/windows-x86_64.cmake \
#         -DIWAN_OPENSSL_DIR=... -DIWAN_STATIC=ON
#
# Options (all mirror Makefile variables):
#   IWAN_OPENSSL_DIR   OpenSSL sysroot with include/ + lib/ or lib64/
#                      (Makefile OPENSSL_DIR). Unset -> system OpenSSL.
#   IWAN_LINUX_STATIC  Linux: link fully static (musl toolchain or glibc
#                      -static); requires a static OpenSSL. (LINUX_STATIC=1)
#   IWAN_STATIC        Windows: statically link OpenSSL + winpthread +
#                      libssp so the exe needs no DLLs. (STATIC=1)
#   IWAN_BPF           Linux: compile+embed the tun steering eBPF program.
#   IWAN_WERROR        Treat compiler warnings as errors (CI).

project(iwan VERSION 0.1.1 LANGUAGES C)

# Release-by-default (CMAKE_C_FLAGS_RELEASE = -O3; no -DNDEBUG: the
# code has no runtime assert()s, only _Static_assert, which is
# NDEBUG-independent).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)          # -std=c11 (strict, as before)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(IWAN_LINUX_STATIC "Linux: link fully static binaries" OFF)
option(IWAN_STATIC       "Windows: statically link OpenSSL + runtime libs" OFF)
option(IWAN_BPF          "Linux: compile and embed the tun steering eBPF program" ON)
option(IWAN_WERROR       "Treat compiler warnings as errors" OFF)
set(IWAN_OPENSSL_DIR "" CACHE PATH "OpenSSL sysroot (include/ + lib/ or lib64/)")
# SOCKS-mode userspace TCP stack. lwip = vendored lwIP 2.2.1 (default);
# native = the hand-rolled netstack.c, retained one release cycle as a
# rollback target.
set(IWAN_TCP_STACK "lwip" CACHE STRING "SOCKS-mode TCP stack (lwip | native)")
set_property(CACHE IWAN_TCP_STACK PROPERTY STRINGS lwip native)

# ---------------------------------------------------------------------------
# Global flags — the old Makefile's CFLAGS/LDFLAGS, split per platform.
# ---------------------------------------------------------------------------
add_compile_options(-Wall -Wextra)

string(TOUPPER "${CMAKE_BUILD_TYPE}" _bt)
if(UNIX AND NOT APPLE)
  # Linux-only: -D_GNU_SOURCE and FORTIFY_SOURCE are glibc/musl-isms;
  # FORTIFY_SOURCE needs optimization (silently dropped at -O0, but gcc
  # warns). macOS (clang) gets only the stack protector below.
  add_compile_definitions(_GNU_SOURCE)
  add_compile_options(-fstack-protector-strong)
  if(_bt STREQUAL "RELEASE")
    add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
  endif()
elseif(APPLE)
  add_compile_options(-fstack-protector-strong)
elseif(WIN32)
  # MinGW-w64 (and MSYS2). -D_GNU_SOURCE and -fPIE are ELF-isms and
  # mingw's FORTIFY_SOURCE support is unreliable, so drop all three;
  # pin the Windows API version like the Makefile did.
  add_compile_definitions(_WIN32_WINNT=0x0601 WINVER=0x0601)
  add_compile_options(-fstack-protector-strong)
endif()

if(IWAN_WERROR)
  add_compile_options(-Werror)
endif()

if(WIN32)
  # PE hardening equivalents of the ELF flags. --high-entropy-va is an
  # x86_64-only linker feature.
  add_link_options(-Wl,--dynamicbase -Wl,--nxcompat)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    add_link_options(-Wl,--high-entropy-va)
  endif()
  if(IWAN_STATIC)
    add_link_options(-static-libgcc)
  endif()
elseif(UNIX AND NOT APPLE)
  add_link_options(-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack)
  if(IWAN_LINUX_STATIC)
    # -static is incompatible with -pie/-fPIE (and with PIE, glibc's
    # static startup would warn); drop both exactly like LINUX_STATIC=1.
    add_link_options(-static)
  else()
    add_compile_options(-fPIE)
    add_link_options(-pie)
  endif()
elseif(APPLE)
  # macOS: PIE is the default for clang builds; no -z flags on ld64.
endif()

# Binaries land in <repo>/bin like the Makefile produced (tests and CI
# rely on that path); archives stay in the build tree.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

find_package(Threads REQUIRED)       # -pthread everywhere (winpthreads on MinGW)

# ---------------------------------------------------------------------------
# Core library: everything in src/common (minus the platform splits and the
# BPF payload, which is generated). All consumers inherit Threads, OpenSSL
# and the platform system libs from here.
# ---------------------------------------------------------------------------
set(IWAN_CORE_SRCS
  src/common/addr.c
  src/common/auth.c
  src/common/buffer.c
  src/common/cli.c
  src/common/config.c
  src/common/crypto.c
  src/common/gcm.c
  src/common/https.c
  src/common/ipv4.c
  src/common/json.c
  src/common/port.c
  src/common/protocol.c
  src/common/proxy.c
  src/common/route.c
  src/common/socks.c
  src/common/socks_flow.c
  src/common/util.c)
if(WIN32)
  # tun_win.c replaces tun.c (wintun backend; tun.c is Linux TUN ioctls),
  # and server.c is Linux-only (TUN/iptables/BPF, see src/common/server.c).
  list(APPEND IWAN_CORE_SRCS src/common/tun_win.c)
elseif(APPLE)
  # macOS client: tun.c holds the generic code (reader pool, write
  # retry, close; its Linux-only ioctl/BPF parts are #ifdef __linux__),
  # tun_mac.c provides the utun open/attach/detach + name mapping.
  list(APPEND IWAN_CORE_SRCS src/common/tun.c src/common/tun_mac.c)
else()
  list(APPEND IWAN_CORE_SRCS src/common/server.c src/common/tun.c)
endif()

# Userspace TCP stack for the SOCKS mode (exactly one implementation).
if(IWAN_TCP_STACK STREQUAL "lwip")
  list(APPEND IWAN_CORE_SRCS src/common/lwip_bridge.c)
elseif(IWAN_TCP_STACK STREQUAL "native")
  list(APPEND IWAN_CORE_SRCS src/common/netstack.c)
else()
  message(FATAL_ERROR "IWAN_TCP_STACK must be 'lwip' or 'native' (got '${IWAN_TCP_STACK}')")
endif()

# ---------------------------------------------------------------------------
# Vendored lwIP 2.2.1 (third_party/lwip): the userspace TCP stack behind the
# SOCKS mode. NO_SYS=1 raw API, IPv4/TCP only, no socket layer — configured by
# third_party/lwip/lwipopts.h and third_party/lwip/port/arch/cc.h. Built as a
# standalone static lib; iwan_core links it (native netstack.c remains the
# IWAN_TCP_STACK=native alternative).
# ---------------------------------------------------------------------------
set(IWAN_LWIP_SRCS
  third_party/lwip/src/core/def.c
  third_party/lwip/src/core/inet_chksum.c
  third_party/lwip/src/core/init.c
  third_party/lwip/src/core/ip.c
  third_party/lwip/src/core/mem.c
  third_party/lwip/src/core/memp.c
  third_party/lwip/src/core/netif.c
  third_party/lwip/src/core/pbuf.c
  third_party/lwip/src/core/stats.c
  third_party/lwip/src/core/sys.c
  third_party/lwip/src/core/tcp.c
  third_party/lwip/src/core/tcp_in.c
  third_party/lwip/src/core/tcp_out.c
  third_party/lwip/src/core/timeouts.c
  third_party/lwip/src/core/ipv4/ip4.c
  third_party/lwip/src/core/ipv4/ip4_addr.c
  third_party/lwip/src/core/ipv4/ip4_frag.c)

add_library(lwip STATIC ${IWAN_LWIP_SRCS})
# Include order: third_party/lwip (lwipopts.h), third_party/lwip/include
# (lwip/*.h), third_party/lwip/port (arch/cc.h).
target_include_directories(lwip PUBLIC
  third_party/lwip
  third_party/lwip/include
  third_party/lwip/port)

# clang-only: vendored tcp.c:941 compares TCP_WND/2 (131072 with our
# 256KB window) against pcb->mss (u16_t), which
# -Wtautological-constant-out-of-range-compare (promoted by -Werror)
# flags as always-false. Upstream lwIP assumes TCP_WND fits u16; keep
# the vendored tree pristine and silence the diagnostic for the
# third-party library only (our own code still builds with -Werror).
# GCC/MinGW never see this flag (unknown-option warning would trip the
# CI grep gate).
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(lwip PRIVATE -Wno-tautological-constant-out-of-range-compare)
endif()

add_library(iwan_core STATIC ${IWAN_CORE_SRCS})
target_include_directories(iwan_core PUBLIC src/common)
target_link_libraries(iwan_core PUBLIC lwip)
if(IWAN_TCP_STACK STREQUAL "lwip")
  target_compile_definitions(iwan_core PUBLIC IWAN_TCP_STACK_LWIP=1)
endif()
# Threads::Threads is linked LAST: on MinGW it resolves to -lpthread, and
# in the IWAN_STATIC build it must come after the -Bstatic winpthread group
# (whose archive then satisfies the pthread refs and the trailing -lpthread
# import lib is dropped). Same ordering the old Makefile got from the gcc
# driver appending -lpthread at the end.

# OpenSSL. With IWAN_OPENSSL_DIR the sysroot is used verbatim (include/ +
# lib/ and lib64/, exactly like OPENSSL_DIR); otherwise the system
# OpenSSL is found. Windows static builds must scope ssl/crypto/winpthread/
# ssp into a -Bstatic group — a plain -static would also strip the
# ws2_32/iphlpapi import libs and fail to link (historical Makefile logic).
# winpthread/libssp are probed so clang-based toolchains (llvm-mingw) that
# lack one of them still link.
include(CheckLibraryExists)
if(WIN32 AND IWAN_STATIC)
  check_library_exists(winpthread pthread_create
                       "${CMAKE_C_IMPLICIT_LINK_DIRECTORIES}" IWAN_HAVE_WINPTHREAD)
  check_library_exists(ssp __stack_chk_fail
                       "${CMAKE_C_IMPLICIT_LINK_DIRECTORIES}" IWAN_HAVE_SSP)
  set(IWAN_STATIC_EXTRA "")
  if(IWAN_HAVE_WINPTHREAD)
    list(APPEND IWAN_STATIC_EXTRA -lwinpthread)
  endif()
  if(IWAN_HAVE_SSP)
    list(APPEND IWAN_STATIC_EXTRA -lssp)
  endif()
endif()
if(IWAN_OPENSSL_DIR)
  target_include_directories(iwan_core PUBLIC "${IWAN_OPENSSL_DIR}/include")
  target_link_directories(iwan_core PUBLIC
    "${IWAN_OPENSSL_DIR}/lib" "${IWAN_OPENSSL_DIR}/lib64")
  if(WIN32 AND IWAN_STATIC)
    target_link_libraries(iwan_core PUBLIC
      -Wl,-Bstatic -Wl,--start-group -lcrypto -lssl -Wl,--end-group
      ${IWAN_STATIC_EXTRA} -Wl,-Bdynamic)
  else()
    target_link_libraries(iwan_core PUBLIC ssl crypto)
  endif()
else()
  find_package(OpenSSL REQUIRED)
  if(WIN32 AND IWAN_STATIC)
    target_include_directories(iwan_core PUBLIC "${OPENSSL_INCLUDE_DIR}")
    target_link_libraries(iwan_core PUBLIC
      -Wl,-Bstatic -Wl,--start-group -lcrypto -lssl -Wl,--end-group
      ${IWAN_STATIC_EXTRA} -Wl,-Bdynamic)
  else()
    target_link_libraries(iwan_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

# Windows system import libs must come AFTER the static OpenSSL group:
# the group is an archive set whose winsock/iphlpapi references resolve
# only when ld reaches these import libs (a plain archive pass would
# leave __imp_WSACleanup & co. undefined).
if(WIN32)
  target_link_libraries(iwan_core PUBLIC ws2_32 iphlpapi bcrypt crypt32 shell32 mpr)
endif()
target_link_libraries(iwan_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# Tun steering eBPF (Linux only): clang -target bpf -> ELF object -> C
# array -> compiled into iwan_core. tun.c parses the embedded ELF section
# table at runtime (classifier/license sections, see steer_bpf.c).
# ---------------------------------------------------------------------------
set(IWAN_STEER_DIR "${CMAKE_CURRENT_BINARY_DIR}/steer")

function(iwan_enable_bpf)
  find_program(IWAN_CLANG NAMES clang)
  if(NOT IWAN_CLANG)
    message(WARNING "clang not found — building without tun steering eBPF "
                    "(IWAN_NO_STEER_BPF, kernel automq steering)")
    set(IWAN_BPF OFF PARENT_SCOPE)
    return()
  endif()

  # steer_bpf.c includes <linux/bpf.h> -> <asm/types.h>; the asm headers
  # live in the host gcc multiarch dir (/usr/include/<triplet>), which
  # clang does not search for the bpf target. Probe the candidate dirs
  # with the host gcc/cc (NOT the cross compiler: clang has no
  # -print-multiarch). The BPF program itself is arch-neutral, so the
  # host headers are correct even for cross-compiled Linux targets.
  set(_cands)
  execute_process(COMMAND gcc -print-multiarch
    OUTPUT_VARIABLE _ma ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _ma)
    execute_process(COMMAND cc -print-multiarch
      OUTPUT_VARIABLE _ma ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  if(_ma AND EXISTS "/usr/include/${_ma}")
    list(APPEND _cands "/usr/include/${_ma}")
  endif()
  if(CMAKE_C_COMPILER_TARGET AND EXISTS "/usr/${CMAKE_C_COMPILER_TARGET}/include")
    list(APPEND _cands "/usr/${CMAKE_C_COMPILER_TARGET}/include")
  endif()

  set(_bpf_inc "")
  foreach(_cand IN LISTS _cands)
    execute_process(COMMAND "${IWAN_CLANG}" -target bpf -O2 -Wall
                            -isystem "${_cand}" -c
                            "${CMAKE_CURRENT_SOURCE_DIR}/src/common/steer_bpf.c"
                            -o /dev/null
                    RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_QUIET)
    if(_rc EQUAL 0)
      set(_bpf_inc "${_cand}")
      break()
    endif()
  endforeach()
  if(NOT _bpf_inc)
    message(WARNING "clang cannot compile the bpf target with the available "
                    "linux headers — building without tun steering eBPF "
                    "(IWAN_NO_STEER_BPF, kernel automq steering)")
    set(IWAN_BPF OFF PARENT_SCOPE)
    return()
  endif()

  add_custom_command(
    OUTPUT "${IWAN_STEER_DIR}/steer_bpf.o"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${IWAN_STEER_DIR}"
    COMMAND "${IWAN_CLANG}" -O2 -target bpf -Wall
            -isystem "${_bpf_inc}" -c
            "${CMAKE_CURRENT_SOURCE_DIR}/src/common/steer_bpf.c"
            -o "${IWAN_STEER_DIR}/steer_bpf.o"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/common/steer_bpf.c"
    COMMENT "Compiling tun steering eBPF program (clang -target bpf)")
  add_custom_command(
    OUTPUT "${IWAN_STEER_DIR}/steer_bpf_data.c"
    COMMAND "${CMAKE_COMMAND}" -DIN="${IWAN_STEER_DIR}/steer_bpf.o"
            -DOUT="${IWAN_STEER_DIR}/steer_bpf_data.c"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.cmake"
    DEPENDS "${IWAN_STEER_DIR}/steer_bpf.o"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.cmake"
    COMMENT "Embedding BPF payload (steer_bpf_data.c)")
  target_sources(iwan_core PRIVATE "${IWAN_STEER_DIR}/steer_bpf_data.c")
endfunction()

if(UNIX AND NOT APPLE AND IWAN_BPF)
  iwan_enable_bpf()
endif()
if(UNIX AND NOT IWAN_BPF)
  target_compile_definitions(iwan_core PRIVATE IWAN_NO_STEER_BPF)
  message(STATUS "tun steering eBPF disabled (IWAN_NO_STEER_BPF)")
endif()

# ---------------------------------------------------------------------------
# OIDC login flow (src/oidc, one-way dependency on iwan_core).
# ---------------------------------------------------------------------------
add_library(iwan_oidc STATIC
  src/oidc/oidc_cli.c
  src/oidc/oidc_config.c
  src/oidc/oidc_connect.c
  src/oidc/oidc_flow.c
  src/oidc/oidc_jwt.c
  src/oidc/oidc_select.c
  src/oidc/oidc_util.c)
target_include_directories(iwan_oidc PUBLIC src/oidc)
target_link_libraries(iwan_oidc PUBLIC iwan_core)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
add_executable(iwan-client src/iwan_client.c)
target_include_directories(iwan-client PRIVATE src/common)
target_link_libraries(iwan-client PRIVATE iwan_core)

add_executable(iwan-client-oidc src/iwan_client_oidc.c)
target_link_libraries(iwan-client-oidc PRIVATE iwan_oidc)

# SOCKS5 handshake test harness (root-free: drives the real accept/handshake/
# netstack code with a loopback listener; see tests/socks_handshake.py).
# Built only when testing is enabled so release binaries don't ship it.
# Plain option() — NOT include(CTest), whose enable_testing() defines a
# `test` target that collides with the integration-suite target below.
option(BUILD_TESTING "Build the SOCKS5 handshake test harness" ON)
if(BUILD_TESTING)
  add_executable(socks_handshake_harness tests/socks_handshake_harness.c)
  target_link_libraries(socks_handshake_harness PRIVATE iwan_core)
  # Root-free data-plane test: the lwIP bridge uploads a pattern through the
  # readv/commit path against an in-process fake TCP peer and verifies the
  # echo (exercises tcp_write / tcp_recv / netif output / rx). Only meaningful
  # for the lwip stack.
  add_executable(lwip_data_harness tests/lwip_data_harness.c)
  target_link_libraries(lwip_data_harness PRIVATE iwan_core)
  # Multi-conn fairness test: N simultaneous uploads must all complete (the
  # per-conn tx-queue fair-share gate, NS_TX_CONN_CAP).
  add_executable(lwip_fairness_harness tests/lwip_fairness_harness.c)
  target_link_libraries(lwip_fairness_harness PRIVATE iwan_core)
endif()

if(UNIX AND NOT APPLE)
  add_executable(iwan-server src/iwan_server.c)
  target_include_directories(iwan-server PRIVATE src/common)
  target_link_libraries(iwan-server PRIVATE iwan_core)
endif()

# ---------------------------------------------------------------------------
# Integration suite: tests/integration.sh needs root (TUN devices) and is
# Linux-only, so it is not wired into CI — run it via sudo locally.
# ---------------------------------------------------------------------------
if(WIN32 OR APPLE)
  add_custom_target(test
    COMMAND "${CMAKE_COMMAND}" -E echo
            "integration tests are Linux-only (TUN devices, root); skipped")
else()
  add_custom_target(test
    COMMAND tests/integration.sh
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endif()
