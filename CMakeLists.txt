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

project(iwan VERSION 0.7.3 LANGUAGES C)

# F: interprocedural optimization (LTO). OFF by default: the mingw/musl
# cross toolchains have uneven LTO support, so opt in after an A/B on
# the Linux-native echo benchmark (IWAN_LTO=ON vs OFF).
option(IWAN_LTO "Enable interprocedural optimization (LTO)" OFF)
if(IWAN_LTO)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Release-by-default (CMAKE_C_FLAGS_RELEASE = -O3 -DNDEBUG, CMake's
# built-in default; this project never removes -DNDEBUG). The code has
# no runtime assert()s — only _Static_assert, which is NDEBUG-independent
# — so that -DNDEBUG is inert.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
# Non-Debug builds compile out the whole debug tier: log_debug calls and
# their format strings never reach the binary, and IWAN_DEBUG /
# IWAN_PUMP_PROF / IWAN_PROFILE are not parsed at all. A Debug build
# keeps everything for field diagnosis.
if(CMAKE_BUILD_TYPE MATCHES "Debug")
  set(_IWAN_STRIP_DEFAULT OFF)
else()
  set(_IWAN_STRIP_DEFAULT ON)
endif()
option(IWAN_DEBUG_STRIP "Compile out debug logging and diagnostic env vars" ${_IWAN_STRIP_DEFAULT})
if(IWAN_DEBUG_STRIP)
  add_compile_definitions(IWAN_DEBUG_STRIP=1)
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)          # -std=c11 (strict, as before)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(IWAN_LINUX_STATIC "Linux: link fully static binaries" OFF)
option(IWAN_STATIC       "Windows: statically link OpenSSL + runtime libs" OFF)
option(IWAN_BPF          "Linux: compile and embed the tun steering eBPF program" ON)
option(IWAN_WERROR       "Treat compiler warnings as errors" OFF)
# Strict warning gate for the project's OWN sources (src/, tests/). It is
# applied per target with target_compile_options — never through
# CMAKE_C_FLAGS/add_compile_options, which reach every target: the vendored
# lwIP does not build clean under -Wconversion/-Wshadow, so a global flag
# set killed the gate inside third_party/ before iwan_core was ever
# compiled, and "src/ is warning-free" could not be verified (R37 R1-C-7 /
# R1-B-7). third_party/lwip keeps the global -Wall -Wextra and stays
# pristine.
option(IWAN_STRICT       "Strict warning gate for project sources (src/, tests/)" OFF)
# The documented CI invariant: -Wall -Wextra -Wpedantic -Wshadow
# -Wconversion -Wsign-conversion -Werror. Unchanged, and it is what every
# non-Windows build gets (Linux gcc/clang strict legs: rc=0, 0 diagnostics).
set(IWAN_STRICT_FLAGS
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror)
# ---------------------------------------------------------------------------
# Windows/LLP64 history (opened by R37 R6-WG5, closed at the source by R37 R7,
# scaffolding deleted in R38).
#
# HISTORY: the seven strict flags used to produce 25 diagnostics in 7 files on
# Windows, all of them LLP64-only (mingw `long` is 32-bit; winsock `SOCKET` is
# uint64): 20x -Wsign-conversion + 5x -Wconversion, 0x -Wpedantic. R6-WG5
# therefore introduced a reduced Windows "platform tier" (no
# -Wconversion/-Wsign-conversion) so the win-cross gate was green. R37 R7
# fixed all 25 at the source:
#   * `int fd` -> `struct pollfd.fd` / winsock SOCKET arguments: routed through
#     PORT_FD_ARG() in port.h (the one place that knows the platform spelling);
#   * `ai_addrlen` -> `socklen_t` and `size_t` -> `nfds_t`: explicit casts at
#     the call sites;
#   * `(time_t)` -> `struct timeval.tv_sec`: explicit (long) cast (value is
#     bounded by HTTPS_POLL_MS);
#   * port.c's `long unsigned -> long int` value changes: (long)FIONBIO at the
#     two ioctlsocket sites (the wrapped bit pattern is what winsock
#     documents), and _snwprintf's count is passed as the size_t it already is.
# R38 deleted the leftover tier scaffolding: IWAN_STRICT_FLAGS_WIN and the
# IWAN_STRICT_WIN_LLP64 option (ON by default since R37 R7, i.e. a no-op in
# every tree and CI leg). Windows now selects IWAN_STRICT_FLAGS exactly like
# every other platform, so there is one list, not two. A downstream still
# passing -DIWAN_STRICT_WIN_LLP64=... gets CMake's harmless
# "Manually-specified variables were not used by the project" warning; the
# effective flags are the full set (the old default). Downstreams that relied
# on =OFF for the reduced tier must fix the diagnostic at the source instead —
# the tier no longer exists to hide it.
#
# Coverage of the strict gate, stated exactly (R38 P0-5; the old comment here
# claimed "the whole tree" on the strength of a production-only run, and told
# readers to just add -DIWAN_STRICT=ON to the win-cross leg, which would have
# failed on i686 and on any leg with -DBUILD_TESTING=ON):
#   * production tree = iwan_core, iwan_oidc, iwan-client, iwan-client-oidc,
#     iwan-server. rc=0 / 0 diagnostics on Linux gcc and clang (Release) and
#     on mingw-w64 x86_64. Verified in R38 with
#     `-DIWAN_STRICT=ON -DIWAN_WERROR=ON` (see .cc_tmp/r38/fixes/).
#   * `-DBUILD_TESTING=ON` adds tests/socks_handshake_harness.c,
#     tests/lwip_data_harness.c and tests/lwip_fairness_harness.c to the SAME
#     per-target gate (the target list at the end of this file). "Whole tree"
#     therefore means "production tree + those harnesses", and it needed the
#     R38 P0-4 fix (SOCKET conversion in socks_handshake_harness.c) before it
#     held on mingw x86_64.
#   * mingw-w64 i686 (ILP32) additionally needed the R38 P0-3 explicit
#     narrowings: ssize_t is `int` there, so `unsigned msg_len` assignments are
#     sign changes that LLP64 x86_64 never sees. R37 verified x86_64 only.
#   * CI does NOT enable IWAN_STRICT on the win-cross / win-arm64 legs today
#     (they pass -DIWAN_WERROR=ON only), so "add -DIWAN_STRICT=ON to CI" is a
#     coverage change, not a no-op: it must land together with the P0-3/P0-4
#     source fixes, on every matrix entry it touches.
# Scope is unchanged: the gate is applied per target, so third_party/lwip
# still gets only the global -Wall -Wextra.
#
# Opt-in extras (IWAN_STRICT=ON + IWAN_STRICT_EXTRA=ON). These are ADVISORY:
# const-correctness / float-equality style diagnostics the code deliberately
# does not follow (`char *argv[] = {"literal", ...}` throughout; the 4
# -Wfloat-equal sites are exact-value comparisons with written justifications)
# stay out of the default gate rather than being silently suppressed. With
# IWAN_WERROR=ON an un-demoted extras diagnostic is fatal, and the documented
# "opt-in" switch became "turn this on and the build dies" (R38 P0-2, gcc
# Release: 144 diagnostics — 140 discarded-qualifiers from -Wwrite-strings,
# 4 -Wfloat-equal; clang 155, adding 12 -Wcast-align). Each extras flag is
# therefore demoted by name, AFTER the -Werror in IWAN_STRICT_FLAGS; a bare
# -Wno-error would also demote the base gate, which is exactly what must not
# happen. The diagnostics are still printed — warnings, not silence.
option(IWAN_STRICT_EXTRA "Add -Wwrite-strings/-Wfloat-equal/... to IWAN_STRICT (advisory, never fatal)" OFF)
set(IWAN_STRICT_EXTRA_FLAGS
  -Wfloat-equal -Wcast-align -Wpointer-arith -Wwrite-strings -fno-common)
set(IWAN_STRICT_EXTRA_NOWERROR_FLAGS
  -Wno-error=float-equal -Wno-error=cast-align -Wno-error=pointer-arith)
# -Wwrite-strings is a spelling both front ends accept, but the diagnostic it
# enables is named differently, and an unknown -Wno-error=<name> target is
# itself an error once -Werror is in effect (clang: -Wunknown-warning-option),
# so the demotion must use the name the compiler prints:
#   gcc   : ... discards 'const' qualifier from pointer target type [-Wdiscarded-qualifiers]
#   clang : ... discards qualifiers [-Wincompatible-pointer-types-discards-qualifiers]
# (Verified in R38 that gcc's -Wno-error=write-strings does NOT demote
# -Wdiscarded-qualifiers — the per-diagnostic spelling above is required.)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  list(APPEND IWAN_STRICT_EXTRA_NOWERROR_FLAGS -Wno-error=discarded-qualifiers)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
  list(APPEND IWAN_STRICT_EXTRA_NOWERROR_FLAGS
       -Wno-error=incompatible-pointer-types-discards-qualifiers)
endif()
set(IWAN_OPENSSL_DIR "" CACHE PATH "OpenSSL sysroot (include/ + lib/ or lib64/)")
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
  # -std=c11 (strict) defines __STRICT_ANSI__, which drops the SDK's
  # __DARWIN_C_LEVEL to ANSI and hides BSD extensions (sysctl,
  # KERN_* constants, ...); _DARWIN_C_SOURCE restores the full level
  # like _GNU_SOURCE does on Linux. (The utun control-socket constants
  # SYSPROTO_CONTROL/AF_SYS_CONTROL are kernel-private in the public
  # SDK and are defined locally in tun_mac.c.)
  add_compile_definitions(_DARWIN_C_SOURCE)
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
# rely on that path); archives stay in the build tree. An explicit
# -DCMAKE_RUNTIME_OUTPUT_DIRECTORY wins (R37 R3-L15): the plain set()
# used to shadow the cache variable, so the documented redirect was
# silently ignored and concurrent out-of-source builds of one tree
# overwrote each other's <tree>/bin binaries.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
endif()
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
  src/common/cli_common.c
  src/common/config.c
  src/common/crypto.c
  src/common/gcm.c
  src/common/https.c
  src/common/ipv4.c
  src/common/json.c
  src/common/lockout.c
  src/common/port.c
  src/common/protocol.c
  src/common/proto_parse.c
  src/common/proxy.c
  src/common/relay_proxy.c
  src/common/route.c
  src/common/socks.c
  src/common/socks_flow.c
  src/common/udp_send.c
  src/common/util.c)
if(WIN32)
  # tun_win.c replaces tun.c (wintun backend; tun.c is Linux TUN ioctls),
  # and server.c is Linux-only (TUN/iptables/BPF, see src/common/server.c).
  # single-thread zero-copy uplink (the SPSC + sender-thread variant
  # was removed; pump_win_single.c is the only Windows pump)
  list(APPEND IWAN_CORE_SRCS src/common/tun_win.c
    src/common/wintun_fetch.c
    src/common/wintun_pin.c
    src/common/pump_win_single.c)
elseif(APPLE)
  # macOS client: tun.c holds the generic code (reader pool, write
  # retry, close; its Linux-only ioctl/BPF parts are #ifdef __linux__),
  # tun_mac.c provides the utun open/attach/detach + name mapping.
  list(APPEND IWAN_CORE_SRCS src/common/tun.c src/common/tun_mac.c)
else()
  list(APPEND IWAN_CORE_SRCS src/common/server.c src/common/tun.c)
endif()

# Userspace TCP stack for the SOCKS mode: the vendored lwIP bridge is
# the only implementation (the native netstack.c rollback was removed).
list(APPEND IWAN_CORE_SRCS src/common/lwip_bridge.c)

# throughput instrumentation (bottleneck profiling; IWAN_PROFILE=1)
list(APPEND IWAN_CORE_SRCS src/common/profile.c)

# ---------------------------------------------------------------------------
# Vendored lwIP 2.2.1 (third_party/lwip): the userspace TCP stack behind the
# SOCKS mode. NO_SYS=1 raw API, IPv4/TCP only, no socket layer — configured by
# third_party/lwip/lwipopts.h and third_party/lwip/port/arch/cc.h. Built as a
# standalone static lib; iwan_core links it.
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
  third_party/lwip/src/core/ipv4/ip4_frag.c
  third_party/lwip/src/core/ipv6/ip6.c
  third_party/lwip/src/core/ipv6/ip6_addr.c
  third_party/lwip/src/core/ipv6/nd6.c
  third_party/lwip/src/core/ipv6/icmp6.c)

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
# vendored ip6_addr.c:284 (ip6addr_ntoa_r) indexes addr[(block+1)>>1]
# which is addr[4] at the last block — a latent upstream OOB read that
# gcc's -Warray-bounds only proves on some targets (s390x). Suppress for
# the third-party library only; the function is used solely for debug
# printing, never in the data path. Known to both gcc and clang.
target_compile_options(lwip PRIVATE -Wno-array-bounds)

add_library(iwan_core STATIC ${IWAN_CORE_SRCS})
target_include_directories(iwan_core PUBLIC src/common)
target_link_libraries(iwan_core PUBLIC lwip)
target_compile_definitions(iwan_core PUBLIC IWAN_TCP_STACK_LWIP=1)
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
  target_link_libraries(iwan_core PUBLIC ws2_32 iphlpapi bcrypt crypt32 shell32 mpr setupapi wintrust)
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
    COMMENT "Compiling tun steering eBPF program (clang -target bpf)" VERBATIM)
  # Bake the two paths into a private script at configure time and invoke that
  # script with NO arguments: a path containing a space cannot be carried as a
  # build-recipe argument portably (-D"..." puts the quotes in the value,
  # VERBATIM escapes them again, and Makefiles turn a positional path's space
  # into a literal backslash). configure_file() substitutes them as string
  # literals instead, so source dir / build dir / both may contain spaces.
  set(IN  "${IWAN_STEER_DIR}/steer_bpf.o")
  set(OUT "${IWAN_STEER_DIR}/steer_bpf_data.c")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf_gen.cmake.in"
                 "${CMAKE_CURRENT_BINARY_DIR}/embed_bpf_gen.cmake" @ONLY)
  add_custom_command(
    OUTPUT "${IWAN_STEER_DIR}/steer_bpf_data.c"
    COMMAND "${CMAKE_COMMAND}" -P
            "${CMAKE_CURRENT_BINARY_DIR}/embed_bpf_gen.cmake"
    DEPENDS "${IWAN_STEER_DIR}/steer_bpf.o"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf_gen.cmake.in"
    COMMENT "Embedding BPF payload (steer_bpf_data.c)" VERBATIM)
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
  src/oidc/oidc_pwsecret.c
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

if(APPLE)
  # Keychain branch: SecItem* from Security, CF* helpers from CoreFoundation.
  # SHELL: keeps each "-framework X" as one argument and stops CMake from
  # translating the framework names into -lSecurity / -lCoreFoundation.
  target_link_options(iwan-client-oidc PRIVATE
    "SHELL:-framework Security"
    "SHELL:-framework CoreFoundation")
endif()

# SOCKS5 handshake test harness (root-free: drives the real accept/handshake/
# netstack code with a loopback listener; see tests/socks_handshake.py).
# Off by default so release binaries don't ship it; CI passes
# -DBUILD_TESTING=ON wherever tests/socks_handshake.py runs.
# Plain option() — NOT include(CTest), whose enable_testing() defines a
# `test` target that collides with the integration-suite target below.
option(BUILD_TESTING "Build the SOCKS5 handshake test harness" OFF)
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

# Strict gate, applied to every target built from our own sources (iwan_core
# pulls in src/common + the generated BPF payload; tests/ harnesses are
# built only with -DBUILD_TESTING=ON). lwip is deliberately absent: it is
# vendored code and keeps the global -Wall -Wextra only.
#
# One flag list for every platform (R38 P2-12/P2-16): non-Windows and Windows
# both use IWAN_STRICT_FLAGS, and the extras (when enabled) are appended after
# the -Werror it ends with, followed by their per-diagnostic -Wno-error=
# demotions. The target SCOPE never changes — lwip never enters this loop.
if(IWAN_STRICT)
  set(_iwan_strict_flags ${IWAN_STRICT_FLAGS})
  if(IWAN_STRICT_EXTRA)
    list(APPEND _iwan_strict_flags ${IWAN_STRICT_EXTRA_FLAGS})
    # Must stay after IWAN_STRICT_FLAGS (which ends in -Werror) and after the
    # extras that produce these diagnostics; see the options block above.
    list(APPEND _iwan_strict_flags ${IWAN_STRICT_EXTRA_NOWERROR_FLAGS})
  endif()
  foreach(_tgt iwan_core iwan_oidc iwan-client iwan-client-oidc iwan-server
               socks_handshake_harness lwip_data_harness lwip_fairness_harness)
    if(TARGET ${_tgt})
      target_compile_options(${_tgt} PRIVATE ${_iwan_strict_flags})
    endif()
  endforeach()
  unset(_iwan_strict_flags)
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

# ---------------------------------------------------------------------------
# Packaging / install: this project deliberately has NO install() rule (R38
# P2-13). The delivery path is the CI release job, which assembles the
# archives itself from the build tree; the binaries land in
# CMAKE_RUNTIME_OUTPUT_DIRECTORY (<repo>/bin by default), which is the path
# tests and CI rely on.
#
# Know what `cmake --install <build-dir> --prefix <dir>` does here: CMake
# accepts it and returns 0 WITHOUT copying a single file, because
# cmake_install.cmake has no file(INSTALL) rules to run. That silent success
# is a fail-open trap — scripts that "install" and then package or ship the
# prefix get an empty directory and no error. (`ninja install` / `make
# install` do fail with "unknown target", but that is not the invocation
# people reach for.) Until a real install() rule exists, copy the binaries
# from bin/ explicitly, and treat a zero-exit `cmake --install` as "nothing
# was installed", not as success.
#
# If a downstream does want `cmake --install` to work, adding install(TARGETS
# ...) alone is not enough: iwan_core links against ${IWAN_OPENSSL_DIR}/lib /
# lib64 as a non-implicit directory, so the build tree binaries carry a build
# RPATH pointing there (CMake adds it automatically). The install rule must
# also set CMAKE_INSTALL_RPATH / INSTALL_RPATH_USE_LINK_PATH so the staged
# binaries do not keep a build-tree path — otherwise they only run on the
# machine that built them.
