# embed_bpf.cmake — turn a BPF ELF object into a C array for embedding.
#
# STANDALONE / MANUAL USE ONLY. The build no longer runs this file:
# CMakeLists.txt bakes the two paths into <build>/embed_bpf_gen.cmake at
# configure time (from cmake/embed_bpf_gen.cmake.in) and runs THAT script with
# no arguments, which is the only shape that survives a path containing a space
# on every generator.
#
# Do NOT call this file from add_custom_command with path arguments — both
# spellings are traps there:
#   * `-DIN="<path>"` puts the quotes inside the value, so file(READ) is handed
#     `"…/steer_bpf.o"` (quotes included);
#   * VERBATIM escapes those quotes a second time, and a positional path is
#     rendered by Unix Makefiles with "\ " escapes that a further quoted recipe
#     passes to the shell verbatim, so file(READ) receives a literal backslash
#     (this worked under Ninja, which is how the gap stayed hidden until the
#     R38 generator matrix ran).
#
# Manual usage (an interactive shell quotes these correctly):
#   cmake -P embed_bpf.cmake -- <obj> <cfile>
#   cmake -DIN=<obj> -DOUT=<cfile> -P embed_bpf.cmake
#
# Emits the same file shape the Makefile produced with od|awk:
#   const unsigned char steer_bpf_o[] = { 0x..,0x.., ... };
#   const unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);
# tun.c (bpf_prog_load_steer) parses the embedded ELF section table at
# runtime, so the object bytes must be preserved verbatim.

if(DEFINED IN AND DEFINED OUT)
  set(_in "${IN}")
  set(_out "${OUT}")
elseif(CMAKE_ARGV5)
  # cmake -P script.cmake -- <obj> <cfile>:
  # ARGV0=cmake ARGV1=-P ARGV2=<script> ARGV3=-- ARGV4=<obj> ARGV5=<cfile>
  set(_in "${CMAKE_ARGV4}")
  set(_out "${CMAKE_ARGV5}")
else()
  message(FATAL_ERROR "usage: cmake -P embed_bpf.cmake -- <obj> <cfile> "
                      "| cmake -DIN=<obj> -DOUT=<cfile> -P embed_bpf.cmake")
endif()

file(READ "${_in}" _hex HEX)                # continuous lowercase hex
string(REGEX REPLACE "(..)" "0x\\1," _bytes "${_hex}")
string(REGEX REPLACE "((0x[0-9a-f]{2},){16})" "\\1\n" _lines "${_bytes}")

file(WRITE "${_out}"
"/* generated from steer_bpf.o; do not edit */\n"
"const unsigned char steer_bpf_o[] = {\n${_lines}};\n"
"const unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);\n")
