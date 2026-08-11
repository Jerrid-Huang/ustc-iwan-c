# embed_bpf.cmake — turn a BPF ELF object into a C array for embedding.
#
# Usage: cmake -DIN=<steer_bpf.o> -DOUT=<steer_bpf_data.c> -P embed_bpf.cmake
#
# Emits the same file shape the Makefile produced with od|awk:
#   const unsigned char steer_bpf_o[] = { 0x..,0x.., ... };
#   const unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);
# tun.c (bpf_prog_load_steer) parses the embedded ELF section table at
# runtime, so the object bytes must be preserved verbatim.

if(NOT DEFINED IN OR NOT DEFINED OUT)
  message(FATAL_ERROR "usage: cmake -DIN=<obj> -DOUT=<cfile> -P embed_bpf.cmake")
endif()

file(READ "${IN}" HEX _hex)                 # continuous lowercase hex
string(REGEX REPLACE "(..)" "0x\\1," _bytes "${_hex}")
string(REGEX REPLACE "((0x[0-9a-f]{2},){16})" "\\1\n" _lines "${_bytes}")

file(WRITE "${OUT}"
"/* generated from steer_bpf.o; do not edit */\n"
"const unsigned char steer_bpf_o[] = {\n${_lines}};\n"
"const unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);\n")
