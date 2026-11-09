#!/bin/bash
# Test-only EFI identity: never use production signing material for this fixture.
set -euo pipefail
[[ $# == 4 && ($1 == error || $1 == hang) ]] || {
    printf 'Usage: %s error|hang TEST_KEY TEST_CERT OUTPUT_EFI\n' "$0" >&2
    exit 1
}
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
source_file=broken-loader.c
[[ $1 != hang ]] || source_file=hanging-loader.c
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
gcc -DGNU_EFI_USE_MS_ABI -Wall -Wextra -Werror -fpie -fshort-wchar -mno-red-zone \
    -fno-stack-protector -fno-asynchronous-unwind-tables \
    -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -c "$source_dir/$source_file" -o "$work/loader.o"
# The C entry uses RIP-relative code and needs no ELF runtime. Keep a valid
# PE relocation directory with ABSOLUTE (no-op) entries for firmware placement.
gcc -c -x assembler -o "$work/reloc.o" - <<'ASM'
.section .reloc, "a"
.balign 4
.long 0
.long 12
.word 0
.word 0
ASM
ld --fatal-warnings -shared -Bsymbolic -z noexecstack -z separate-code \
    -T /usr/lib/elf_x86_64_efi.lds --entry efi_main \
    "$work/loader.o" "$work/reloc.o" -o "$work/loader.so"
objcopy --strip-all -j .text -j .data -j .dynamic -j .dynsym -j .reloc \
    --file-alignment=512 --section-alignment=4096 \
    --output-target=efi-app-x86_64 "$work/loader.so" "$work/loader.efi"
sbsign --key "$2" --cert "$3" --output "$4" "$work/loader.efi"
sbverify --cert "$3" "$4"
