#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_ASM="$ROOT_DIR/BASIC-M6502/m6502.asm"
OUT_DIR="$ROOT_DIR/examples/converted"

TRANSLATED_ASM="$OUT_DIR/m6502_xa65.asm"
OUTPUT_BIN="$OUT_DIR/m6502_xa65.bin"
LISTING_FILE="$OUT_DIR/m6502_xa65.lst"
SYMBOL_FILE="$OUT_DIR/m6502_xa65.sym"
WARNINGS_FILE="$OUT_DIR/m6502_xa65.warnings.txt"
ERROR_LOG="$OUT_DIR/m6502_xa65.errors.txt"

ORIG_BIN="$OUT_DIR/m6502_original_m6502asm.bin"
ORIG_LISTING="$OUT_DIR/m6502_original_m6502asm.lst"
ORIG_VERBOSE="$OUT_DIR/m6502_original_m6502asm.verbose.txt"

mkdir -p "$OUT_DIR"

python3 "$ROOT_DIR/m6502_to_xa65.py" \
  --in "$INPUT_ASM" \
  --out "$TRANSLATED_ASM" \
  2>"$WARNINGS_FILE"

set +e
/usr/bin/xa \
  -o "$OUTPUT_BIN" \
  -P "$LISTING_FILE" \
  -l "$SYMBOL_FILE" \
  -e "$ERROR_LOG" \
  "$TRANSLATED_ASM" \
  >/dev/null 2>&1
XA_STATUS=$?

python3 "$ROOT_DIR/m6502asm.py" \
  -o "$ORIG_BIN" \
  -l "$ORIG_LISTING" \
  -v \
  "$INPUT_ASM" \
  >"$ORIG_VERBOSE" 2>&1
ORIG_STATUS=$?
set -e

if [[ $XA_STATUS -eq 0 ]]; then
  echo "Translation and assembly complete."
else
  echo "Translation complete, assembler reported errors (exit $XA_STATUS)."
fi

if [[ $ORIG_STATUS -eq 0 ]]; then
  echo "Original assembly with m6502asm.py complete."
else
  echo "Original assembly with m6502asm.py reported errors (exit $ORIG_STATUS)."
fi

echo "Translated source : $TRANSLATED_ASM"
echo "Binary output     : $OUTPUT_BIN"
echo "Listing           : $LISTING_FILE"
echo "Symbol table      : $SYMBOL_FILE"
echo "Warnings log      : $WARNINGS_FILE"
echo "Assembler errors  : $ERROR_LOG"
echo "Original binary   : $ORIG_BIN"
echo "Original listing  : $ORIG_LISTING"
echo "Original verbose  : $ORIG_VERBOSE"

if [[ $XA_STATUS -ne 0 || $ORIG_STATUS -ne 0 ]]; then
  exit 1
fi

exit 0
