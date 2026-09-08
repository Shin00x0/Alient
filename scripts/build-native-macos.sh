#!/bin/sh
# Builds Ghidra's decompiler and GNU demanglers from the matching release sources.
set -eu
if [ "$(uname -s)" != Darwin ]; then
  echo 'Este script requiere macOS.' >&2
  exit 1
fi
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENGINE_ROOT=${GHIDRA_HOME:-"$PROJECT_ROOT/.runtime/ghidra_12.1.3_PUBLIC"}
NATIVE_ARCH=$(uname -m)
case "$NATIVE_ARCH" in
  arm64) PLATFORM=mac_arm_64; MIN_OS=11.0 ;;
  x86_64) PLATFORM=mac_x86_64; MIN_OS=10.13 ;;
  *) echo 'Arquitectura no soportada.' >&2; exit 1 ;;
esac
make -C "$ENGINE_ROOT/Ghidra/Features/Decompiler/src/decompile/cpp" -j4 ghidra_opt "ARCH_TYPE=-arch $NATIVE_ARCH" "ADDITIONAL_FLAGS=-mmacosx-version-min=$MIN_OS" 'CXX=clang++ -std=c++11'
mkdir -p "$ENGINE_ROOT/Ghidra/Features/Decompiler/os/$PLATFORM"
cp "$ENGINE_ROOT/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt" "$ENGINE_ROOT/Ghidra/Features/Decompiler/os/$PLATFORM/decompile"
echo "Decompilador instalado en $ENGINE_ROOT/Ghidra/Features/Decompiler/os/$PLATFORM/decompile"
# Match the compile definitions in Ghidra's GPL/DemanglerGnu/build.gradle.
mkdir -p "$ENGINE_ROOT/GPL/DemanglerGnu/os/$PLATFORM"
for DEMANGLER_VERSION in 2_41 2_24; do
  DEMANGLER_SRC="$ENGINE_ROOT/GPL/DemanglerGnu/src/demangler_gnu_v$DEMANGLER_VERSION"
  if [ "$DEMANGLER_VERSION" = 2_24 ]; then
    clang -arch "$NATIVE_ARCH" -std=gnu17 -O2 -DHAVE_STDLIB_H -DHAVE_STRING_H -DMAIN_CPLUS_DEM -I "$DEMANGLER_SRC/headers" "$DEMANGLER_SRC"/c/*.c -o "$ENGINE_ROOT/GPL/DemanglerGnu/os/$PLATFORM/demangler_gnu_v$DEMANGLER_VERSION"
  else
    clang -arch "$NATIVE_ARCH" -std=gnu17 -O2 -DHAVE_STDLIB_H -DHAVE_STRING_H -I "$DEMANGLER_SRC/headers" "$DEMANGLER_SRC"/c/*.c -o "$ENGINE_ROOT/GPL/DemanglerGnu/os/$PLATFORM/demangler_gnu_v$DEMANGLER_VERSION"
  fi
done
