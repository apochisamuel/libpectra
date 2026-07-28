#!/bin/bash -eu

cd $SRC

# Compile all C source files into objects
for f in src/*.c; do
    $CC $CFLAGS -Isrc -c "$f" -o "${f%.c}.o"
done

# Link each fuzzer harness
for fuzzer in fuzz/*_fuzzer.cc; do
    name=$(basename "$fuzzer" .cc)
    $CXX $CXXFLAGS -Isrc -c "$fuzzer" -o "fuzz/${name}.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        "fuzz/${name}.o" src/*.o \
        -lm -o "$OUT/${name}"

    # Copy seed corpus if it exists
    if [ -d "fuzz/corpus/${name}" ]; then
        zip -j "$OUT/${name}_seed_corpus.zip" fuzz/corpus/${name}/* 2>/dev/null || true
    fi
done
