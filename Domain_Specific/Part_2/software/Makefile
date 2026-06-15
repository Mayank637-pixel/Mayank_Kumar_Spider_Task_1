# Compiler for normal builds (clang with ASan)
CC      = clang
CFLAGS  = -g -O1 -fsanitize=address -fno-omit-frame-pointer

# Compiler for the AFL++ fuzz target
CC_FUZZ      = afl-clang-lto
FUZZ_CFLAGS  = -g -O0 -fsanitize=address -fno-omit-frame-pointer

all: fuzzer test_bin

# Regular object (used by test_bin)
license.o: license.c license.h
	$(CC) $(CFLAGS) -c license.c -o license.o

# AFL++-instrumented object (used by fuzzer)
license_afl.o: license.c license.h
	$(CC_FUZZ) $(FUZZ_CFLAGS) -c license.c -o license_afl.o

# Fuzz target
fuzzer: afl_harness.c license_afl.o
	$(CC_FUZZ) $(FUZZ_CFLAGS) afl_harness.c license_afl.o -o fuzzer

# Unit test binary
test_bin: test_license.c license.o
	$(CC) $(CFLAGS) test_license.c license.o -o test_bin

test: test_bin
	./test_bin

clean:
	rm -f *.o fuzzer test_bin
