CC ?= cc
CFLAGS ?= -O2
WARNINGS = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CPPFLAGS = -D_POSIX_C_SOURCE=200809L
SRC = main.c parser.c utils.c
OBJ = $(SRC:.c=.o)
TARGET = xarinfo
SANFLAGS =
TEST_GEN = tests/gen_xar

.PHONY: all clean asan test asan-test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) $(SANFLAGS) -o $@ $(OBJ)

%.o: %.c parser.h utils.h
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) $(SANFLAGS) -c $< -o $@

$(TEST_GEN): tests/generate_corpus.c
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) -o $@ $<

asan: CFLAGS = -O1 -g
asan: SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean $(TARGET)

test: $(TARGET) $(TEST_GEN)
	./tests/run-tests.sh ./$(TARGET) ./$(TEST_GEN)

asan-test: asan $(TEST_GEN)
	ASAN_OPTIONS=detect_leaks=0 ./tests/run-tests.sh ./$(TARGET) ./$(TEST_GEN)

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_GEN)
