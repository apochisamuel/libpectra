CC ?= gcc
CXX ?= g++
CFLAGS ?= -Wall -Wextra -O2
CXXFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?= -lm

SRC_DIR = src
FUZZ_DIR = fuzz
TOOLS_DIR = tools
TESTS_DIR = tests

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:.c=.o)
HDRS = $(SRC_DIR)/pectra.h $(SRC_DIR)/internal.h

.PHONY: all clean test fuzz tools

all: libpectra.a tools test

# Static library
libpectra.a: $(OBJS)
	ar rcs $@ $^

# Object files
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(HDRS)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

# Tools
tools: $(TOOLS_DIR)/pectra_dump

$(TOOLS_DIR)/pectra_dump: $(TOOLS_DIR)/pectra_dump.c libpectra.a
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -L. -lpectra $(LDFLAGS) -o $@

# Tests
test: $(TESTS_DIR)/test_basic
	./$(TESTS_DIR)/test_basic

$(TESTS_DIR)/test_basic: $(TESTS_DIR)/test_basic.c libpectra.a
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -L. -lpectra $(LDFLAGS) -o $@

# ASAN build
asan: CFLAGS += -fsanitize=address -g -O1
asan: LDFLAGS += -fsanitize=address
asan: clean all test

# Fuzzers (requires libFuzzer)
fuzz: libpectra.a
	@for f in $(FUZZ_DIR)/*_fuzzer.cc; do \
		name=$$(basename $$f .cc); \
		echo "Building $$name..."; \
		$(CXX) $(CXXFLAGS) -fsanitize=fuzzer,address -I$(SRC_DIR) \
			$$f $(SRCS) $(LDFLAGS) -o $(FUZZ_DIR)/$$name; \
	done

clean:
	rm -f $(SRC_DIR)/*.o libpectra.a
	rm -f $(TOOLS_DIR)/pectra_dump
	rm -f $(TESTS_DIR)/test_basic
	rm -f $(FUZZ_DIR)/parse_fuzzer $(FUZZ_DIR)/import_fuzzer $(FUZZ_DIR)/resource_fuzzer

# Line count
loc:
	@echo "Source LOC:"
	@find src fuzz tools tests -name '*.c' -o -name '*.h' -o -name '*.cc' | xargs wc -l | tail -1
