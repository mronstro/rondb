# Phase 0 fiber microbenchmarks.
#
# Usage:
#   make            # build all benches
#   make run        # build then run all
#   make clean

CXX      ?= clang++
CXXSTD   ?= -std=c++17
OPT      ?= -O3
WARN     ?= -Wall -Wextra -Wno-unused-parameter -Wno-unused-function
INC      ?= -I../../../include/util
CXXFLAGS ?= $(CXXSTD) $(OPT) $(WARN) $(INC) -fno-omit-frame-pointer

BENCHES  := bench_switch bench_stack bench_mlp

all: $(BENCHES)

bench_switch: bench_switch.cpp ../../../include/util/tiny_fiber.h
	$(CXX) $(CXXFLAGS) -o $@ $<

bench_stack: bench_stack.cpp ../../../include/util/tiny_fiber.h
	$(CXX) $(CXXFLAGS) -o $@ $<

bench_mlp: bench_mlp.cpp ../../../include/util/tiny_fiber.h
	$(CXX) $(CXXFLAGS) -o $@ $<

run: $(BENCHES)
	@echo "=== bench_switch ==="
	@./bench_switch
	@echo
	@echo "=== bench_stack ==="
	@./bench_stack
	@echo
	@echo "=== bench_mlp ==="
	@./bench_mlp

clean:
	rm -f $(BENCHES)

.PHONY: all run clean
