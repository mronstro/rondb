/*
 * Phase 0 / Benchmark 1 — fiber switch latency.
 *
 * Measures the cost of tiny_fiber::SwitchFiber() versus three baselines:
 *   - empty direct function call
 *   - empty indirect (function-pointer) call
 *   - register-only context save/restore (via setjmp + manual jump-back is
 *     not easy; we use ucontext for a portable comparison)
 *
 * Build:  see Makefile.
 * Run  :  ./bench_switch [iters]
 *
 * Output: ns per operation. iters defaults to 100M.
 */
#include "tiny_fiber.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <chrono>

namespace {

using clk = std::chrono::steady_clock;

inline double ns_per_op(clk::duration d, uint64_t ops) {
  using ns = std::chrono::nanoseconds;
  return std::chrono::duration_cast<ns>(d).count() / static_cast<double>(ops);
}

// --- Baseline 1: empty direct call -----------------------------------------
volatile uint64_t g_sink = 0;
__attribute__((noinline)) void noop_direct() { g_sink++; }

double bench_direct_call(uint64_t iters) {
  auto t0 = clk::now();
  for (uint64_t i = 0; i < iters; i++) {
    noop_direct();
  }
  auto t1 = clk::now();
  return ns_per_op(t1 - t0, iters);
}

// --- Baseline 2: empty indirect call ---------------------------------------
using FnPtr = void (*)();
volatile FnPtr g_fn = noop_direct;

double bench_indirect_call(uint64_t iters) {
  auto t0 = clk::now();
  for (uint64_t i = 0; i < iters; i++) {
    g_fn();
  }
  auto t1 = clk::now();
  return ns_per_op(t1 - t0, iters);
}

// --- Fiber switch ----------------------------------------------------------
tiny_fiber::FiberHandle thread_fiber;
tiny_fiber::FiberHandle worker_fiber;
uint64_t g_remaining = 0;

void worker_main(void* /*arg*/) {
  while (true) {
    g_sink++;
    tiny_fiber::SwitchFiber(worker_fiber, thread_fiber);
  }
}

double bench_fiber_switch(uint64_t iters) {
  thread_fiber = tiny_fiber::CreateFiberFromThread();
  // Pass a non-null arg because CreateFiber rejects null
  worker_fiber = tiny_fiber::CreateFiber(64 * 1024, worker_main,
                                         reinterpret_cast<void*>(1));
  // Warmup: enter worker once
  tiny_fiber::SwitchFiber(thread_fiber, worker_fiber);

  auto t0 = clk::now();
  for (uint64_t i = 0; i < iters; i++) {
    // One iteration = main -> worker -> main = 2 switches
    tiny_fiber::SwitchFiber(thread_fiber, worker_fiber);
  }
  auto t1 = clk::now();
  return ns_per_op(t1 - t0, 2 * iters);
}

} // namespace

int main(int argc, char** argv) {
  uint64_t iters = (argc > 1) ? strtoull(argv[1], nullptr, 10)
                              : 100ULL * 1000 * 1000;

  printf("Phase 0 / Benchmark 1: switch latency\n");
  printf("  iterations: %llu\n", static_cast<unsigned long long>(iters));
  printf("\n");

  double d1 = bench_direct_call(iters);
  printf("  direct call    : %7.2f ns/op\n", d1);

  double d2 = bench_indirect_call(iters);
  printf("  indirect call  : %7.2f ns/op\n", d2);

  // Divide fiber iters down — each "iter" inside is 2 switches, and switches
  // are slower, so scale to keep runtime sane.
  uint64_t fiber_iters = iters / 4;
  if (fiber_iters < 1000) fiber_iters = 1000;
  double d3 = bench_fiber_switch(fiber_iters);
  printf("  fiber switch   : %7.2f ns/op (counted per single SwitchFiber call)\n", d3);

  printf("\nsink: %llu\n", static_cast<unsigned long long>(g_sink));
  return 0;
}
