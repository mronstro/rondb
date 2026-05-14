/*
 * Phase 0 / Benchmark 2 — stack working-set cost.
 *
 * For each (N fibers, stack size) combination, run a round-robin loop where
 * each fiber touches the top K bytes of its stack before yielding. Compares
 * throughput vs the N=1 / no-fiber case.
 *
 * This stresses two things at once:
 *   1. Switch overhead (stays roughly the same with stack size).
 *   2. dTLB working set: 2 MB stack = 512 4K pages; with 8 fibers and an
 *      M2 Pro dTLB of ~256 entries you start to thrash.
 *
 * Build: see Makefile.
 * Run  : ./bench_stack [iters_per_fiber] [touch_bytes]
 *
 * iters_per_fiber defaults to 5M, touch_bytes defaults to 4096 (one page).
 */
#include "tiny_fiber.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>

namespace {

using clk = std::chrono::steady_clock;

uint64_t g_iters_per_fiber = 5ULL * 1000 * 1000;
uint64_t g_touch_bytes = 4096;
uint32_t g_num_fibers = 0;            // 0 = "no fiber" baseline
uint32_t g_next_fiber = 0;            // round-robin index

tiny_fiber::FiberHandle g_thread_fiber;
std::vector<tiny_fiber::FiberHandle> g_fibers;
std::vector<uint64_t>                g_remaining;

volatile uint64_t g_sink = 0;

inline void touch_stack(uint64_t bytes) {
  // Touch one byte per cacheline (64 B) up to `bytes`, on the stack.
  // alloca-style VLA to land on the local frame.
  // We can't safely make `bytes` huge (caller bounds it). Use 64 KB max here
  // — the harness picks `bytes` <= 64 KB.
  alignas(64) volatile uint8_t buf[65536];
  uint64_t step = 64;
  for (uint64_t off = 0; off < bytes; off += step) {
    buf[off] = static_cast<uint8_t>(off);
  }
  // Sink the result so the compiler keeps the writes.
  g_sink += buf[0];
}

void fiber_main(void* arg) {
  uint32_t my_id = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg) - 1);
  for (;;) {
    if (g_remaining[my_id] == 0) {
      // Done — yield to thread fiber forever.
      tiny_fiber::SwitchFiber(g_fibers[my_id], g_thread_fiber);
      continue;
    }
    g_remaining[my_id]--;
    touch_stack(g_touch_bytes);
    tiny_fiber::SwitchFiber(g_fibers[my_id], g_thread_fiber);
  }
}

double run_baseline_no_fiber(uint64_t total_iters) {
  auto t0 = clk::now();
  for (uint64_t i = 0; i < total_iters; i++) {
    touch_stack(g_touch_bytes);
  }
  auto t1 = clk::now();
  using ns = std::chrono::nanoseconds;
  uint64_t n = std::chrono::duration_cast<ns>(t1 - t0).count();
  return n / static_cast<double>(total_iters);
}

double run_with_fibers(uint32_t n_fibers, uint32_t stack_kb) {
  g_num_fibers = n_fibers;
  g_thread_fiber = tiny_fiber::CreateFiberFromThread();
  g_fibers.assign(n_fibers, nullptr);
  g_remaining.assign(n_fibers, g_iters_per_fiber);
  uint32_t stack_size = stack_kb * 1024u;
  for (uint32_t i = 0; i < n_fibers; i++) {
    g_fibers[i] = tiny_fiber::CreateFiber(
        stack_size, fiber_main,
        reinterpret_cast<void*>(static_cast<uintptr_t>(i + 1)));
    if (!g_fibers[i]) {
      printf("  CreateFiber(%u KB) failed\n", stack_kb);
      return -1.0;
    }
  }

  auto t0 = clk::now();
  // Round-robin: switch into each fiber once per round. Stop when all done.
  uint64_t total_switches = 0;
  bool done = false;
  while (!done) {
    done = true;
    for (uint32_t i = 0; i < n_fibers; i++) {
      if (g_remaining[i] > 0) {
        done = false;
        tiny_fiber::SwitchFiber(g_thread_fiber, g_fibers[i]);
        total_switches += 2; // round-trip
      }
    }
  }
  auto t1 = clk::now();

  for (uint32_t i = 0; i < n_fibers; i++) {
    tiny_fiber::DeleteFiber(g_fibers[i]);
  }
  // Note: tiny_fiber doesn't really support DeleteFiber for the thread-fiber
  // on POSIX; on macOS it's a no-op malloc'd struct.
  tiny_fiber::DeleteFiber(g_thread_fiber);

  using ns = std::chrono::nanoseconds;
  uint64_t n = std::chrono::duration_cast<ns>(t1 - t0).count();
  uint64_t total_ops = static_cast<uint64_t>(n_fibers) * g_iters_per_fiber;
  double ns_per_op_value = n / static_cast<double>(total_ops);
  double ns_per_switch = n / static_cast<double>(total_switches);
  printf("    n=%u  stack=%4u KB   %7.2f ns/touch   %7.2f ns/switch\n",
         n_fibers, stack_kb, ns_per_op_value, ns_per_switch);
  return ns_per_op_value;
}

} // namespace

int main(int argc, char** argv) {
  if (argc > 1) g_iters_per_fiber = strtoull(argv[1], nullptr, 10);
  if (argc > 2) g_touch_bytes     = strtoull(argv[2], nullptr, 10);
  if (g_touch_bytes > 65536) g_touch_bytes = 65536;

  printf("Phase 0 / Benchmark 2: stack working-set cost\n");
  printf("  iters_per_fiber: %llu\n",
         static_cast<unsigned long long>(g_iters_per_fiber));
  printf("  touch_bytes    : %llu (one byte per 64 B cacheline)\n",
         static_cast<unsigned long long>(g_touch_bytes));
  printf("\n");

  double base = run_baseline_no_fiber(g_iters_per_fiber);
  printf("  baseline (no fiber):    %7.2f ns/touch\n\n", base);

  uint32_t stack_kbs[] = {64, 1024, 1536, 2048};
  uint32_t fibers[]    = {1, 2, 4, 8};

  for (uint32_t sk : stack_kbs) {
    printf("  stack = %u KB\n", sk);
    for (uint32_t nf : fibers) {
      run_with_fibers(nf, sk);
    }
    printf("\n");
  }

  printf("sink: %llu\n", static_cast<unsigned long long>(g_sink));
  return 0;
}
