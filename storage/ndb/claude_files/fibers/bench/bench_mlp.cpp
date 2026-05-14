/*
 * Phase 0 / Benchmark 3 — memory-level parallelism via fiber interleaving.
 *
 * Synthetic pointer-chase: a working set bigger than LLC is laid out as a
 * random permutation, and we follow the chain. Each step is a cold load
 * (~80–150 ns on M2 Pro SLC miss).
 *
 * Variants:
 *   V0: serial pointer chase, no prefetch.
 *   V1: serial pointer chase, with an explicit prefetch of the next-but-one
 *       node (gives the hardware a ~one-miss head start).
 *   V2: N independent chases interleaved via fibers. Each fiber prefetches
 *       its next node, then yields. Round-robin scheduler in the thread
 *       fiber. N = 2, 4, 8.
 *
 * Run: ./bench_mlp [working_set_mb] [steps_per_chain]
 *   working_set_mb defaults to 256 (clearly above the 4 MB per-cluster L2
 *   and any SLC; on Apple Silicon this lands in DRAM).
 *   steps_per_chain defaults to 2,000,000.
 *
 * Output: ns / pointer-chase step, for each variant.
 */
#include "tiny_fiber.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

namespace {

using clk = std::chrono::steady_clock;

uint64_t g_working_set_bytes = 256ULL * 1024 * 1024;
uint64_t g_steps             = 2ULL * 1000 * 1000;

// Each node holds a pointer to the next node and some pad so a node occupies
// a full cacheline. We don't want adjacent nodes to share a line — every
// step should be its own miss.
struct alignas(64) Node {
  Node* next;
  uint64_t payload[7];
};

std::vector<Node> g_nodes;
Node* g_heads[8] = {nullptr};

void build_chain() {
  uint64_t n_nodes = g_working_set_bytes / sizeof(Node);
  g_nodes.assign(n_nodes, Node{});

  std::vector<uint64_t> perm(n_nodes);
  for (uint64_t i = 0; i < n_nodes; i++) perm[i] = i;
  std::mt19937_64 rng(0xC0FFEEULL);
  std::shuffle(perm.begin(), perm.end(), rng);

  for (uint64_t i = 0; i < n_nodes; i++) {
    g_nodes[perm[i]].next = &g_nodes[perm[(i + 1) % n_nodes]];
  }
  // 8 well-separated head pointers, used as independent starting positions
  for (int i = 0; i < 8; i++) {
    g_heads[i] = &g_nodes[perm[(n_nodes / 8) * i]];
  }
  printf("  working set : %llu MB, %llu nodes, %llu B/node\n",
         static_cast<unsigned long long>(g_working_set_bytes / (1024 * 1024)),
         static_cast<unsigned long long>(n_nodes),
         static_cast<unsigned long long>(sizeof(Node)));
}

volatile uint64_t g_sink = 0;

inline double ns_per_step(clk::duration d, uint64_t steps) {
  using ns = std::chrono::nanoseconds;
  return std::chrono::duration_cast<ns>(d).count() / static_cast<double>(steps);
}

// --- V0: serial, no prefetch ----------------------------------------------
double run_serial_no_prefetch() {
  Node* p = g_heads[0];
  auto t0 = clk::now();
  for (uint64_t i = 0; i < g_steps; i++) {
    p = p->next;
  }
  auto t1 = clk::now();
  g_sink += reinterpret_cast<uintptr_t>(p);
  return ns_per_step(t1 - t0, g_steps);
}

// --- V1: serial with one-ahead prefetch -----------------------------------
double run_serial_prefetch() {
  Node* p = g_heads[0];
  Node* q = p->next;
  auto t0 = clk::now();
  for (uint64_t i = 0; i < g_steps; i++) {
    __builtin_prefetch(q->next, 0, 0);
    p = q;
    q = q->next;
  }
  auto t1 = clk::now();
  g_sink += reinterpret_cast<uintptr_t>(p) + reinterpret_cast<uintptr_t>(q);
  return ns_per_step(t1 - t0, g_steps);
}

// --- V2: N fibers interleaved ---------------------------------------------
constexpr uint32_t MAX_N = 8;

tiny_fiber::FiberHandle g_thread_fiber;
tiny_fiber::FiberHandle g_fiber[MAX_N];

struct FiberState {
  Node*    cursor;
  uint64_t remaining;
};
FiberState g_state[MAX_N];

template <int /*tag*/>
void chase_fiber_main(void* arg) {
  uint32_t my_id = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg) - 1);
  while (true) {
    while (g_state[my_id].remaining > 0) {
      g_state[my_id].remaining--;
      Node* next = g_state[my_id].cursor->next;
      __builtin_prefetch(next, 0, 0);   // hide miss while other fibers run
      g_state[my_id].cursor = next;
      tiny_fiber::SwitchFiber(g_fiber[my_id], g_thread_fiber);
    }
    tiny_fiber::SwitchFiber(g_fiber[my_id], g_thread_fiber);
  }
}

double run_fiber_interleaved(uint32_t n) {
  g_thread_fiber = tiny_fiber::CreateFiberFromThread();
  uint64_t steps_each = g_steps / n;
  for (uint32_t i = 0; i < n; i++) {
    g_state[i].cursor    = g_heads[i];
    g_state[i].remaining = steps_each;
    g_fiber[i] = tiny_fiber::CreateFiber(
        64 * 1024, chase_fiber_main<0>,
        reinterpret_cast<void*>(static_cast<uintptr_t>(i + 1)));
  }

  auto t0 = clk::now();
  bool done = false;
  while (!done) {
    done = true;
    for (uint32_t i = 0; i < n; i++) {
      if (g_state[i].remaining > 0) {
        done = false;
        tiny_fiber::SwitchFiber(g_thread_fiber, g_fiber[i]);
      }
    }
  }
  auto t1 = clk::now();

  uint64_t total_steps = steps_each * n;
  for (uint32_t i = 0; i < n; i++) {
    g_sink += reinterpret_cast<uintptr_t>(g_state[i].cursor);
    tiny_fiber::DeleteFiber(g_fiber[i]);
  }
  tiny_fiber::DeleteFiber(g_thread_fiber);
  return ns_per_step(t1 - t0, total_steps);
}

} // namespace

int main(int argc, char** argv) {
  if (argc > 1) g_working_set_bytes = strtoull(argv[1], nullptr, 10) *
                                      1024ULL * 1024ULL;
  if (argc > 2) g_steps = strtoull(argv[2], nullptr, 10);

  printf("Phase 0 / Benchmark 3: MLP via fiber interleaving\n");
  build_chain();
  printf("  steps       : %llu (per variant)\n\n",
         static_cast<unsigned long long>(g_steps));

  double v0 = run_serial_no_prefetch();
  printf("  V0 serial, no prefetch          : %7.2f ns/step\n", v0);

  double v1 = run_serial_prefetch();
  printf("  V1 serial, +1 prefetch          : %7.2f ns/step  (%.2fx vs V0)\n",
         v1, v0 / v1);

  for (uint32_t n : {2u, 4u, 8u}) {
    double v = run_fiber_interleaved(n);
    printf("  V2 fiber-interleaved, n=%u       : %7.2f ns/step  (%.2fx vs V0)\n",
           n, v, v0 / v);
  }

  printf("\nsink: %llu\n", static_cast<unsigned long long>(g_sink));
  return 0;
}
