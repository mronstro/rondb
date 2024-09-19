#include <iostream>
#include "tiny_fiber.h"

/**
 * A very simple test program checking how fibers and threads interact.
 * The program will printout the following:
hello from fibermain
hello from main
hello from fibermain 2
hello from main 2
 */

tiny_fiber::FiberHandle thread_fiber;
tiny_fiber::FiberHandle fiber;

void fibermain(void* arg) {
  tiny_fiber::FiberHandle fiber =
  *reinterpret_cast<tiny_fiber::FiberHandle*>(arg);
  std::cout<<"hello from fibermain"<<std::endl;
  tiny_fiber::SwitchFiber(fiber, thread_fiber);
  std::cout<<"hello from fibermain 2"<<std::endl;
  tiny_fiber::SwitchFiber(fiber, thread_fiber);
}

int main(int argc, char** argv) {
  const int stack_size = 1024 * 16;
  thread_fiber = tiny_fiber::CreateFiberFromThread();
  fiber = tiny_fiber::CreateFiber(stack_size, fibermain, &fiber);
  tiny_fiber::SwitchFiber(thread_fiber, fiber);
  std::cout<<"hello from main"<<std::endl;
  tiny_fiber::SwitchFiber(thread_fiber, fiber);
  std::cout<<"hello from main 2"<<std::endl;
  return 0;
}
