/*
    MIT License

    Copyright (c) 2023 Jiayin Cao

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 */

/*
   Copyright (c) 2024, 2024, Hopsworks and/or its affiliates.
   Use is subject to license terms.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#ifndef TINY_FIBER_H
#define TINY_FIBER_H


// Tiny fiber is a lazor thin library that support fiber interfaces on different 64 bits platforms.
// User can include this one header file in their project to use fiber in their own projects.
// It is currently supported on the following platform
//   - X64 Windows
//   - X64 Linux
//   - X64 Mac
//   - Arm64 Linux
//   - Arm64 Mac
//
// Below is a simple example demonstrating the basic usage of the library
//
//     #include <iostream>
//     #include "tiny_fiber.h"
//
//     tiny_fiber::FiberHandle thread_fiber;
//     tiny_fiber::FiberHandle fiber;
//
//     void fibermain(void* arg) {
//         tiny_fiber::FiberHandle fiber = *reinterpret_cast<tiny_fiber::FiberHandle*>(arg);
//         std::cout<<"hello fiber"<<std::endl;
//         tiny_fiber::SwitchFiber(fiber, thread_fiber);
//     }
//
//     int main(int argc, char** argv) {
//         const int stack_size = 1024 * 16;
//         thread_fiber = tiny_fiber::CreateFiberFromThread();
//         fiber = tiny_fiber::CreateFiber(stack_size, fibermain, &fiber);
//         tiny_fiber::SwitchFiber(thread_fiber, fiber);
//         return 0;
//     }
//

#pragma once

#if defined(__aarch64__)
    #define TINY_FIBER_ARM64
#elif defined(__x86_64__) || defined(_M_X64)
    #define TINY_FIBER_X64
#else
    #error "Target architecture is not supported."
#endif

#if defined(__APPLE__)
    #define TINY_FIBER_APPLE
#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #define TINY_FIBER_WIN
#elif defined(__linux__)
    #define TINY_FIBER_LINUX
#else
    #error "Target Platform is not supported."
#endif

#if defined(TINY_FIBER_ARM64) && !defined(TINY_FIBER_WIN)
    #define FIBER_ASM_ARM64_IMPLEMENTATION
#elif defined(TINY_FIBER_X64) && !defined(TINY_FIBER_WIN)
    #define FIBER_ASM_X64_IMPLEMENTATION
#endif

#if defined(TINY_FIBER_MALLOC) && defined(TINY_FIBER_FREE)
// custom stack allocation is fine
#elif !defined(TINY_FIBER_MALLOC) && !defined(TINY_FIBER_FREE)
// default stack allocation is fine either
#else
#error "Do not define either of TINY_FIBER_MALLOC and TINY_FIBER_FREE"
#endif

#include <memory>

#if defined(TINY_FIBER_WIN)
#include <Windows.h>
#endif

#ifndef TINY_FIBER_MALLOC
#define TINY_FIBER_MALLOC   malloc
#define TINY_FIBER_FREE     free
#endif

namespace tiny_fiber {

// an alias for CPU registers, all need to be 64 bits long
typedef unsigned long long  Register;

// check the register size, making sure it is 8 bytes.
static_assert(sizeof(Register) == 8, "Incorrect register size");

// helper macro to check the offset of a register in fiber context
#define CHECK_OFFSET(REGISTER, OFFSET)    \
    static_assert(offsetof(FiberContexInternal, REGISTER) == OFFSET, \
                  "Incorrect register offset")

// Both x64 and arm64 require stack memory pointer to be 16 bytes aligned
#define FIBER_STACK_ALIGNMENT    16

// MacOS requires a _ to be defined at the beginning of a function name implemented in asm
#if defined(TINY_FIBER_APPLE)
    #define _switch_fiber_internal switch_fiber_internal
#endif

#ifdef FIBER_ASM_ARM64_IMPLEMENTATION

#define FIBER_ASM_IMPLEMENTATION

// alias for registers that need to be saved during a fiber switch
#define FIBER_REG_X0    0x00
#define FIBER_REG_X16   0x08
#define FIBER_REG_X17   0x10
#define FIBER_REG_X18   0x18
#define FIBER_REG_X19   0x20
#define FIBER_REG_X20   0x28
#define FIBER_REG_X21   0x30
#define FIBER_REG_X22   0x38
#define FIBER_REG_X23   0x40
#define FIBER_REG_X24   0x48
#define FIBER_REG_X25   0x50
#define FIBER_REG_X26   0x58
#define FIBER_REG_X27   0x60
#define FIBER_REG_X28   0x68
#define FIBER_REG_X29   0x70
#define FIBER_REG_X30   0x78
#define FIBER_REG_V8    0x80
#define FIBER_REG_V9    0x88
#define FIBER_REG_V10   0x90
#define FIBER_REG_V11   0x98
#define FIBER_REG_V12   0xa0
#define FIBER_REG_V13   0xa8
#define FIBER_REG_V14   0xb0
#define FIBER_REG_V15   0xb8
#define FIBER_REG_SP    0xc0

/**
 * On Arm 64 architecture, each register should be 64 bits. And following registers need to be
 * saved during a context switch
 *   - [X16 - X30]
 *     https://developer.arm.com/documentation/102374/0101/Procedure-Call-Standard
 *   - [D16 - D23]
 *     https://developer.arm.com/documentation/den0024/a/The-ABI-for-ARM-64-bit-Architecture/Register-use-in-the-AArch64-Procedure-Call-Standard/Parameters-in-NEON-and-floating-point-registers
 */
struct FiberContexInternal {
    // funciton paramters
    Register    x0;

    // general purpose registers
    Register    x16;
    Register    x17;
    Register    x18;
    Register    x19;
    Register    x20;
    Register    x21;
    Register    x22;
    Register    x23;
    Register    x24;
    Register    x25;
    Register    x26;
    Register    x27;
    Register    x28;
    Register    x29;    // frame pointer (FP)
    Register    x30;    // link register (R30)

    // float-point and neon registers
    Register    v8;
    Register    v9;
    Register    v10;
    Register    v11;
    Register    v12;
    Register    v13;
    Register    v14;
    Register    v15;

    // stack pointer
    Register    sp;     
};

// Making sure our offsets are all correct
CHECK_OFFSET(x0,  FIBER_REG_X0);
CHECK_OFFSET(x16, FIBER_REG_X16);
CHECK_OFFSET(x17, FIBER_REG_X17);
CHECK_OFFSET(x18, FIBER_REG_X18);
CHECK_OFFSET(x19, FIBER_REG_X19);
CHECK_OFFSET(x20, FIBER_REG_X20);
CHECK_OFFSET(x21, FIBER_REG_X21);
CHECK_OFFSET(x22, FIBER_REG_X22);
CHECK_OFFSET(x23, FIBER_REG_X23);
CHECK_OFFSET(x24, FIBER_REG_X24);
CHECK_OFFSET(x25, FIBER_REG_X25);
CHECK_OFFSET(x26, FIBER_REG_X26);
CHECK_OFFSET(x27, FIBER_REG_X27);
CHECK_OFFSET(x28, FIBER_REG_X28);
CHECK_OFFSET(x29, FIBER_REG_X29);
CHECK_OFFSET(x30, FIBER_REG_X30);
CHECK_OFFSET(v8,  FIBER_REG_V8);
CHECK_OFFSET(v9,  FIBER_REG_V9);
CHECK_OFFSET(v10, FIBER_REG_V10);
CHECK_OFFSET(v11, FIBER_REG_V11);
CHECK_OFFSET(v12, FIBER_REG_V12);
CHECK_OFFSET(v13, FIBER_REG_V13);
CHECK_OFFSET(v14, FIBER_REG_V14);
CHECK_OFFSET(v15, FIBER_REG_V15);
CHECK_OFFSET(sp,  FIBER_REG_SP);

// create a new fiber
extern "C" inline bool _create_fiber_internal(void* stack, uint32_t stack_size, void (*target)(void*), void* arg, FiberContexInternal* context) {
    // it is the users responsibility to make sure the stack is 16 bytes aligned, which is required by the Arm64 architecture
    if((((uintptr_t)stack) & (FIBER_STACK_ALIGNMENT - 1)) != 0)
        return false;

    uintptr_t* stack_top = (uintptr_t*)((uint8_t*)(stack) + stack_size);
    context->x30 = (uintptr_t)target;
    context->x0 = (uintptr_t)arg;
    context->sp = (uintptr_t)stack_top;

    return true;
}

// switching to a different fiber
asm(
R"(
.text
.align 4
_switch_fiber_internal:
    str x16, [x0, 0x08] /* FIBER_REG_X16 */
    str x17, [x0, 0x10] /* FIBER_REG_X17 */
    str x18, [x0, 0x18] /* FIBER_REG_X18 */

    str x19, [x0, 0x20] /* FIBER_REG_X19 */
    str x20, [x0, 0x28] /* FIBER_REG_X20 */
    str x21, [x0, 0x30] /* FIBER_REG_X21 */
    str x22, [x0, 0x38] /* FIBER_REG_X22 */
    str x23, [x0, 0x40] /* FIBER_REG_X23 */
    str x24, [x0, 0x48] /* FIBER_REG_X24 */
    str x25, [x0, 0x50] /* FIBER_REG_X25 */
    str x26, [x0, 0x58] /* FIBER_REG_X26 */
    str x27, [x0, 0x60] /* FIBER_REG_X27 */
    str x28, [x0, 0x68] /* FIBER_REG_X28 */
    str x29, [x0, 0x70] /* FIBER_REG_X29 */

    str d8,  [x0, 0x80] /* FIBER_REG_V8 */
    str d9,  [x0, 0x88] /* FIBER_REG_V9 */
    str d10, [x0, 0x90] /* FIBER_REG_V10 */
    str d11, [x0, 0x98] /* FIBER_REG_V11 */
    str d12, [x0, 0xa0] /* FIBER_REG_V12 */
    str d13, [x0, 0xa8] /* FIBER_REG_V13 */
    str d14, [x0, 0xb0] /* FIBER_REG_V14 */
    str d15, [x0, 0xb8] /* FIBER_REG_V15 */

    // store sp and lr
    mov x2, sp
    str x2,  [x0, 0xc0] /* FIBER_REG_SP */
    str x30, [x0, 0x78] /* FIBER_REG_X30 */

    // load context 'to'
    mov x7, x1

    ldr x16, [x7, 0x08] /* FIBER_REG_X16 */
    ldr x17, [x7, 0x10] /* FIBER_REG_X17 */
    ldr x18, [x7, 0x18] /* FIBER_REG_X18 */

    ldr x19, [x7, 0x20] /* FIBER_REG_X19 */
    ldr x20, [x7, 0x28] /* FIBER_REG_X20 */
    ldr x21, [x7, 0x30] /* FIBER_REG_X21 */
    ldr x22, [x7, 0x38] /* FIBER_REG_X22 */
    ldr x23, [x7, 0x40] /* FIBER_REG_X23 */
    ldr x24, [x7, 0x48] /* FIBER_REG_X24 */
    ldr x25, [x7, 0x50] /* FIBER_REG_X25 */
    ldr x26, [x7, 0x58] /* FIBER_REG_X26 */
    ldr x27, [x7, 0x60] /* FIBER_REG_X27 */
    ldr x28, [x7, 0x68] /* FIBER_REG_X28 */
    ldr x29, [x7, 0x70] /* FIBER_REG_X29 */

    ldr d8,  [x7, 0x80] /* FIBER_REG_V8 */
    ldr d9,  [x7, 0x88] /* FIBER_REG_V9 */
    ldr d10, [x7, 0x90] /* FIBER_REG_V10 */
    ldr d11, [x7, 0x98] /* FIBER_REG_V11 */
    ldr d12, [x7, 0xa0] /* FIBER_REG_V12 */
    ldr d13, [x7, 0xa8] /* FIBER_REG_V13 */
    ldr d14, [x7, 0xb0] /* FIBER_REG_V14 */
    ldr d15, [x7, 0xb8] /* FIBER_REG_V15 */

    // Load first parameter, this is only used for the first time a fiber gains control
    ldr x0, [x7, 0x00]  /* FIBER_REG_X0 */

    ldr x30, [x7, 0x78] /* FIBER_REG_X30 */
    ldr x2,  [x7, 0xc0] /* FIBER_REG_SP */
    mov sp, x2

    ret
)");

#elif defined(FIBER_ASM_X64_IMPLEMENTATION)

#define FIBER_ASM_IMPLEMENTATION

#define FIBER_REG_RBX 0x00
#define FIBER_REG_RBP 0x08
#define FIBER_REG_R12 0x10
#define FIBER_REG_R13 0x18
#define FIBER_REG_R14 0x20
#define FIBER_REG_R15 0x28
#define FIBER_REG_RDI 0x30
#define FIBER_REG_RSP 0x38
#define FIBER_REG_RIP 0x40

//! Fiber context that saves all the callee saved registers
/**
 * The specific set of register is architecture and OS dependent. SORT uses this implementation for
 * Intel Mac and X64 Ubuntu, which use 'System V AMD64 ABI'.
 * https://en.wikipedia.org/wiki/X86_calling_conventions#cite_note-AMD-28
 * 
 * System V Application Binary Interface AMD64 Architecture Processor Supplement
 * Page 23, AMD64 ABI Draft 1.0
 * https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf
 */
struct FiberContexInternal {
    // callee-saved registers
    Register rbx;
    Register rbp;
    Register r12;
    Register r13;
    Register r14;
    Register r15;

    // parameter registers
    Register rdi;

    // stack and instruction registers
    Register rsp;
    Register rip;
};

CHECK_OFFSET(rbx, FIBER_REG_RBX);
CHECK_OFFSET(rbp, FIBER_REG_RBP);
CHECK_OFFSET(r12, FIBER_REG_R12);
CHECK_OFFSET(r13, FIBER_REG_R13);
CHECK_OFFSET(r14, FIBER_REG_R14);
CHECK_OFFSET(r15, FIBER_REG_R15);
CHECK_OFFSET(rdi, FIBER_REG_RDI);
CHECK_OFFSET(rsp, FIBER_REG_RSP);
CHECK_OFFSET(rip, FIBER_REG_RIP);

// create a new fiber
inline bool _create_fiber_internal(void* stack, uint32_t stack_size, void (*target)(void*), void* arg, FiberContexInternal* context) {
    // it is the users responsibility to make sure the stack is 16 bytes aligned, which is required by the Arm64 architecture
    if((((uintptr_t)stack) & (FIBER_STACK_ALIGNMENT - 1)) != 0)
        return false;

    uintptr_t* stack_top = (uintptr_t*)((uint8_t*)(stack) + stack_size);
    context->rip = (uintptr_t)target;
    context->rdi = (uintptr_t)arg;
    context->rsp = (uintptr_t)&stack_top[-3];
    stack_top[-2] = 0;

    return true;
}

// switching to a different fiber
asm(
R"(
.text
.align 4
_switch_fiber_internal:

    // Save context 'from'

    // Store callee-preserved registers
    movq        %rbx, 0x00(%rdi) /* FIBER_REG_RBX */
    movq        %rbp, 0x08(%rdi) /* FIBER_REG_RBP */
    movq        %r12, 0x10(%rdi) /* FIBER_REG_R12 */
    movq        %r13, 0x18(%rdi) /* FIBER_REG_R13 */
    movq        %r14, 0x20(%rdi) /* FIBER_REG_R14 */
    movq        %r15, 0x28(%rdi) /* FIBER_REG_R15 */

    /* call stores the return address on the stack before jumping */
    movq        (%rsp), %rcx             
    movq        %rcx, 0x40(%rdi) /* FIBER_REG_RIP */
    
    /* skip the pushed return address */
    leaq        8(%rsp), %rcx            
    movq        %rcx, 0x38(%rdi) /* FIBER_REG_RSP */

    // Load context 'to'
    movq        %rsi, %r8

    // Load callee-preserved registers
    movq        0x00(%r8), %rbx /* FIBER_REG_RBX */
    movq        0x08(%r8), %rbp /* FIBER_REG_RBP */
    movq        0x10(%r8), %r12 /* FIBER_REG_R12 */
    movq        0x18(%r8), %r13 /* FIBER_REG_R13 */
    movq        0x20(%r8), %r14 /* FIBER_REG_R14 */
    movq        0x28(%r8), %r15 /* FIBER_REG_R15 */

    // Load first parameter, this is only used for the first time a fiber gains control
    movq        0x30(%r8), %rdi /* FIBER_REG_RDI */

    // Load stack pointer
    movq        0x38(%r8), %rsp /* FIBER_REG_RSP */

    // Load instruction pointer, and jump
    movq        0x40(%r8), %rcx /* FIBER_REG_RIP */
    jmp         *%rcx
)");

#elif defined(TINY_FIBER_WIN)

struct FiberContexInternal {
    // handle to hold fiber
    LPVOID  raw_fiber_handle = nullptr;
};

#endif

#if defined(FIBER_ASM_IMPLEMENTATION)

#if __has_attribute (optnone)
    #define FORCENOTINLINE     __attribute__((optnone))
#elif __has_attribute (noinline)
    #define FORCENOTINLINE     __attribute__((noinline))
#else
    #define FORCENOTINLINE
#endif

extern "C" 
{
    extern void FORCENOTINLINE _switch_fiber_internal(FiberContexInternal* from, const FiberContexInternal* to);
}
#endif

//! Abstruction for fiber struct.
struct Fiber {
    /**< fiber context, this is platform dependent. */
    FiberContexInternal     context;

#if defined(FIBER_ASM_IMPLEMENTATION)
    /**< Pointer to stack. */
    void*                   stack_ptr = nullptr;

    /**< Stack size. */
    unsigned int            stack_size = 0;
#elif defined(TINY_FIBER_WIN)
    // whether the fiber is originated from a thread or not
    bool                    is_fiber_from_thread = false;
#endif
};

// Define fiber handle
typedef Fiber*  FiberHandle;

//! Create a new fiber.
//!
//! Allocate stack memory for the fiber. If there is no valid function pointer provided, it will fail.
inline FiberHandle CreateFiber(uint32_t stack_size, void (*fiber_func)(void*), void* arg) {
    if(stack_size == 0 || !fiber_func || !arg)
        return nullptr;

    Fiber* ptr = (Fiber*)TINY_FIBER_MALLOC(sizeof(Fiber));

    ptr->context = {};

#if defined(FIBER_ASM_IMPLEMENTATION)
    ptr->stack_ptr = TINY_FIBER_MALLOC(stack_size + FIBER_STACK_ALIGNMENT - 1);
    ptr->stack_size = stack_size;

    if(!ptr->stack_ptr)
        return nullptr;

    // Make sure the stack meets the alignment requirement
    uintptr_t aligned_stack_ptr = (uintptr_t)ptr->stack_ptr;
    aligned_stack_ptr += FIBER_STACK_ALIGNMENT - 1;
    aligned_stack_ptr &= ~(FIBER_STACK_ALIGNMENT - 1);

    if(!_create_fiber_internal((void*)aligned_stack_ptr, stack_size, fiber_func, arg, &ptr->context))
    	return nullptr;
#elif defined(TINY_FIBER_WIN)
    ptr->context.raw_fiber_handle = ::CreateFiber(stack_size, fiber_func, arg);
    ptr->is_fiber_from_thread = false;
#endif

    return ptr;
}

//! Convert the current thread to fiber.
//!
//! Note, on Ubuntu and Mac, this doesn't really convert the current thread to a new fiber, it really just creates a brand new fiber that has nothing to do
//! with the current thread. However, as long as the thread first switch to a fiber from this created fiber, this would allow the thread fiber to capture 
//! the thread context.
inline FiberHandle CreateFiberFromThread() {
    Fiber* ptr = (Fiber*)TINY_FIBER_MALLOC(sizeof(Fiber));
#if defined(FIBER_ASM_IMPLEMENTATION)
    ptr->context = {};
    ptr->stack_ptr = nullptr;
    ptr->stack_size = 0;
#elif defined(TINY_FIBER_WIN)
    ptr->context.raw_fiber_handle = ConvertThreadToFiber(nullptr);
    ptr->is_fiber_from_thread = true;
#endif

    return ptr;
}

//! Switch from one fiber to another different fiber
//!
//! The upper level logic should have checked for same fiber switch. The low level implementation defined here won't do such a check. In the case of
//! switching to a same fiber, it should not crash the system. But there could be some loss of performance. Another more important thing that derserve our 
//! attention is that the high level code will have to make sure the from_fiber is the current executing fiber, otherwise there will be undefined behavior.
inline void SwitchFiber(Fiber* from_fiber, const Fiber* to_fiber) {
#if defined(FIBER_ASM_IMPLEMENTATION)
    _switch_fiber_internal(&from_fiber->context, &to_fiber->context);
#elif defined(TINY_FIBER_WIN)
    ::SwitchToFiber(to_fiber->context.raw_fiber_handle);
#endif
}

//! Delete a fiber
//!
//! If the fiber is converted from a thread, delete fiber will convert the fiber back to a regular thread then.
inline void DeleteFiber(FiberHandle fiber_handle){
    if(!fiber_handle)
        return;

#if defined(TINY_FIBER_WIN)
    if (fiber_handle->is_fiber_from_thread)
        ConvertFiberToThread();
    else
        ::DeleteFiber(fiber_handle->context.raw_fiber_handle);

    fiber_handle->context.raw_fiber_handle = nullptr;
    fiber_handle->is_fiber_from_thread = false;
#elif defined(FIBER_ASM_IMPLEMENTATION)
    if(fiber_handle->stack_ptr){
        TINY_FIBER_FREE(fiber_handle->stack_ptr);
        fiber_handle->stack_ptr = nullptr;
    }
#endif

    TINY_FIBER_FREE(fiber_handle);
}

} // namespace tiny_fiber
