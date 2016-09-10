#ifndef _COTINY_H_
#define _COTINY_H_

// Sample:
// #include <iostream>
// #include "cotiny.hh"
// int main() {
//     uint8_t buf[2048];
//     cotiny::Coroutine<> co([](cotiny::Coroutine<>* co, int32_t arg) {
//         for(int32_t i = 0; i < arg; ++i)
//             co->yield(i * i);
//     }, 2048, buf);
//     while(co.resume(5)) {
//         std::cout << co.get_yield_value() << std::endl;
//     }
//     co.restart();
//     while(co.resume(8)) {
//         std::cout << co.get_yield_value() << std::endl;
//     }
//     return 0;
// }

#include <functional>
#include <cstdint>
#include <cstring>

namespace cotiny
{
#if (defined(_WIN32) || defined(_WIN64)) && defined(USING_WINDOWS_FIBER)
// use fiber library on windows
#include <windows.h>

    template<typename YIELD_TYPE = int32_t, typename RESUME_TYPE = int32_t>
    class Coroutine {
    public:
        Coroutine(std::function<void(Coroutine*, RESUME_TYPE)> co_fun, size_t ssize = 0, void* = nullptr) {
            coroutine_func = co_fun;
            parent = GetCurrentFiber();
            if(parent == (LPVOID)0x1E00)
                parent = ConvertThreadToFiber(0);
            if(GetFiberData() == nullptr) {
                static_counter()++;
                is_thread = true;
            }
            stack_size = ssize;
            child = CreateFiber(stack_size, &coroutine_proc, this);
        }
        
        ~Coroutine() {
            DeleteFiber(child);
            if(is_thread && --static_counter() == 0)
                ConvertFiberToThread();
        }
        
        bool resume(RESUME_TYPE v = RESUME_TYPE()) {
            if(finished)
                return false;
            resume_value = v;
            SwitchToFiber(child);
            return !finished;
        }
        
        RESUME_TYPE yield(YIELD_TYPE v = YIELD_TYPE()) {
            yield_value = v;
            SwitchToFiber(parent);
            return resume_value;
        }
        
        void restart() {
            finished = false;
            DeleteFiber(child);
            child = CreateFiber(stack_size, &coroutine_proc, this);
        }
        
        inline YIELD_TYPE get_yield_value() { return yield_value; }
        inline bool is_finished() { return finished; }
        
    protected:
        static void WINAPI coroutine_proc(LPVOID param) {
            Coroutine* co = reinterpret_cast<Coroutine*>(param);
            co->coroutine_func(co, co->resume_value);
            co->finished = true;
            SwitchToFiber(co->parent);
        }
        
        inline int32_t& static_counter() { static thread_local int32_t coroutine_counter; return coroutine_counter; }
        
        std::function<void(Coroutine*, RESUME_TYPE)> coroutine_func;
        LPVOID parent;
        LPVOID child;
        YIELD_TYPE yield_value = YIELD_TYPE();
        RESUME_TYPE resume_value = RESUME_TYPE();
        size_t stack_size = 0;
        bool is_thread = false;
        bool finished = false;
    };

#else // WINDOWS FIBER

#define DISABLE_INLINE __attribute__((noinline))

#if defined(__i386__) || defined(_WIN32)

    // important registers only
    struct cpu_context {
        long eax;
        long ebx;
        long ecx;
        long edx;
        long edi;
        long esi;
        long eip;
        long ebp;
        long esp;
    };

    class coroutine_util {
    private:
        DISABLE_INLINE
        static int32_t save_cpu_status(cpu_context* ctx) {
            // generally compiler will add prologue and epilogue for non-naked function
            // sometimes the prologue can be optimized so we have to check %rbp and %rsp
            __asm__(
                "cmpl %esp, %ebp\n"
                "jnz save_cpu32\n"
                "popl %ebp\n" 
                "save_cpu32:\n"
                "movl 4(%esp), %eax;"    // first param -> %eax
                "movl $1, (%eax);"
                "movl %ebx, 4(%eax);"
                "movl %ecx, 8(%eax);"
                "movl %edx, 12(%eax);"
                "movl %edi, 16(%eax);"
                "movl %esi, 20(%eax);"
                "movl %ebp, 28(%eax);"
                "movl (%esp), %ecx;"    // %eip
                "movl %ecx, 24(%eax);"
                "leal 4(%esp), %ecx;"   // %esp
                "movl %ecx, 32(%eax);"
                "movl 8(%eax), %ecx;"
                "movl $0, %eax;"
                "ret;"
            );
            // used to prevent ctx being optimized out
            return (int32_t)(reinterpret_cast<uintptr_t>(ctx) & 0xabcd);
        }
        
        DISABLE_INLINE
        static int32_t restore_cpu_status(const cpu_context* ctx) {
            __asm__(
                "cmpl %esp, %ebp\n"
                "jnz restore_cpu32\n"
                "popl %ebp\n" 
                "restore_cpu32:\n"
                "movl 4(%esp), %eax;"   // first param -> %eax
                "movl 4(%eax), %ebx;"
                "movl 8(%eax), %ecx;"
                "movl 12(%eax), %edx;"
                "movl 16(%eax), %edi;"
                "movl 20(%eax), %esi;"
                "movl 28(%eax), %ebp;"
                "movl 32(%eax), %esp;"
                "pushl 24(%eax);"
                "movl (%eax), %eax;"
                "ret;"
            );
            // used to prevent ctx being optimized out
            return (int32_t)(reinterpret_cast<uintptr_t>(ctx) & 0xabcd);
        }
        
    public:
        
        static uint8_t* init_stack(uint8_t* stack_pointer, size_t stack_size) {
            uintptr_t sp = reinterpret_cast<uintptr_t>(stack_pointer + stack_size);
            // make stack 4bytes-aligh
            sp = sp - sp % 4;
            // reserve arg and return address
            sp -= sizeof(long) * 2;
            return reinterpret_cast<uint8_t*>(sp);
        }
        
        static void init_context(cpu_context* ctx, void (*func)(void*), uint8_t* sp, void* arg) {
            save_cpu_status(ctx);
            *(long*)(sp + 4) = reinterpret_cast<long>(arg);
            ctx->eip = reinterpret_cast<long>(func);
            ctx->esp = reinterpret_cast<long>(sp);
        }
        
        static int32_t swap_context(cpu_context* octx, const cpu_context* ctx) {
            if(save_cpu_status(octx) == 0)
                restore_cpu_status(ctx);
            return 0;
        }
    };

#else // X86-64

    // important registers only
    struct cpu_context {
        long rdi;
        long rsi;
        long rax;
        long rbx;
        long rcx;
        long rdx;
        long r8;
        long r9;
        long r10;
        long r11;
        long r12;
        long r13;
        long r14;
        long r15;
        long rip;
        long rbp;
        long rsp;
    };

    class coroutine_util {
    private:
        DISABLE_INLINE
        static int32_t save_cpu_status(cpu_context* ctx) {
            // generally compiler will add prologue and epilogue for non-naked function
            // sometimes the prologue can be optimized so we have to check %rbp and %rsp
            asm(
                "cmpq %rsp, %rbp\n"
                "jnz save_cpu64\n"
                "popq %rbp\n" 
                "save_cpu64:\n"
                "movq %rdi, (%rdi)\n"
                "movq %rsi, 8(%rdi)\n"
                "movq $1, 16(%rdi)\n"
                "movq %rbx, 24(%rdi)\n"
                "movq %rcx, 32(%rdi)\n"
                "movq %rdx, 40(%rdi)\n"
                "movq %r8, 48(%rdi)\n"
                "movq %r9, 56(%rdi)\n"
                "movq %r10, 64(%rdi)\n"
                "movq %r11, 72(%rdi)\n"
                "movq %r12, 80(%rdi)\n"
                "movq %r13, 88(%rdi)\n"
                "movq %r14, 96(%rdi)\n"
                "movq %r15, 104(%rdi)\n"
                "movq %rbp, 120(%rdi)\n"
                "movq (%rsp), %rax\n"    // %rip
                "movq %rax, 112(%rdi)\n"
                "leaq 8(%rsp), %rax\n"   // %rsp
                "movq %rax, 128(%rdi)\n"
                "movq $0, %rax\n"
                "ret\n"
            );
            // used to prevent ctx being optimized out
            return (int32_t)(reinterpret_cast<uintptr_t>(ctx) & 0xabcd);
        }
        
        DISABLE_INLINE
        static int32_t restore_cpu_status(const cpu_context* ctx) {
            __asm__(
                "movq 8(%rdi), %rsi\n"
                "movq 16(%rdi), %rax\n"
                "movq 24(%rdi), %rbx\n"
                "movq 32(%rdi), %rcx\n"
                "movq 40(%rdi), %rdx\n"
                "movq 48(%rdi), %r8\n"
                "movq 56(%rdi), %r9\n"
                "movq 64(%rdi), %r10\n"
                "movq 72(%rdi), %r11\n"
                "movq 80(%rdi), %r12\n"
                "movq 88(%rdi), %r13\n"
                "movq 96(%rdi), %r14\n"
                "movq 104(%rdi), %r15\n"
                "movq 120(%rdi), %rbp\n"
                "movq 128(%rdi), %rsp\n"
                "pushq 112(%rdi)\n"
                "movq (%rdi), %rdi\n"
                "ret\n"
            );
            // used to prevent ctx being optimized out
            return (int32_t)(reinterpret_cast<uintptr_t>(ctx) & 0xabcd);
        }
        
    public:
        static uint8_t* init_stack(uint8_t* stack_pointer, size_t stack_size) {
            uintptr_t sp = reinterpret_cast<uintptr_t>(stack_pointer + stack_size);
            // make stack pointer 16bytes-align (OSX)
            sp = sp - sp % 16;
            // we don't need to push args because the args are passed by register %rdi
            // we have to reserve space for return address to prevent "stack_not_16_byte_aligned_error"
            sp -= sizeof(long);
            return reinterpret_cast<uint8_t*>(sp);
        }
        
        static void init_context(cpu_context* ctx, void (*func)(void*), uint8_t* sp, void* arg) {
            save_cpu_status(ctx);
            ctx->rdi = reinterpret_cast<long>(arg);
            ctx->rip = reinterpret_cast<long>(func);
            ctx->rsp = reinterpret_cast<long>(sp);
        }
        
        static int32_t swap_context(cpu_context* octx, const cpu_context* ctx) {
            if(save_cpu_status(octx) == 0)
                restore_cpu_status(ctx);
            return 0;
        }
    };

#endif // i386/x64

    template<typename YIELD_TYPE = int32_t, typename RESUME_TYPE = int32_t>
    class Coroutine {
    public:
        // disable shared stack feature while using Address Sanitizer
        // otherwise you will get a stack-buffer-overflow error when stack memory swap
        Coroutine(std::function<void(Coroutine*, RESUME_TYPE)> co_fun, size_t stack_size = 0x10000, void* sstack_ptr = nullptr) {
            coroutine_func = co_fun;
            if(sstack_ptr) {
                share_stack = true;
                stack_pointer = static_cast<uint8_t*>(sstack_ptr);
            } else
                stack_pointer = new uint8_t[stack_size];
            stack_top = coroutine_util::init_stack(stack_pointer, stack_size);
            coroutine_util::init_context(&child, (void(*)(void*))coroutine_proc, stack_top, this);
        }
        
        ~Coroutine() {
            if(!share_stack)
                delete[] stack_pointer;
            if(stack_cache)
                delete[] stack_cache;
        }
        
        bool resume(RESUME_TYPE v = RESUME_TYPE()) {
            if(finished)
                return false;
            resume_value = v;
            if(share_stack)
                restore_stack();
            coroutine_util::swap_context(&parent, &child);
            if(share_stack)
                save_stack();
            return !finished;
        }
        
        RESUME_TYPE yield(YIELD_TYPE v = YIELD_TYPE()) {
            long stack_var = 0;
            stack_bottom = reinterpret_cast<uint8_t*>(&stack_var);
            yield_value = v;
            coroutine_util::swap_context(&child, &parent);
            return resume_value;
        }
        
        void restart() {
            finished = false;
            coroutine_util::init_context(&child, (void(*)(void*))coroutine_proc, stack_top, this);
        }
        
        inline YIELD_TYPE get_yield_value() { return yield_value; }
        inline bool is_finished() { return finished; }
        
    protected:
        
        static void coroutine_proc(Coroutine* ycon) {
            ycon->coroutine_func(ycon, ycon->resume_value);
            ycon->finished = true;
            // the context must be swapped before the function returns
            coroutine_util::swap_context(&ycon->child, &ycon->parent);
        }
        
        void save_stack() {
            int32_t used_stack_size = (int32_t)(stack_top - stack_bottom);
            if(stack_cache_reserve == 0) {
                stack_cache_reserve = used_stack_size + 256;
                stack_cache = new uint8_t[stack_cache_reserve];
            } else if(used_stack_size > stack_cache_reserve) {
                delete[] stack_cache;
                stack_cache_reserve = used_stack_size + 256;
                stack_cache = new uint8_t[stack_cache_reserve];
            }
            stack_cache_size = used_stack_size;
            memcpy(stack_cache, stack_top - stack_cache_size, stack_cache_size);
        }
        
        void restore_stack() {
            if(stack_cache)
                memcpy(stack_top - stack_cache_size, stack_cache, stack_cache_size);
        }
        
        std::function<void(Coroutine*, RESUME_TYPE)> coroutine_func;
        cpu_context parent;
        cpu_context child;
        YIELD_TYPE yield_value = YIELD_TYPE();
        RESUME_TYPE resume_value = RESUME_TYPE();
        uint8_t* stack_pointer = nullptr;
        uint8_t* stack_top = nullptr;
        uint8_t* stack_cache = nullptr;
        uint8_t* stack_bottom = nullptr;
        bool share_stack = false;
        bool finished = false;
        int32_t stack_cache_size = 0;
        int32_t stack_cache_reserve = 0;
    };

#endif // WINDOWS FIBER
    
} // namespace end

#endif // _COTINY_H_
