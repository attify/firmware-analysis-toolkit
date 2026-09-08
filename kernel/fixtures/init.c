#ifndef FAT_KERNEL_CLASS
#define FAT_KERNEL_CLASS "unknown"
#endif

#if defined(__mips__)
#define FAT_SYSCALL_BASE 4000

static long fat_syscall0(long number) {
    register long v0 __asm__("$2") = number;
    register long a3 __asm__("$7") = 0;
    __asm__ volatile("syscall" : "+r"(v0), "+r"(a3) : : "memory");
    return a3 ? -v0 : v0;
}

static long fat_syscall3(long number, long first, long second, long third) {
    register long v0 __asm__("$2") = number;
    register long a0 __asm__("$4") = first;
    register long a1 __asm__("$5") = second;
    register long a2 __asm__("$6") = third;
    register long a3 __asm__("$7") = 0;
    __asm__ volatile("syscall"
                     : "+r"(v0), "+r"(a3)
                     : "r"(a0), "r"(a1), "r"(a2)
                     : "memory");
    return a3 ? -v0 : v0;
}
#elif defined(__arm__)
#define FAT_SYSCALL_BASE 0

static long fat_syscall0(long number) {
    register long r0 __asm__("r0");
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
    return r0;
}

static long fat_syscall3(long number, long first, long second, long third) {
    register long r0 __asm__("r0") = first;
    register long r1 __asm__("r1") = second;
    register long r2 __asm__("r2") = third;
    register long r7 __asm__("r7") = number;
    __asm__ volatile("svc 0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r7)
                     : "memory");
    return r0;
}
#else
#error unsupported fixture architecture
#endif

static const char marker[] =
    "FAT-FIXTURE:USERSPACE_REACHED class=" FAT_KERNEL_CLASS " pid=1\n";

__attribute__((noreturn)) void _start(void) {
    (void)fat_syscall3(FAT_SYSCALL_BASE + 4, 1, (long)marker,
                       (long)(sizeof(marker) - 1));
    for (;;) {
        (void)fat_syscall0(FAT_SYSCALL_BASE + 29);
    }
}
