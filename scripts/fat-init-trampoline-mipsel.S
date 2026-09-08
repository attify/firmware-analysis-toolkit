/*
 * FAT-owned MIPSEL PID-1 trampoline.
 *
 * Some compatible research kernels add an LD_PRELOAD entry to the initial
 * process environment. A shell-script init cannot remove it because the
 * dynamic loader acts before the script runs. This static, libc-free entry
 * point execs FAT's generated preinit with a minimal known environment.
 *
 * Reproduce with LLVM:
 *   clang --target=mipsel-linux-none -march=mips1 -mabi=32 -fno-pic \
 *     -fuse-ld=lld -nostdlib -static \
 *     -Wl,--build-id=none,-e,_start,-Ttext=0x00400000,-z,max-page-size=4096 \
 *     -o fat-init-trampoline.mipsel scripts/fat-init-trampoline-mipsel.S
 *   llvm-strip --strip-all fat-init-trampoline.mipsel
 */

    .set noreorder
    .set nomips16
    .text
    .globl _start
    .ent _start
_start:
    lui     $a0, %hi(preinit_path)
    addiu   $a0, $a0, %lo(preinit_path)
    lui     $a1, %hi(preinit_argv)
    addiu   $a1, $a1, %lo(preinit_argv)
    lui     $a2, %hi(preinit_envp)
    addiu   $a2, $a2, %lo(preinit_envp)
    addiu   $v0, $zero, 4011       /* __NR_execve */
    syscall

    addiu   $a0, $zero, 127
    addiu   $v0, $zero, 4001       /* __NR_exit */
    syscall
    .end _start

    .data
    .align 2
preinit_path:
    .asciz  "/fat/preinit.sh"
home_env:
    .asciz  "HOME=/"
term_env:
    .asciz  "TERM=linux"
path_env:
    .asciz  "PATH=/fat/shims:/bin:/sbin:/usr/bin:/usr/sbin"

    .align 2
preinit_argv:
    .word   preinit_path
    .word   0
preinit_envp:
    .word   home_env
    .word   term_env
    .word   path_env
    .word   0
