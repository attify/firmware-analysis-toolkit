/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2026 Attify
 * This optional QEMU plugin is licensed separately from FAT.
 * See LICENSES/GPL-2.0-or-later.txt in the repository.
 */

/*
 * FAT Firmware Hook Plugin for QEMU TCG
 *
 * Pure data-plane plugin — hooks guest addresses, reads registers,
 * dereferences string arguments, and emits traces. All configuration
 * parsing happens in the Rust launcher; this plugin only accepts
 * pre-resolved hook= CLI args.
 *
 * Degrades gracefully when the target architecture does not expose
 * registers to the plugin API (known issue on MIPS system-mode in
 * QEMU <= 10.2 — the MIPS backend does not call
 * gdb_register_coprocessor, so qemu_plugin_get_registers() returns
 * empty). In degraded mode, hook hits are still logged with address
 * and hit count, but register values and string dereferences are
 * unavailable.
 *
 * Build (macOS arm64):
 *   cc -shared -fPIC -o fat-hook.so fat-hook-plugin.c \
 *      $(pkg-config --cflags glib-2.0) \
 *      -I$(brew --prefix)/include -undefined dynamic_lookup
 *
 * Usage:
 *   qemu-system-mipsel ... \
 *     -plugin fat-hook.so,hook=0x0043a070:hardware_reg,log=trace.jsonl \
 *     -d plugin
 *
 * Hook format:  hook=0xADDRESS:name[:flags]
 *   mX  — exact hex bitmask (bit 0=a0, 1=a1, 2=a2, 3=a3)
 *          m1=a0, m2=a1, m5=a0+a2, mf=all four
 *   sN  — legacy prefix shorthand (s1=a0, s2=a0+a1, s=all)
 */

#include <qemu-plugin.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ------------------------------------------------------------------ */
/* Register handle cache                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    REG_A0 = 0, REG_A1, REG_A2, REG_A3,
    REG_V0, REG_RA, REG_SP,
    REG_COUNT
} RegIndex;

static const char *reg_names[REG_COUNT] = {
    "a0", "a1", "a2", "a3", "v0", "ra", "sp"
};

static struct qemu_plugin_register *reg_handles[REG_COUNT] = { NULL };
static bool regs_initialized = false;
static bool any_regs = false;   /* true if at least one handle resolved */
static bool all_regs = false;   /* true if ALL required handles resolved */
static unsigned int target_reg_count = 0;  /* total regs exposed by QEMU */
static int resolved_count = 0;  /* how many of our REG_COUNT names matched */

/* Reusable buffer for register reads — allocated once in vcpu_init */
static GByteArray *reg_buf = NULL;

/* ------------------------------------------------------------------ */
/* Hook configuration                                                  */
/* ------------------------------------------------------------------ */

#define MAX_HOOKS 64
#define MAX_STRING_ARGS 4
#define MAX_STRING_LEN 512

typedef struct {
    uint64_t address;
    char name[64];
    uint64_t hit_count;
    uint8_t string_args_mask;  /* bit 0 = deref a0, bit 1 = a1, ... */
} HookEntry;

static HookEntry hooks[MAX_HOOKS];
static int num_hooks = 0;
static FILE *log_file = NULL;
static bool json_output = false;
static unsigned int flush_interval = 1;  /* fflush every N hits (0 = never) */
static char *target_name = NULL;

/* ------------------------------------------------------------------ */
/* Register / memory helpers                                           */
/* ------------------------------------------------------------------ */

static uint32_t read_reg_value(RegIndex idx)
{
    if (!reg_handles[idx] || !reg_buf) return 0;

    g_byte_array_set_size(reg_buf, 0);
    int size = qemu_plugin_read_register(reg_handles[idx], reg_buf);
    if (size < 4) return 0;

    uint32_t val;
    memcpy(&val, reg_buf->data, 4);
    return val;
}

/* Reusable buffer for memory reads */
static GByteArray *mem_buf = NULL;

static bool read_guest_string(uint64_t addr, char *out, size_t max_len)
{
    if (addr < 0x1000 || max_len == 0) {
        out[0] = '\0';
        return false;
    }

    if (!mem_buf) {
        mem_buf = g_byte_array_sized_new(MAX_STRING_LEN);
    }
    g_byte_array_set_size(mem_buf, 0);

    bool ok = qemu_plugin_read_memory_vaddr(addr, mem_buf, max_len);
    if (!ok || mem_buf->len == 0) {
        out[0] = '\0';
        return false;
    }

    size_t copy_len = 0;
    for (size_t i = 0; i < mem_buf->len && i < max_len - 1; i++) {
        if (mem_buf->data[i] == '\0') break;
        out[i] = mem_buf->data[i];
        copy_len = i + 1;
    }
    out[copy_len] = '\0';
    return copy_len > 0;
}

static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 6 < dst_len; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"')       { dst[di++] = '\\'; dst[di++] = '"'; }
        else if (c == '\\') { dst[di++] = '\\'; dst[di++] = '\\'; }
        else if (c == '\n') { dst[di++] = '\\'; dst[di++] = 'n'; }
        else if (c == '\r') { dst[di++] = '\\'; dst[di++] = 'r'; }
        else if (c == '\t') { dst[di++] = '\\'; dst[di++] = 't'; }
        else if (c < 0x20)  { di += snprintf(dst + di, dst_len - di, "\\u%04x", c); }
        else                { dst[di++] = c; }
    }
    dst[di] = '\0';
}

/* ------------------------------------------------------------------ */
/* Hook execution callback                                            */
/* ------------------------------------------------------------------ */

/* Helper: emit a single register as JSON value or null */
static void json_emit_reg(FILE *out, const char *name, RegIndex idx)
{
    if (reg_handles[idx]) {
        fprintf(out, ",\"%s\":\"0x%08x\"", name, read_reg_value(idx));
    } else {
        fprintf(out, ",\"%s\":null", name);
    }
}

static void hook_exec_cb(unsigned int vcpu_index, void *udata)
{
    HookEntry *hook = (HookEntry *)udata;
    hook->hit_count++;

    FILE *out = log_file ? log_file : stderr;

    if (!any_regs) {
        /* Degraded mode: no ABI register handles resolved */
        if (json_output) {
            fprintf(out,
                "{\"hook\":\"%s\",\"addr\":\"0x%08lx\",\"hit\":%lu,"
                "\"vcpu\":%u,\"mode\":\"degraded\"}\n",
                hook->name, (unsigned long)hook->address,
                (unsigned long)hook->hit_count, vcpu_index);
        } else {
            fprintf(out, "[FAT-HOOK] %s hit #%lu at 0x%08lx (vcpu=%u) "
                    "[degraded: no register data]\n",
                    hook->name, (unsigned long)hook->hit_count,
                    (unsigned long)hook->address, vcpu_index);
        }
        if (flush_interval && (hook->hit_count % flush_interval) == 0) {
            fflush(out);
        }
        return;
    }

    /* Read registers — only resolved handles return real values */
    uint32_t arg_vals[MAX_STRING_ARGS] = { 0 };
    static const RegIndex arg_regs[MAX_STRING_ARGS] = {
        REG_A0, REG_A1, REG_A2, REG_A3
    };
    for (int i = 0; i < MAX_STRING_ARGS; i++) {
        if (reg_handles[arg_regs[i]]) {
            arg_vals[i] = read_reg_value(arg_regs[i]);
        }
    }

    /* String dereference — only for resolved arg registers */
    char str_bufs[MAX_STRING_ARGS][MAX_STRING_LEN];
    bool str_ok[MAX_STRING_ARGS] = { false };
    for (int i = 0; i < MAX_STRING_ARGS; i++) {
        if ((hook->string_args_mask & (1 << i)) && reg_handles[arg_regs[i]]) {
            str_ok[i] = read_guest_string(arg_vals[i], str_bufs[i],
                                          MAX_STRING_LEN);
        }
    }

    if (json_output) {
        fprintf(out, "{\"hook\":\"%s\",\"addr\":\"0x%08lx\",\"hit\":%lu,"
                "\"vcpu\":%u",
                hook->name, (unsigned long)hook->address,
                (unsigned long)hook->hit_count, vcpu_index);

        /* Emit each register — null if handle is unresolved */
        json_emit_reg(out, "a0", REG_A0);
        json_emit_reg(out, "a1", REG_A1);
        json_emit_reg(out, "a2", REG_A2);
        json_emit_reg(out, "a3", REG_A3);
        json_emit_reg(out, "v0", REG_V0);
        json_emit_reg(out, "ra", REG_RA);
        json_emit_reg(out, "sp", REG_SP);

        for (int i = 0; i < MAX_STRING_ARGS; i++) {
            if (str_ok[i]) {
                char escaped[MAX_STRING_LEN * 2];
                json_escape(str_bufs[i], escaped, sizeof(escaped));
                fprintf(out, ",\"%s_str\":\"%s\"", reg_names[i], escaped);
            }
        }
        fprintf(out, "}\n");
    } else {
        fprintf(out, "[FAT-HOOK] %s hit #%lu at 0x%08lx (vcpu=%u)\n",
                hook->name, (unsigned long)hook->hit_count,
                (unsigned long)hook->address, vcpu_index);
        for (int r = 0; r < REG_COUNT; r++) {
            if (reg_handles[r]) {
                fprintf(out, "  %s=0x%08x", reg_names[r], read_reg_value(r));
            } else {
                fprintf(out, "  %s=???", reg_names[r]);
            }
            if (r == REG_A3 || r == REG_SP) fprintf(out, "\n");
        }

        for (int i = 0; i < MAX_STRING_ARGS; i++) {
            if (str_ok[i]) {
                fprintf(out, "  %s -> \"%s\"\n", reg_names[i], str_bufs[i]);
            }
        }
    }

    if (flush_interval && (hook->hit_count % flush_interval) == 0) {
        fflush(out);
    }
}

/* ------------------------------------------------------------------ */
/* Translation callback                                               */
/* ------------------------------------------------------------------ */

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t addr = qemu_plugin_insn_vaddr(insn);

        for (int h = 0; h < num_hooks; h++) {
            if (addr == hooks[h].address) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, hook_exec_cb,
                    any_regs ? QEMU_PLUGIN_CB_R_REGS
                             : QEMU_PLUGIN_CB_NO_REGS,
                    &hooks[h]);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* vCPU init — cache register handles and allocate reusable buffers   */
/* ------------------------------------------------------------------ */

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    if (regs_initialized) return;

    /* Allocate reusable buffers */
    reg_buf = g_byte_array_sized_new(8);
    mem_buf = g_byte_array_sized_new(MAX_STRING_LEN);

    GArray *regs = qemu_plugin_get_registers();
    if (!regs) {
        fprintf(stderr, "[FAT-HOOK] qemu_plugin_get_registers() returned NULL\n");
        regs_initialized = true;
        return;
    }

    fprintf(stderr, "[FAT-HOOK] Enumerating %u registers for vcpu %u\n",
            regs->len, vcpu_index);

    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *rd =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);

        for (int r = 0; r < REG_COUNT; r++) {
            if (strcmp(rd->name, reg_names[r]) == 0) {
                reg_handles[r] = rd->handle;
                fprintf(stderr, "[FAT-HOOK]   cached: %s (idx=%u)\n",
                        rd->name, i);
            }
        }
    }

    target_reg_count = regs->len;
    g_array_free(regs, TRUE);
    regs_initialized = true;

    /* Count resolved handles */
    resolved_count = 0;
    for (int r = 0; r < REG_COUNT; r++) {
        if (reg_handles[r]) resolved_count++;
    }
    any_regs = (resolved_count > 0);
    all_regs = (resolved_count == REG_COUNT);

    if (target_reg_count == 0) {
        /* Target exposes no registers at all via the plugin API */
        fprintf(stderr,
            "\n"
            "[FAT-HOOK] *** DEGRADED MODE: no register descriptors ***\n"
            "[FAT-HOOK] qemu_plugin_get_registers() returned 0 descriptors for '%s'.\n"
            "[FAT-HOOK] The '%s' target backend does not expose registers to the\n"
            "[FAT-HOOK] plugin API (QEMU MIPS system-mode is affected in <= 10.2).\n"
            "[FAT-HOOK]\n"
            "[FAT-HOOK] Hook hits will be logged with address and count only.\n"
            "[FAT-HOOK] For argument capture, use the GDB stub instead:\n"
            "[FAT-HOOK]   python3 scripts/fat-instrument.py --host 127.0.0.1 --port <gdb-port>\n"
            "\n",
            target_name, target_name);
    } else if (resolved_count == 0) {
        /* Target exposes registers but none match our ABI names */
        fprintf(stderr,
            "\n"
            "[FAT-HOOK] *** DEGRADED MODE: ABI register names not found ***\n"
            "[FAT-HOOK] The '%s' target exposes %u register descriptors, but none\n"
            "[FAT-HOOK] match the expected MIPS ABI names (a0-a3, v0, ra, sp).\n"
            "[FAT-HOOK] This plugin currently only maps MIPS calling convention\n"
            "[FAT-HOOK] registers. For other architectures, register name mapping\n"
            "[FAT-HOOK] needs to be added.\n"
            "[FAT-HOOK]\n"
            "[FAT-HOOK] Hook hits will be logged with address and count only.\n"
            "\n",
            target_name, target_reg_count);
    } else if (!all_regs) {
        /* Partial: some ABI names resolved, others didn't */
        fprintf(stderr,
            "[FAT-HOOK] Partial register resolution: %d/%d matched\n",
            resolved_count, REG_COUNT);
        for (int r = 0; r < REG_COUNT; r++) {
            if (!reg_handles[r]) {
                fprintf(stderr,
                    "[FAT-HOOK]   WARNING: register '%s' not found "
                    "(will be null in output)\n",
                    reg_names[r]);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Exit callback                                                      */
/* ------------------------------------------------------------------ */

static void plugin_exit_cb(qemu_plugin_id_t id, void *udata)
{
    FILE *out = log_file ? log_file : stderr;

    const char *mode = all_regs ? "full" : any_regs ? "partial" : "degraded";

    if (json_output) {
        fprintf(out, "{\"event\":\"summary\",\"mode\":\"%s\""
                ",\"resolved_regs\":%d,\"total_regs\":%d,\"hooks\":[",
                mode, resolved_count, REG_COUNT);
        for (int i = 0; i < num_hooks; i++) {
            if (i > 0) fprintf(out, ",");
            fprintf(out, "{\"name\":\"%s\",\"addr\":\"0x%08lx\",\"hits\":%lu}",
                    hooks[i].name, (unsigned long)hooks[i].address,
                    (unsigned long)hooks[i].hit_count);
        }
        fprintf(out, "]}\n");
    } else {
        fprintf(out, "\n[FAT-HOOK] === Summary (%s mode, %d/%d regs) ===\n",
                mode, resolved_count, REG_COUNT);
        for (int i = 0; i < num_hooks; i++) {
            fprintf(out, "[FAT-HOOK] %s (0x%08lx): %lu hits\n",
                    hooks[i].name, (unsigned long)hooks[i].address,
                    (unsigned long)hooks[i].hit_count);
        }
    }

    if (log_file) fclose(log_file);
    if (reg_buf) g_byte_array_free(reg_buf, TRUE);
    if (mem_buf) g_byte_array_free(mem_buf, TRUE);
    g_free(target_name);
    target_name = NULL;
}

/* ------------------------------------------------------------------ */
/* Hook CLI arg parsing: hook=0xADDRESS:name[:flags]                 */
/* ------------------------------------------------------------------ */

static void parse_hook(const char *arg)
{
    if (num_hooks >= MAX_HOOKS) {
        fprintf(stderr, "[FAT-HOOK] Max hooks (%d) reached, ignoring: %s\n",
                MAX_HOOKS, arg);
        return;
    }

    const char *first_colon = strchr(arg, ':');
    if (!first_colon) {
        fprintf(stderr, "[FAT-HOOK] Invalid hook (missing ':'): %s\n", arg);
        return;
    }

    char addr_str[32];
    size_t addr_len = first_colon - arg;
    if (addr_len >= sizeof(addr_str)) return;
    strncpy(addr_str, arg, addr_len);
    addr_str[addr_len] = '\0';

    hooks[num_hooks].address = strtoull(addr_str, NULL, 0);

    const char *name_start = first_colon + 1;
    const char *second_colon = strchr(name_start, ':');
    size_t name_len = second_colon ? (size_t)(second_colon - name_start) : strlen(name_start);
    if (name_len >= sizeof(hooks[num_hooks].name))
        name_len = sizeof(hooks[num_hooks].name) - 1;
    strncpy(hooks[num_hooks].name, name_start, name_len);
    hooks[num_hooks].name[name_len] = '\0';

    hooks[num_hooks].hit_count = 0;
    hooks[num_hooks].string_args_mask = 0;

    if (second_colon) {
        const char *flags = second_colon + 1;
        if (flags[0] == 'm') {
            /* Exact hex bitmask: m1=a0, m2=a1, m5=a0+a2, mf=all */
            hooks[num_hooks].string_args_mask =
                (uint8_t)strtoul(flags + 1, NULL, 16) & 0x0F;
        } else if (flags[0] == 's') {
            /* Legacy prefix shorthand: s1=a0, s2=a0+a1, s/s4=all */
            if (flags[1] == '\0' || flags[1] == '4')
                hooks[num_hooks].string_args_mask = 0x0F;
            else if (flags[1] >= '1' && flags[1] <= '3')
                hooks[num_hooks].string_args_mask = (1 << (flags[1] - '0')) - 1;
        }
    }

    fprintf(stderr, "[FAT-HOOK] Registered: %s at 0x%08lx (string_args=0x%02x)\n",
            hooks[num_hooks].name, (unsigned long)hooks[num_hooks].address,
            hooks[num_hooks].string_args_mask);
    num_hooks++;
}

/* ------------------------------------------------------------------ */
/* Plugin install                                                     */
/* ------------------------------------------------------------------ */

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                            const qemu_info_t *info,
                                            int argc, char **argv)
{
    target_name = g_strdup(info->target_name);

    fprintf(stderr, "[FAT-HOOK] FAT Firmware Hook Plugin v3 loaded\n");
    fprintf(stderr, "[FAT-HOOK] Target: %s (QEMU plugin API v%d)\n",
            target_name, QEMU_PLUGIN_VERSION);

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "hook=", 5) == 0) {
            parse_hook(argv[i] + 5);
        } else if (strncmp(argv[i], "log=", 4) == 0) {
            log_file = fopen(argv[i] + 4, "w");
            if (!log_file) {
                fprintf(stderr, "[FAT-HOOK] Failed to open log file: %s\n",
                        argv[i] + 4);
            }
        } else if (strcmp(argv[i], "json") == 0 ||
                   strcmp(argv[i], "format=json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "format=text") == 0) {
            json_output = false;
        } else if (strncmp(argv[i], "flush=", 6) == 0) {
            flush_interval = (unsigned int)strtoul(argv[i] + 6, NULL, 10);
        }
    }

    /* Auto-detect JSON from log filename */
    if (log_file && !json_output) {
        for (int i = 0; i < argc; i++) {
            if (strncmp(argv[i], "log=", 4) == 0) {
                const char *path = argv[i] + 4;
                size_t plen = strlen(path);
                if ((plen > 6 && strcmp(path + plen - 6, ".jsonl") == 0) ||
                    (plen > 5 && strcmp(path + plen - 5, ".json") == 0)) {
                    json_output = true;
                }
            }
        }
    }

    if (num_hooks == 0) {
        fprintf(stderr,
                "[FAT-HOOK] No hooks configured.\n"
                "  Usage: -plugin fat-hook.so,hook=0xADDR:name[:mX]\n");
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);

    return 0;
}
