#!/usr/bin/env python3
"""
angr-based Reaching Definitions taint analysis for firmware binaries.

Traces data flow from source functions (CGI_Find_Parameter, getenv) to
sink functions (system, popen, execl) using angr's ReachingDefinitions
analysis — NOT symbolic execution (which blows up on firmware).

Usage:
    python3 angr_taint.py /path/to/binary.cgi
"""

import angr
import sys
import json
import logging
import re
from collections import defaultdict

# Reduce angr noise
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)

# =============================================================================
# Taint models
#
# This script carries no catalog of its own. Every source, sink and blocker
# comes from the YAML profiles the caller materializes and passes with
# --profiles: FAT's core models, plus whatever profile the operator selected.
# There used to be a hardcoded multi-vendor union here, used whenever PyYAML
# was missing or the profile directory was absent — which meant a missing
# dependency silently applied several vendors' taint semantics to an
# unrelated binary. A missing profile source is now an error.
#
# The tables below are argument-position facts about specific functions, not a
# selection of which functions matter, so they stay.
# =============================================================================

# Functions where tainted data goes to an argument, not return value
# Format: function_name -> argument index containing tainted data (0-indexed)
TAINTED_ARG_SOURCES = {
    'read': 1,          # read(fd, buf, count) -- buf (arg 1) gets the data
    'recv': 1,          # recv(fd, buf, len, flags) -- buf gets the data
    'recvfrom': 1,      # recvfrom(fd, buf, len, flags, addr, addrlen) -- buf
    'fread': 0,         # fread(ptr, size, nmemb, stream) -- ptr gets the data
    'fgets': 0,         # fgets(str, num, stream) -- str gets the data
    'HAL_UART_Receive': 1,     # HAL_UART_Receive(handle, buf, size, timeout) -- buf
    'HAL_UART_Receive_IT': 1,  # same pattern
    'HAL_UART_Receive_DMA': 1,
    'HAL_SPI_Receive': 1,
}

# Blockers are not listed here. Like sources and sinks, they come from the
# profiles the caller materializes and are merged into BLOCKERS at load time.
# A stale copy of the list lived here until it was noticed that nothing read
# it, which had made the profiles' narrower set look like an oversight.


def profile_entry_names(profile):
    """Every name a profile contributes to the merged catalog.

    Mirrors `profile_entry_names` in profile.rs, so both engines agree on what
    counts as a redefinition.
    """
    for src in profile.get('sources', {}).get('primary', []):
        yield src['name']
    for src in profile.get('sources', {}).get('secondary', []):
        yield src['name']
    for sink in profile.get('sinks', []):
        yield sink['name']
    for blocker in profile.get('blockers', []):
        yield blocker['name']


def load_profiles(profile_dir, binary_imports, arch=None):
    """
    Load every taint profile in `profile_dir` and merge them.

    The caller decides what is in that directory: FAT's core models, plus an
    external profile if the operator selected one. This function does not
    choose. It used to load a profile whose 'detect' symbols appeared in the
    binary's imports, which let an observed symbol pull in a whole vendor's
    semantics without anyone asking for them.

    `binary_imports` and `arch` are retained for call compatibility and are
    deliberately unused in the selection decision.

    Returns merged (sources_primary, sources_secondary, sinks, blockers).
    """
    import os

    try:
        import yaml
    except ImportError:
        raise SystemExit(
            "PyYAML is required to load taint profiles. Install it with: pip install pyyaml"
        )

    sources_primary = set()
    sources_secondary = set()
    sinks = {}
    blockers = set()
    loaded_profiles = []
    owners = {}

    if not profile_dir or not os.path.isdir(profile_dir):
        raise SystemExit(f"taint profile directory not found: {profile_dir}")

    # Scan all YAML files in the profile directory
    for filename in sorted(os.listdir(profile_dir)):
        if not filename.endswith('.yaml') and not filename.endswith('.yml'):
            continue

        filepath = os.path.join(profile_dir, filename)
        try:
            with open(filepath) as f:
                profile = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Failed to load {filename}: {e}")
            continue

        if not profile:
            continue

        # Every profile placed here was chosen by the caller, so every profile
        # here is loaded. A 'detect' or 'detect_arch' key is ignored.
        profile_name = profile.get('name', filename)
        loaded_profiles.append(profile_name)

        # Core is materialized as core.yaml and sorts before external.yaml, so
        # by the time a later profile is read, every name already seen belongs
        # to a profile with priority over it. A restatement is refused rather
        # than resolved: the Rust catalog refuses it too, and a silent
        # resolution here is what let the two engines disagree about which
        # definition of a sink's argument position was in force.
        for name in profile_entry_names(profile):
            if name in owners and owners[name] != filename:
                raise SystemExit(
                    f"taint profile {profile_name} ({filename}) redefines "
                    f"{name}, already defined by {owners[name]}. Core models are "
                    f"fixed by specification and cannot be overridden; remove "
                    f"the entry or rename it."
                )
            owners[name] = filename

        # Merge sources
        for src in profile.get('sources', {}).get('primary', []):
            sources_primary.add(src['name'])
        for src in profile.get('sources', {}).get('secondary', []):
            sources_secondary.add(src['name'])

        # Merge sinks
        for sink in profile.get('sinks', []):
            sinks[sink['name']] = sink.get('arg', 0)

        # Merge blockers
        for blocker in profile.get('blockers', []):
            blockers.add(blocker['name'])

    print(f"[*] Loaded profiles: {', '.join(loaded_profiles)}")
    return sources_primary, sources_secondary, sinks, blockers


def identify_functions_by_strings(proj, cfg, raw, base):
    """
    Identify function roles by embedded string references.

    Bare-metal firmware has no symbol table, but debug/error strings reveal
    what a function does. For example:
      - A function referencing "EEPROM Write" is likely an EEPROM write handler (sink)
      - A function referencing "SerialCom rx" is likely a serial receive handler (source)
      - A function referencing "tcp" or "udp" strings from LwIP is network-related

    Returns: {func_addr: (inferred_name, 'source'|'sink')}
    """
    import struct

    # Map: string pattern → (inferred function name, role)
    string_patterns = {
        # Sources (network/serial input)
        b'SerialCom rx':      ('serial_rx_handler', 'source'),
        b'Uart ORE':          ('uart_rx_handler', 'source'),
        b'ethernet_input':    ('ethernet_input', 'source'),
        b'tcp_recv':          ('lwip_tcp_recv', 'source'),
        b'udp_recv':          ('lwip_udp_recv', 'source'),
        b'TFTP':              ('tftp_handler', 'source'),
        b'tftp':              ('tftp_handler', 'source'),

        # Sinks (writes, transmits, persistent storage)
        b'EEPROM Write':      ('eeprom_write', 'sink'),
        b'EEPROM Read':       ('eeprom_read', 'source'),  # could be source or sink
        b'SerialCom tx':      ('serial_tx_handler', 'sink'),
        b'UART ERROR DMA':    ('uart_dma_handler', 'sink'),
    }

    results = {}

    for pattern, (name, role) in string_patterns.items():
        offset = raw.find(pattern)
        if offset < 0:
            continue

        string_addr = base + offset

        # Method 1: Use angr's cross-reference database (handles PC-relative loads)
        xrefs = list(cfg.kb.xrefs.get_xrefs_by_dst(string_addr))
        for xref in xrefs:
            for faddr, func in cfg.functions.items():
                if faddr <= xref.ins_addr < faddr + func.size:
                    if faddr not in results:
                        results[faddr] = (name, role)
                        print(f"    [xref] '{pattern.decode()}' → {name} ({role}) at 0x{faddr:08x}")
                    break

        # Method 2: Search for address as literal in code (literal pools, data tables)
        addr_bytes_le = struct.pack("<I", string_addr)
        code_size = len(raw)
        pos = 0
        while pos < code_size:
            pos = raw.find(addr_bytes_le, pos)
            if pos < 0:
                break
            ref_addr = base + pos
            for faddr, func in cfg.functions.items():
                if faddr <= ref_addr < faddr + func.size:
                    if faddr not in results:
                        results[faddr] = (name, role)
                        print(f"    [literal] '{pattern.decode()}' → {name} ({role}) at 0x{faddr:08x}")
                    break
            pos += 1

        # Method 3: For Thumb-2, check if any function's address range contains
        # the string address in a literal pool (aligned 4-byte region after function code).
        # Literal pools are typically within ±4KB of the referencing instruction.
        if not any(faddr in results for faddr, _ in cfg.functions.items()):
            # Check ±4KB around the string for function boundaries
            search_lo = max(0, string_addr - base - 4096)
            search_hi = min(code_size, string_addr - base + 4096)
            for faddr, func in cfg.functions.items():
                func_lo = faddr - base
                func_hi = func_lo + func.size
                if func_lo <= search_lo < func_hi or func_lo <= search_hi < func_hi:
                    if faddr not in results:
                        results[faddr] = (name, role)
                        print(f"    [proximity] '{pattern.decode()}' → {name} ({role}) at 0x{faddr:08x}")
                    break

    return results


# =============================================================================
# Gap 1: Precise Source-to-Sink Data Flow via Reaching Definitions
# =============================================================================

def get_arch_return_reg(proj):
    """Get the return value register offset for this architecture."""
    arch = proj.arch
    if arch.name in ('MIPS32', 'MIPS64'):
        return arch.registers['v0'][0]  # register offset
    elif arch.name in ('ARMEL', 'ARMHF', 'AARCH64'):
        return arch.registers['r0'][0]
    elif arch.name in ('AMD64',):
        return arch.registers['rax'][0]
    elif arch.name in ('X86',):
        return arch.registers['eax'][0]
    else:
        return arch.registers['r0'][0]  # fallback


def get_arch_arg_reg(proj, arg_index):
    """Get the register offset for function argument N."""
    arch = proj.arch
    if arch.name in ('MIPS32', 'MIPS64'):
        arg_regs = ['a0', 'a1', 'a2', 'a3']
    elif arch.name in ('ARMEL', 'ARMHF'):
        arg_regs = ['r0', 'r1', 'r2', 'r3']
    elif arch.name in ('AARCH64',):
        arg_regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
    elif arch.name in ('AMD64',):
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    elif arch.name in ('X86',):
        return None  # x86 uses stack, not registers
    else:
        arg_regs = ['r0', 'r1', 'r2', 'r3']

    if arg_index < len(arg_regs):
        return arch.registers[arg_regs[arg_index]][0]
    return None


def get_arch_arg_reg_name(proj, arg_index):
    """Get the register NAME for function argument N (for symbolic state access)."""
    arch = proj.arch
    if arch.name in ('MIPS32', 'MIPS64'):
        arg_regs = ['a0', 'a1', 'a2', 'a3']
    elif arch.name in ('ARMEL', 'ARMHF'):
        arg_regs = ['r0', 'r1', 'r2', 'r3']
    elif arch.name in ('AARCH64',):
        arg_regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
    elif arch.name in ('AMD64',):
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    elif arch.name in ('X86',):
        return None
    else:
        arg_regs = ['r0', 'r1', 'r2', 'r3']

    if arg_index < len(arg_regs):
        return arg_regs[arg_index]
    return None


def trace_source_to_sink(proj, rd, func, src_call_addr, sink_call_addr, sink_arg_index):
    """
    Check if the return value from the source call site reaches the
    sink call site's argument register via Reaching Definitions.

    Returns: (confirmed: bool, trace_steps: list[dict])
    """
    ret_reg_offset = get_arch_return_reg(proj)
    arg_reg_offset = get_arch_arg_reg(proj, sink_arg_index)

    if arg_reg_offset is None:
        # x86 stack-based calling — fall back to co-occurrence
        return False, []

    # Get all definitions at the source call site
    # The return value is defined AT the call instruction (after it executes)
    source_defs = set()
    try:
        # Look for definitions of the return register at/after the source call
        for d in rd.all_definitions:
            if hasattr(d.atom, 'reg_offset') and d.atom.reg_offset == ret_reg_offset:
                if hasattr(d, 'codeloc') and d.codeloc is not None:
                    if d.codeloc.ins_addr is not None and d.codeloc.ins_addr == src_call_addr:
                        source_defs.add(d)
    except Exception:
        pass

    if not source_defs:
        # Try broader matching: any definition of ret_reg within a small window after source
        try:
            for d in rd.all_definitions:
                if hasattr(d.atom, 'reg_offset') and d.atom.reg_offset == ret_reg_offset:
                    if hasattr(d, 'codeloc') and d.codeloc is not None:
                        if d.codeloc.ins_addr is not None:
                            # Within 16 bytes after the source call (next few instructions)
                            if 0 <= d.codeloc.ins_addr - src_call_addr <= 16:
                                source_defs.add(d)
        except Exception:
            pass

    if not source_defs:
        return False, []

    # Now check what definitions reach the sink's argument register
    # Look for uses of the argument register at the sink call site
    sink_reaching = set()
    try:
        for d in rd.all_definitions:
            if hasattr(d.atom, 'reg_offset') and d.atom.reg_offset == arg_reg_offset:
                if hasattr(d, 'codeloc') and d.codeloc is not None:
                    if d.codeloc.ins_addr is not None:
                        # Definition of arg register near/at the sink call
                        if 0 <= sink_call_addr - d.codeloc.ins_addr <= 32:
                            sink_reaching.add(d)
    except Exception:
        pass

    # Check if any source definition reaches (or IS used by) any sink-argument definition
    # Walk the use-def chain: does any definition in sink_reaching trace back to source_defs?
    confirmed = False
    trace_steps = []

    # Direct check: same definition object
    if source_defs & sink_reaching:
        confirmed = True

    # Indirect check via uses: walk backwards from sink definitions
    if not confirmed and hasattr(rd, 'all_uses'):
        visited = set()
        worklist = list(sink_reaching)
        depth = 0
        max_depth = 20  # limit chain depth

        while worklist and depth < max_depth:
            depth += 1
            next_worklist = []
            for d in worklist:
                if id(d) in visited:
                    continue
                visited.add(id(d))

                if d in source_defs:
                    confirmed = True
                    break

                # Find what definitions THIS definition depends on
                # (walk backwards through the use-def chain)
                try:
                    for use in rd.all_uses.get_uses(d):
                        for upstream_def in rd.all_definitions:
                            if hasattr(upstream_def, 'codeloc') and upstream_def.codeloc == use.codeloc:
                                next_worklist.append(upstream_def)
                except Exception:
                    pass

            if confirmed:
                break
            worklist = next_worklist

    if confirmed:
        trace_steps = [
            {'addr': hex(src_call_addr), 'action': 'source return value', 'reg': f'reg_offset_{ret_reg_offset}'},
            {'addr': hex(sink_call_addr), 'action': 'reaches sink argument', 'reg': f'reg_offset_{arg_reg_offset}'},
        ]

    return confirmed, trace_steps


def trace_source_arg_to_sink(proj, rd, func, src_call_addr, sink_call_addr, sink_arg_idx, source_arg_idx):
    """
    Trace a source's argument (e.g., read's buffer pointer) to a sink's argument.

    For functions like read(fd, buf, count), the tainted data lands in the
    buffer pointed to by arg 1, NOT in the return value. This function tracks
    the buffer pointer definition at the source call site and checks if it
    (or a derived value) reaches the sink's argument register.
    """
    arg_reg_offset = get_arch_arg_reg(proj, source_arg_idx)
    sink_reg_offset = get_arch_arg_reg(proj, sink_arg_idx)

    if arg_reg_offset is None or sink_reg_offset is None:
        return False, []

    # Find definitions of the source's argument register near the call site
    source_arg_defs = set()
    for d in rd.all_definitions:
        if hasattr(d.atom, 'reg_offset') and d.atom.reg_offset == arg_reg_offset:
            if hasattr(d, 'codeloc') and d.codeloc is not None:
                if d.codeloc.ins_addr is not None:
                    if abs(d.codeloc.ins_addr - src_call_addr) <= 16:
                        source_arg_defs.add(d)

    if not source_arg_defs:
        return False, []

    # Check if any of these definitions (or their derived defs) reach the sink's arg
    sink_arg_defs = set()
    for d in rd.all_definitions:
        if hasattr(d.atom, 'reg_offset') and d.atom.reg_offset == sink_reg_offset:
            if hasattr(d, 'codeloc') and d.codeloc is not None:
                if d.codeloc.ins_addr is not None:
                    if abs(sink_call_addr - d.codeloc.ins_addr) <= 32:
                        sink_arg_defs.add(d)

    # Direct overlap check
    if source_arg_defs & sink_arg_defs:
        return True, [
            {'addr': hex(src_call_addr), 'action': f'source arg {source_arg_idx} (buffer pointer)', 'reg': f'arg{source_arg_idx}'},
            {'addr': hex(sink_call_addr), 'action': 'reaches sink argument', 'reg': f'arg{sink_arg_idx}'},
        ]

    # Walk use-def chain backwards from sink definitions
    visited = set()
    worklist = list(sink_arg_defs)
    for _ in range(20):
        if not worklist:
            break
        next_wl = []
        for d in worklist:
            if id(d) in visited:
                continue
            visited.add(id(d))
            if d in source_arg_defs:
                return True, [
                    {'addr': hex(src_call_addr), 'action': f'source arg {source_arg_idx} (buffer)', 'reg': f'arg{source_arg_idx}'},
                    {'addr': hex(sink_call_addr), 'action': 'reaches sink argument', 'reg': f'arg{sink_arg_idx}'},
                ]
            try:
                for use in rd.all_uses.get_uses(d):
                    for ud in rd.all_definitions:
                        if hasattr(ud, 'codeloc') and ud.codeloc == use.codeloc:
                            next_wl.append(ud)
            except Exception:
                pass
        worklist = next_wl

    return False, []


# =============================================================================
# Gap 1b: Targeted Symbolic Execution for Shell Metacharacter Survivability
# =============================================================================

# Command execution sinks where metacharacter injection matters
COMMAND_EXEC_SINKS = {'system', 'popen', 'execl', 'execlp', 'execv', 'execve', 'execvp'}

SINK_DISCOVERY_CONFIDENCE_ORDER = {
    'weak': 1,
    'probable': 2,
    'strong': 3,
    'confirmed': 4,
}


def load_sink_candidate_sinks(path):
    """Load probable+ address-backed candidate sinks from a SinkDiscoveryReport."""
    if not path:
        return {}, set()

    with open(path) as f:
        report = json.load(f)

    sinks = {}
    command_exec_names = set()
    for candidate in report.get('candidates', []):
        confidence = candidate.get('confidence', '')
        if SINK_DISCOVERY_CONFIDENCE_ORDER.get(confidence, 0) < SINK_DISCOVERY_CONFIDENCE_ORDER['probable']:
            continue

        raw_addr = candidate.get('address')
        if raw_addr is None:
            continue
        if isinstance(raw_addr, str):
            addr = int(raw_addr, 0)
        else:
            addr = int(raw_addr)

        family = candidate.get('family', '')
        family_key = candidate.get('family_key', family)
        sink_name = candidate.get('symbolic_name') or f"sink_candidate_{family_key.replace('-', '_')}_{addr:x}"
        dangerous_arg = 0

        sinks[addr] = {
            'name': sink_name,
            'arg': dangerous_arg,
            'family': family,
            'family_key': family_key,
        }
        if family == 'command-exec' or family_key == 'command-exec':
            command_exec_names.add(sink_name)

    return sinks, command_exec_names


def check_metachar_survivability(proj, cfg, func, src_call_addr, sink_call_addr, sink_arg_idx):
    """
    Use targeted symbolic execution to check if shell metacharacters
    can survive from source to sink within a single function.

    This is the difference between "data flows from getenv to system"
    and "attacker can inject shell commands." We set the source's return
    value to a fully symbolic buffer, explore forward to the sink, and
    then check which metacharacters the solver can satisfy in the sink
    argument.

    Only called for confirmed-rd flows to command execution sinks.
    Scoped to a single function (not full-program) for feasibility.

    Returns: {
        'injectable': bool,
        'surviving_chars': list of str,  # e.g., [';', '|', '$']
        'constraints': str,  # human-readable constraint summary
        'method': 'symbolic' or 'timeout' or 'error'
    }
    """
    import claripy

    source_func_addr = None
    try:
        # Create a symbolic variable for the attacker-controlled input
        # 256 bytes is enough for most HTTP parameters / env vars
        sym_input = claripy.BVS("attacker_input", 256 * 8)

        # Create a state at the function entry with permissive options
        state = proj.factory.call_state(func.addr, add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        })

        # Resolve the source function address from the call site.
        # Walk the function's blocks to find which callee is invoked at src_call_addr.
        source_func_addr = _resolve_callee_at_site(proj, cfg, func, src_call_addr)

        if source_func_addr is None:
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': 'could not resolve source function at call site',
                'method': 'error',
            }

        # Hook the source function to return a pointer to our symbolic buffer.
        # This replaces the real function with one that:
        #   1. Maps a memory region for the symbolic buffer
        #   2. Stores the symbolic bitvector there
        #   3. Returns the pointer
        buf_addr = 0x7fff0000  # arbitrary address in unmapped space

        class SourceHook(angr.SimProcedure):
            def run(self, *args, **kwargs):
                self.state.memory.store(buf_addr, sym_input)
                return buf_addr

        proj.hook(source_func_addr, SourceHook())

        # Find the sink call site's block address for the explore() target
        sink_block_addr = _find_block_containing(func, sink_call_addr)
        if sink_block_addr is None:
            proj.unhook(source_func_addr)
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': 'could not find sink block in function',
                'method': 'error',
            }

        # Run simulation: explore from function entry to the sink call site
        simgr = proj.factory.simulation_manager(state)

        try:
            simgr.explore(
                find=sink_call_addr,
                num_find=1,
                timeout=30,  # 30 seconds max per function
            )
        except Exception as e:
            proj.unhook(source_func_addr)
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': f'exploration failed: {e}',
                'method': 'error',
            }

        if not simgr.found:
            proj.unhook(source_func_addr)
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': 'sink not reachable symbolically (timeout or infeasible path)',
                'method': 'timeout',
            }

        found_state = simgr.found[0]

        # Read the sink's argument register to get the pointer to the command string
        arg_reg_name = get_arch_arg_reg_name(proj, sink_arg_idx)
        if arg_reg_name is None:
            proj.unhook(source_func_addr)
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': 'could not determine sink arg register (x86 stack-based?)',
                'method': 'error',
            }

        sink_arg_val = getattr(found_state.regs, arg_reg_name)

        # Resolve the pointer and read the string bytes from memory
        try:
            str_ptr = found_state.solver.eval(sink_arg_val)
            str_bytes = found_state.memory.load(str_ptr, 256)
        except Exception:
            proj.unhook(source_func_addr)
            return {
                'injectable': False,
                'surviving_chars': [],
                'constraints': 'could not dereference sink argument pointer',
                'method': 'error',
            }

        # Check which shell metacharacters are satisfiable at any byte position
        # in the string that reaches system()/popen().
        metachar_map = {
            ';':  0x3B,  # command separator
            '|':  0x7C,  # pipe
            '`':  0x60,  # backtick (command substitution)
            '$':  0x24,  # dollar (variable expansion / $(...))
            '&':  0x26,  # background / command separator
            '\n': 0x0A,  # newline (command separator in shell)
        }

        surviving = []
        for char, byte_val in metachar_map.items():
            # Check if ANY byte position in the string can hold this metacharacter
            char_found = False
            for i in range(min(256, str_bytes.length // 8)):
                byte_i = str_bytes.get_byte(i)
                try:
                    if found_state.solver.satisfiable(extra_constraints=[byte_i == byte_val]):
                        char_found = True
                        break
                except Exception:
                    pass
            if char_found:
                surviving.append(char)

        # Clean up: always unhook to avoid polluting the project
        proj.unhook(source_func_addr)

        injectable = len(surviving) > 0
        if injectable:
            constraints_str = f"injectable: {', '.join(repr(c) for c in surviving)} survive to sink"
        else:
            constraints_str = 'not injectable: no shell metacharacters survive constraints'

        return {
            'injectable': injectable,
            'surviving_chars': surviving,
            'constraints': constraints_str,
            'method': 'symbolic',
        }

    except Exception as e:
        # Ensure hook cleanup on any unexpected error
        if source_func_addr is not None:
            try:
                proj.unhook(source_func_addr)
            except Exception:
                pass
        return {
            'injectable': False,
            'surviving_chars': [],
            'constraints': f'symbolic execution error: {e}',
            'method': 'error',
        }


def _resolve_callee_at_site(proj, cfg, func, call_site_addr):
    """
    Given a call site address within a function, resolve the address of the
    callee (the function being called). Uses both disassembly operand matching
    and CFG edge analysis.
    """
    for block in func.blocks:
        try:
            for insn in block.capstone.insns:
                if insn.address == call_site_addr:
                    # Check direct operand (immediate target)
                    for op in insn.operands:
                        if hasattr(op, 'imm') and op.imm in cfg.functions:
                            return op.imm
                    # Fallback: check CFG edges from this block
                    node = cfg.model.get_any_node(block.addr)
                    if node:
                        for succ in cfg.graph.successors(node):
                            if succ.addr in cfg.functions and succ.addr != block.addr:
                                return succ.addr
        except Exception:
            pass
    return None


def _find_block_containing(func, addr):
    """Find the block address within a function that contains the given instruction address."""
    for block in func.blocks:
        try:
            for insn in block.capstone.insns:
                if insn.address == addr:
                    return block.addr
        except Exception:
            pass
    return None


# =============================================================================
# Gap 2a: Taint Blocker Enforcement
# =============================================================================

def check_blockers_on_path(cfg, func, src_addr, sink_addr, blockers):
    """
    Check if any taint-blocking function (crypto, integer conversion) is called
    between the source and sink addresses within the function.

    Returns: blocker function name if found, None otherwise.
    """
    if not blockers:
        return None

    # Determine address range between source and sink
    lo = min(src_addr, sink_addr)
    hi = max(src_addr, sink_addr)

    # Get all call sites in this function
    try:
        for block in func.blocks:
            for insn in block.capstone.insns:
                # Check if this instruction is a call
                if insn.mnemonic in ('call', 'jal', 'jalr', 'bl', 'blx', 'blr'):
                    insn_addr = insn.address
                    # Is it between source and sink?
                    if lo < insn_addr < hi:
                        # What function does it call?
                        node = cfg.model.get_any_node(block.addr)
                        if node:
                            for succ in cfg.graph.successors(node):
                                if succ.addr in cfg.functions:
                                    target = cfg.functions[succ.addr]
                                    if target.name in blockers:
                                        return target.name
    except Exception:
        pass

    return None


# =============================================================================
# Gap 3c: Call-Chain Reachability from Entry Point
# =============================================================================

def check_entry_reachability(cfg, func_addr):
    """
    Check if func_addr is reachable from the binary's entry point(s) via the call graph.
    Returns: (reachable: bool, path_depth: int or None)
    """
    try:
        import networkx as nx
    except ImportError:
        return True, None  # assume reachable if networkx not available

    callgraph = cfg.functions.callgraph

    # Find entry points: the project entry + functions with no callers
    entry_funcs = set()

    # The project entry point is the most reliable
    try:
        entry_funcs.add(cfg.project.entry)
    except Exception:
        pass

    # Also add functions with no predecessors in the call graph
    for addr in callgraph.nodes():
        try:
            if callgraph.in_degree(addr) == 0:
                entry_funcs.add(addr)
        except Exception:
            pass

    if not entry_funcs:
        return True, None  # can't determine, assume reachable

    for entry in entry_funcs:
        if entry == func_addr:
            return True, 0
        try:
            if nx.has_path(callgraph, entry, func_addr):
                path = nx.shortest_path(callgraph, entry, func_addr)
                return True, len(path) - 1
        except (nx.NetworkXError, nx.NodeNotFound):
            continue

    return False, None


# =============================================================================
# Gap 3a: String-to-Handler Mapping (CGI endpoint names)
# =============================================================================

def build_handler_map(proj, cfg):
    """
    Find CGI dispatch tables: arrays of (string_ptr, function_ptr) pairs.
    Also find direct string references to .cgi names near function calls.

    Returns: {func_addr: "endpoint_name.cgi"}
    """
    handler_map = {}

    # Search raw binary for .cgi strings and find who references them
    try:
        with open(proj.filename, 'rb') as f:
            binary_bytes = f.read()
    except Exception:
        return handler_map

    base_addr = proj.loader.main_object.min_addr

    # Find all .cgi string positions
    for match in re.finditer(rb'([A-Za-z0-9_/.-]+\.cgi)\x00', binary_bytes):
        cgi_name = match.group(1).decode('ascii', errors='ignore')
        string_addr = base_addr + match.start()

        # Find xrefs to this string address
        try:
            xrefs = list(cfg.kb.xrefs.get_xrefs_by_dst(string_addr))
            for xref in xrefs:
                # Find the function containing this xref
                try:
                    func = cfg.kb.functions.floor_func(xref.block_addr)
                    if func:
                        handler_map[func.addr] = cgi_name
                except Exception:
                    # floor_func may not exist in older angr — walk manually
                    for faddr, f in cfg.functions.items():
                        if faddr <= xref.ins_addr < faddr + f.size:
                            handler_map[faddr] = cgi_name
                            break
        except Exception:
            pass

    return handler_map


def extract_source_parameter(proj, cfg, call_site_addr):
    """
    At a source call site, resolve the first string argument to a concrete value.
    e.g., getenv("QUERY_STRING") -> "QUERY_STRING"
         acosNvramConfig_get("http_passwd") -> "http_passwd"
    """
    try:
        node = cfg.model.get_any_node(call_site_addr, anyaddr=True)
        if node is None:
            return None

        block = proj.factory.block(node.addr)
        # Look for string references in the block's instructions leading up to the call
        for insn in block.capstone.insns:
            if insn.address > call_site_addr:
                break
            # Check for references to data section (string pointers)
            for op in insn.operands:
                if hasattr(op, 'imm') and op.imm > 0:
                    try:
                        # Try to read a string from this address
                        data = proj.loader.memory.load(op.imm, 64)
                        null_idx = data.index(0) if 0 in data else len(data)
                        s = data[:null_idx].decode('ascii', errors='ignore')
                        if s and len(s) >= 2 and s.isascii() and all(c.isprintable() or c == '_' for c in s):
                            return s
                    except Exception:
                        pass
    except Exception:
        pass
    return None


def generate_poc_suggestion(finding):
    """Generate a curl-like PoC suggestion for a confirmed finding."""
    endpoint = finding.get('endpoint')
    parameter = finding.get('parameter')
    source = finding.get('source', '')
    sink = finding.get('sink', '')
    method = finding.get('method', '')

    if method != 'confirmed-rd':
        return None

    if not endpoint:
        return None

    poc = {}

    if sink in ('system', 'popen', 'execl', 'execv', 'execve'):
        # Command injection PoC
        if parameter and parameter in ('QUERY_STRING', 'REQUEST_URI'):
            poc['curl'] = f'curl "http://TARGET/{endpoint}?$(id)"'
        elif parameter:
            poc['curl'] = f'curl "http://TARGET/{endpoint}?{parameter}=$(id)"'
        else:
            poc['curl'] = f'curl "http://TARGET/{endpoint}?cmd=$(id)"'
        poc['type'] = 'command-injection'
        poc['marker'] = f'curl "http://TARGET/{endpoint}?{parameter or "cmd"}=$(touch+/tmp/fat_confirmed)"'

    elif sink in ('sprintf', 'strcpy', 'strcat'):
        # Buffer overflow PoC
        poc['curl'] = f'curl "http://TARGET/{endpoint}?{parameter or "input"}={"A" * 512}"'
        poc['type'] = 'buffer-overflow'

    if poc:
        poc['note'] = 'CAUTION: test only on authorized targets. This is a suggested PoC, not a confirmed exploit.'
        return poc

    return None


# =============================================================================
# Main Analysis
# =============================================================================

def analyze_binary(binary_path, arch=None, base_addr=None, **kwargs):
    """Run taint analysis on a firmware binary (ELF or raw blob)."""
    print(f"[*] Loading {binary_path}")

    if arch and base_addr:
        # Raw blob (flat firmware, e.g., STM32 flash dump)
        base = int(base_addr, 0)

        # Map CLI arch names to angr arch names
        arch_map = {
            "cortex-m": "ARMHF",
            "arm": "ARMEL",
            "armhf": "ARMHF",
            "mipsel": "MIPSEL",
            "mips": "MIPS32",
            "x86": "X86",
            "x86_64": "AMD64",
        }
        angr_arch = arch_map.get(arch.lower(), arch)

        # For Cortex-M, find the entry point from the IVT
        import struct
        with open(binary_path, "rb") as f:
            raw = f.read()
        reset_vector = struct.unpack_from("<I", raw, 4)[0]
        entry = reset_vector & ~1  # Clear Thumb bit

        proj = angr.Project(
            binary_path,
            main_opts={
                "backend": "blob",
                "arch": angr_arch,
                "base_addr": base,
                "entry_point": entry,
            },
            auto_load_libs=False,
        )

        # For bare-metal, limit CFG to code region (skip 0xFF padding)
        last_nonff = max(i for i in range(len(raw)) if raw[i] != 0xFF)
        code_end = base + last_nonff + 1
        cfg = proj.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
            regions=[(base, code_end)],
        )
    else:
        # Standard ELF binary
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

    is_baremetal = arch is not None
    print(f"[*] CFG built: {len(cfg.functions)} functions")
    print(f"[*] Mode: {'bare-metal' if is_baremetal else 'Linux ELF'}")

    # Collect binary's import symbols for profile auto-detection
    binary_imports = set()
    for addr, func in cfg.functions.items():
        if func.name and not func.name.startswith('sub_'):
            binary_imports.add(func.name)

    # Load taint profiles. Every profile the caller materialized is loaded;
    # nothing is selected from the binary's imports.
    profile_dir = kwargs.get('profile_dir')
    result = load_profiles(profile_dir, binary_imports, arch)
    SOURCES_PRIMARY, SOURCES_SECONDARY, SINKS = result[0], result[1], result[2]
    BLOCKERS = result[3] if len(result) > 3 else set()
    sink_candidate_path = kwargs.get('sink_candidates')
    supplemental_sinks, supplemental_command_exec_sinks = load_sink_candidate_sinks(sink_candidate_path)
    command_exec_sinks = set(COMMAND_EXEC_SINKS) | supplemental_command_exec_sinks

    # Gap 3a: Build CGI handler-to-endpoint mapping
    handler_map = build_handler_map(proj, cfg)
    if handler_map:
        print(f"[*] CGI handler mapping: {len(handler_map)} endpoints resolved")
        for addr, name in sorted(handler_map.items()):
            func_name = cfg.functions[addr].name if addr in cfg.functions else hex(addr)
            print(f"    {name} -> {func_name}")

    # Find source and sink functions in the binary.
    # For ELFs: match by symbol name (angr resolves symbols from .dynsym/.symtab).
    # For raw blobs: symbols are absent, so also match by string references.
    sources_found = {}
    sinks_found = {}
    sink_aliases = {}
    all_sources = SOURCES_PRIMARY | SOURCES_SECONDARY

    for addr, func in cfg.functions.items():
        name = func.name
        if name in all_sources:
            source_class = 'primary' if name in SOURCES_PRIMARY else 'secondary'
            sources_found[addr] = (name, source_class)
        if name in SINKS:
            sinks_found[addr] = (name, SINKS[name])

    for candidate_addr, sink in supplemental_sinks.items():
        resolved_addr = resolve_candidate_function_addr(cfg, candidate_addr)
        if resolved_addr is None:
            print(f"    [sink-candidate] skipping {sink['name']} @ 0x{candidate_addr:x}: no containing CFG function")
            continue
        SINKS[sink['name']] = sink['arg']
        sinks_found[resolved_addr] = (sink['name'], sink['arg'])
        sink_aliases[resolved_addr] = sink['name']
        print(
            f"    [sink-candidate] {sink['name']} @ 0x{resolved_addr:x} "
            f"(reported 0x{candidate_addr:x}, family: {sink['family_key']})"
        )

    # For bare-metal blobs: also identify functions by string references.
    # Bare-metal firmware embeds error/debug strings that reveal function purpose.
    if is_baremetal and (not sources_found or not sinks_found):
        print("[*] No symbol-based matches — scanning strings for function identification")
        string_hints = identify_functions_by_strings(proj, cfg, raw, base)
        for addr, (inferred_name, role) in string_hints.items():
            if role == 'source' and addr not in sources_found:
                sources_found[addr] = (inferred_name, 'primary')
            elif role == 'sink' and addr not in sinks_found:
                sinks_found[addr] = (inferred_name, 0)

    print(f"[*] Sources found: {len(sources_found)}")
    for addr, (name, cls) in sorted(sources_found.items()):
        print(f"    {name} @ 0x{addr:x} ({cls})")

    print(f"[*] Sinks found: {len(sinks_found)}")
    for addr, (name, arg_idx) in sorted(sinks_found.items()):
        print(f"    {name} @ 0x{addr:x} (dangerous arg: {arg_idx})")

    if not sources_found or not sinks_found:
        print("[!] Missing sources or sinks — cannot trace")
        return []

    # Find all callers of sources and sinks — with call SITE addresses
    source_callers = find_callers(cfg, set(sources_found.keys()))
    sink_callers = find_callers(cfg, set(sinks_found.keys()), sink_aliases)

    print(f"[*] Functions calling sources: {len(source_callers)}")
    print(f"[*] Functions calling sinks: {len(sink_callers)}")

    # Find functions that call BOTH a source and a sink (co-occurrence)
    co_occurrence = set(source_callers.keys()) & set(sink_callers.keys())
    print(f"[*] Co-occurrence (source + sink in same function): {len(co_occurrence)}")

    findings = []

    for func_addr in co_occurrence:
        func = cfg.functions[func_addr]
        func_sources = source_callers[func_addr]
        func_sinks = sink_callers[func_addr]

        print(f"\n[*] Analyzing {func.name} @ 0x{func_addr:x}")
        print(f"    Sources: {[s[1] for s in func_sources]}")
        print(f"    Sinks: {[s[1] for s in func_sinks]}")

        # Gap 3c: Check reachability from entry point
        reachable, depth = check_entry_reachability(cfg, func_addr)
        if not reachable:
            print(f"    [skip] Not reachable from entry point — internal utility")
            continue

        # Try Reaching Definitions analysis on this function
        try:
            rd = proj.analyses.ReachingDefinitions(
                subject=func,
                func_graph=func.graph,
                observe_all=True,
            )

            for call_site_addr, src_name in func_sources:
                for sink_site_addr, sink_name in func_sinks:
                    src_class = 'primary' if src_name in SOURCES_PRIMARY else 'secondary'
                    sink_arg = SINKS.get(sink_name, 0)

                    # Gap 2a: Check for taint blockers on the path
                    blocker_on_path = check_blockers_on_path(cfg, func, call_site_addr, sink_site_addr, BLOCKERS)

                    if blocker_on_path:
                        print(f"    [blocked] {src_name} -> {sink_name}: blocked by {blocker_on_path}")
                        continue

                    # Gap 1: Precise data flow trace via RD
                    # Upgrade 1: For sources where tainted data is in an argument
                    # (e.g., read's buffer), trace the argument register instead
                    if src_name in TAINTED_ARG_SOURCES:
                        tainted_arg_idx = TAINTED_ARG_SOURCES[src_name]
                        confirmed, trace_steps = trace_source_arg_to_sink(
                            proj, rd, func, call_site_addr, sink_site_addr, sink_arg, tainted_arg_idx
                        )
                    else:
                        confirmed, trace_steps = trace_source_to_sink(
                            proj, rd, func, call_site_addr, sink_site_addr, sink_arg
                        )

                    if confirmed:
                        method = 'confirmed-rd'
                        confidence = 'high'
                        if src_name in TAINTED_ARG_SOURCES:
                            note = f'Confirmed: {src_name} buffer arg reaches {sink_name} argument via RD trace'
                        else:
                            note = f'Confirmed: {src_name} return value reaches {sink_name} argument via RD trace'
                    else:
                        method = 'co-occurrence-only'
                        confidence = 'low'
                        note = f'{src_name} and {sink_name} co-occur but data flow not confirmed by RD'

                    finding = {
                        'function': func.name,
                        'function_addr': hex(func_addr),
                        'source': src_name,
                        'source_addr': hex(call_site_addr),
                        'source_class': src_class,
                        'sink': sink_name,
                        'sink_addr': hex(sink_site_addr),
                        'method': method,
                        'confidence': confidence,
                        'note': note,
                    }

                    if trace_steps:
                        finding['trace'] = trace_steps

                    # Gap 3c: Add reachability depth
                    finding['reachable_depth'] = depth

                    # Gap 3a: Add CGI endpoint name if known
                    endpoint = handler_map.get(func_addr, None)
                    if endpoint:
                        finding['endpoint'] = endpoint

                    # Upgrade 2: Extract source parameter name
                    param_name = extract_source_parameter(proj, cfg, call_site_addr)
                    if param_name:
                        finding['parameter'] = param_name

                    # Upgrade 3: Generate PoC suggestion for confirmed flows
                    poc = generate_poc_suggestion(finding)
                    if poc:
                        finding['poc_suggestion'] = poc

                    # Gap 1b: Targeted symbolic execution for command injection sinks
                    # Only run on confirmed-rd flows to command execution functions.
                    # This upgrades "data flows" to "attacker can inject shell commands."
                    if confirmed and sink_name in command_exec_sinks:
                        print(f"    [symbolic] Checking metacharacter survivability for {src_name} -> {sink_name}")
                        try:
                            sym_result = check_metachar_survivability(
                                proj, cfg, func, call_site_addr, sink_site_addr, sink_arg
                            )
                            finding['symbolic_analysis'] = sym_result
                            if sym_result['injectable']:
                                finding['confidence'] = 'critical'
                                finding['note'] = (
                                    f"CONFIRMED INJECTABLE: {', '.join(repr(c) for c in sym_result['surviving_chars'])} "
                                    f"survive to {sink_name}(). {finding.get('note', '')}"
                                )
                                print(f"    [symbolic] INJECTABLE: {sym_result['surviving_chars']}")
                            else:
                                print(f"    [symbolic] Not injectable: {sym_result['constraints']}")
                        except Exception as e:
                            print(f"    [symbolic] Analysis failed: {e}")

                    findings.append(finding)

            print(f"    RD analysis completed")

        except Exception as e:
            print(f"    RD analysis failed: {e}")
            # Fall back to co-occurrence only
            for call_site_addr, src_name in func_sources:
                for sink_site_addr, sink_name in func_sinks:
                    src_class = 'primary' if src_name in SOURCES_PRIMARY else 'secondary'
                    finding = {
                        'function': func.name,
                        'function_addr': hex(func_addr),
                        'source': src_name,
                        'source_addr': hex(call_site_addr),
                        'source_class': src_class,
                        'sink': sink_name,
                        'sink_addr': hex(sink_site_addr),
                        'method': 'co-occurrence',
                        'confidence': 'low',
                        'note': f'RD failed: {e}',
                    }
                    # Gap 3c: Still include reachability depth
                    finding['reachable_depth'] = depth

                    endpoint = handler_map.get(func_addr, None)
                    if endpoint:
                        finding['endpoint'] = endpoint

                    # Upgrade 2: Extract source parameter name (even in fallback)
                    param_name = extract_source_parameter(proj, cfg, call_site_addr)
                    if param_name:
                        finding['parameter'] = param_name

                    findings.append(finding)

    # Also trace cross-function: source caller → ... → sink caller
    print(f"\n[*] Checking cross-function paths (source caller -> sink caller)")
    cross_func_findings = find_cross_function_paths(proj, cfg, source_callers, sink_callers, sources_found, sinks_found, SOURCES_PRIMARY, handler_map)
    findings.extend(cross_func_findings)

    return findings


def resolve_candidate_function_addr(cfg, candidate_addr):
    """Resolve a discovered sink address to the CFG function address angr uses."""
    if candidate_addr in cfg.functions:
        return candidate_addr

    for func_addr, func in cfg.functions.items():
        size = getattr(func, 'size', 0) or 0
        if size and func_addr <= candidate_addr < func_addr + size:
            return func_addr

    return None


def find_callers(cfg, target_addrs, target_aliases=None):
    """
    Find all functions that call any of the target addresses.

    Returns: {caller_func_addr: [(call_site_addr, target_name), ...]}
    where call_site_addr is the address of the CALL INSTRUCTION within
    the caller function (not the target function address).
    """
    callers = defaultdict(list)  # caller_func_addr → [(call_site_addr, target_name)]
    target_aliases = target_aliases or {}

    for target_addr in target_addrs:
        if target_addr not in cfg.functions:
            continue
        target_func = cfg.functions[target_addr]
        target_name = target_aliases.get(target_addr, target_func.name)

        # Find all callers via the call graph
        if target_addr in cfg.functions.callgraph:
            for caller_addr in cfg.functions.callgraph.predecessors(target_addr):
                # Find the actual call site instruction address within the caller
                call_site = _find_call_site(cfg, caller_addr, target_addr)
                callers[caller_addr].append((call_site, target_name))

    return callers


def _find_call_site(cfg, caller_func_addr, target_func_addr):
    """
    Find the instruction address within caller_func that calls target_func.

    Walks the caller function's blocks looking for a call/branch instruction
    whose target is the given function address. Falls back to the caller's
    address if the exact site can't be determined.
    """
    if caller_func_addr not in cfg.functions:
        return caller_func_addr

    caller = cfg.functions[caller_func_addr]

    try:
        for block in caller.blocks:
            for insn in block.capstone.insns:
                # Check for call/branch instructions
                if insn.mnemonic in ('call', 'jal', 'jalr', 'bl', 'blx', 'blr', 'j', 'b'):
                    # Check if the operand references the target function
                    for op in insn.operands:
                        if hasattr(op, 'imm') and op.imm == target_func_addr:
                            return insn.address

            # Also check the CFG edges: if this block has an edge to target
            node = cfg.model.get_any_node(block.addr)
            if node:
                for succ in cfg.graph.successors(node):
                    if succ.addr == target_func_addr:
                        # The last instruction of this block is likely the call
                        insns = list(block.capstone.insns)
                        if insns:
                            return insns[-1].address
    except Exception:
        pass

    # Fallback: return the caller function address itself
    return caller_func_addr


def find_cross_function_paths(proj, cfg, source_callers, sink_callers, sources_found, sinks_found, SOURCES_PRIMARY, handler_map):
    """Find paths: function_calling_source → ... → function_calling_sink via call graph."""
    findings = []
    callgraph = cfg.functions.callgraph

    for src_func_addr in source_callers:
        for sink_func_addr in sink_callers:
            if src_func_addr == sink_func_addr:
                continue  # Already handled in co-occurrence

            # Check if there's a path in the call graph
            try:
                import networkx as nx
                if nx.has_path(callgraph, src_func_addr, sink_func_addr):
                    path = nx.shortest_path(callgraph, src_func_addr, sink_func_addr)
                    if len(path) <= 4:  # Limit depth to reduce noise
                        path_names = []
                        for addr in path:
                            if addr in cfg.functions:
                                path_names.append(f"{cfg.functions[addr].name}@{hex(addr)}")
                            else:
                                path_names.append(hex(addr))

                        for src_call_site, src_name in source_callers[src_func_addr]:
                            for _, sink_name in sink_callers[sink_func_addr]:
                                src_class = 'primary' if src_name in SOURCES_PRIMARY else 'secondary'
                                finding = {
                                    'function': cfg.functions[src_func_addr].name,
                                    'function_addr': hex(src_func_addr),
                                    'source': src_name,
                                    'source_class': src_class,
                                    'sink': sink_name,
                                    'sink_function': cfg.functions[sink_func_addr].name,
                                    'sink_addr': hex(sink_func_addr),
                                    'call_path': path_names,
                                    'path_depth': len(path) - 1,
                                    'method': 'cross-function-callgraph',
                                    'confidence': 'low',
                                    'note': f'Call graph path depth {len(path)-1}: {" -> ".join(path_names)}',
                                }

                                # Add endpoint if known
                                endpoint = handler_map.get(src_func_addr, None)
                                if endpoint:
                                    finding['endpoint'] = endpoint

                                # Upgrade 2: Extract source parameter name
                                param_name = extract_source_parameter(proj, cfg, src_call_site)
                                if param_name:
                                    finding['parameter'] = param_name

                                findings.append(finding)
            except Exception:
                pass

    return findings


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="FAT angr taint analysis for firmware binaries",
        epilog="Profiles are YAML files in the directory given by --profiles. "
               "Every profile in that directory is loaded; none is selected "
               "from the binary's imports.",
    )
    parser.add_argument("binary", help="Path to ELF binary or raw firmware blob")
    parser.add_argument("output", nargs="?", help="Output JSON file path")
    parser.add_argument("--arch", help="Architecture for raw blobs (cortex-m, arm, mipsel)")
    parser.add_argument("--base", help="Base address for raw blobs (e.g., 0x08000000)")
    parser.add_argument("--profiles", help="Path to profiles directory (default: auto-detect)")
    parser.add_argument("--sink-candidates", help="SinkDiscoveryReport JSON with supplemental candidate sink addresses")
    args = parser.parse_args()

    binary_path = args.binary
    output_path = args.output

    # Auto-detect profiles directory
    import os
    profile_dir = args.profiles
    if not profile_dir:
        # Look relative to this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(script_dir, '..', 'profiles')
        if os.path.isdir(candidate):
            profile_dir = candidate
        # Also check next to the script itself
        candidate2 = os.path.join(script_dir, 'profiles')
        if os.path.isdir(candidate2):
            profile_dir = candidate2

    findings = analyze_binary(
        binary_path,
        arch=args.arch,
        base_addr=args.base,
        profile_dir=profile_dir,
        sink_candidates=args.sink_candidates,
    )

    print(f"\n{'='*60}")
    print(f"RESULTS: {len(findings)} potential taint flows")
    print(f"{'='*60}")

    # Summary counts by method
    method_counts = defaultdict(int)
    for f in findings:
        method_counts[f.get('method', 'unknown')] += 1
    print(f"\nBreakdown by method:")
    for method, count in sorted(method_counts.items()):
        print(f"  {method}: {count}")

    for i, f in enumerate(findings):
        src_class = f.get('source_class', '?')
        method = f.get('method', '?')
        confidence = f.get('confidence', '?')
        print(f"\n  [{i+1}] {f['source']} ({src_class}) -> {f['sink']}")
        print(f"      Function: {f['function']} @ {f['function_addr']}")
        if 'endpoint' in f:
            print(f"      Endpoint: {f['endpoint']}")
        if 'parameter' in f:
            print(f"      Parameter: {f['parameter']}")
        if 'call_path' in f:
            print(f"      Path: {' -> '.join(f['call_path'])}")
        if 'reachable_depth' in f and f['reachable_depth'] is not None:
            print(f"      Reachable depth: {f['reachable_depth']}")
        print(f"      Method: {method} | Confidence: {confidence}")
        if 'symbolic_analysis' in f:
            sym = f['symbolic_analysis']
            if sym.get('injectable'):
                print(f"      SYMBOLIC: INJECTABLE — {', '.join(repr(c) for c in sym['surviving_chars'])} survive")
            else:
                print(f"      Symbolic: {sym.get('method', '?')} — {sym.get('constraints', 'n/a')}")
        if 'poc_suggestion' in f:
            poc = f['poc_suggestion']
            print(f"      PoC ({poc['type']}): {poc['curl']}")

    if output_path:
        with open(output_path, 'w') as fp:
            json.dump(findings, fp, indent=2)
        print(f"\n[*] Results saved to {output_path}")

    return findings


if __name__ == '__main__':
    main()
