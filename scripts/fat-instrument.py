#!/usr/bin/env python3
"""
FAT Instrument — Frida-like firmware instrumentation via QEMU GDB stub.

Connects to QEMU's GDB stub and sets hardware breakpoints on
firmware functions. When a breakpoint hits, logs the MIPS register
state (function arguments, return address, stack pointer).

Usage:
    python3 fat-instrument.py --host 127.0.0.1 --port 1234 --hooks hooks.yaml
"""

import socket
import struct
import time
import json
import sys
import signal

class GDBClient:
    """Minimal GDB Remote Serial Protocol client."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.settimeout(5)
        # Read initial '+' ack
        try:
            self.sock.recv(1)
        except:
            pass

    def send(self, data):
        """Send a GDB RSP packet."""
        checksum = sum(ord(c) for c in data) % 256
        packet = f'${data}#{checksum:02x}'
        self.sock.send(packet.encode())
        return self._recv()

    def _recv(self):
        """Receive a GDB RSP response."""
        buf = b''
        try:
            while True:
                c = self.sock.recv(1)
                if not c:
                    break
                buf += c
                if c == b'#':
                    buf += self.sock.recv(2)  # checksum
                    break
        except socket.timeout:
            pass
        # Strip framing
        text = buf.decode('ascii', errors='replace')
        if '$' in text and '#' in text:
            start = text.index('$') + 1
            end = text.index('#')
            return text[start:end]
        return text

    def read_registers(self):
        """Read all MIPS registers."""
        resp = self.send('g')
        if not resp or resp.startswith('E'):
            return None
        # MIPS registers: 32 GPR + status + lo + hi + bad + cause + pc = 38 regs
        # Each register is 4 bytes (8 hex chars) in little-endian
        regs = {}
        reg_names = [
            'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
            't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
            't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra',
            'sr', 'lo', 'hi', 'bad', 'cause', 'pc'
        ]
        for i, name in enumerate(reg_names):
            offset = i * 8
            if offset + 8 <= len(resp):
                hex_val = resp[offset:offset+8]
                # Convert from little-endian hex
                try:
                    val = struct.unpack('<I', bytes.fromhex(hex_val))[0]
                    regs[name] = val
                except:
                    pass
        return regs

    def read_memory(self, addr, length):
        """Read guest memory."""
        resp = self.send(f'm{addr:x},{length:x}')
        if resp and not resp.startswith('E'):
            return bytes.fromhex(resp)
        return None

    def read_string(self, addr, max_len=256):
        """Read a null-terminated string from guest memory."""
        data = self.read_memory(addr, max_len)
        if data:
            null_pos = data.find(b'\x00')
            if null_pos >= 0:
                return data[:null_pos].decode('ascii', errors='replace')
            return data.decode('ascii', errors='replace')
        return None

    def set_breakpoint(self, addr, kind=4):
        """Set a software breakpoint at addr."""
        resp = self.send(f'Z0,{addr:x},{kind}')
        return resp == 'OK'

    def remove_breakpoint(self, addr, kind=4):
        """Remove breakpoint."""
        resp = self.send(f'z0,{addr:x},{kind}')
        return resp == 'OK'

    def continue_execution(self):
        """Continue execution."""
        self.send('c')

    def step(self):
        """Single step."""
        return self.send('s')

    def wait_for_stop(self, timeout=30):
        """Wait for the target to stop (breakpoint hit)."""
        self.sock.settimeout(timeout)
        try:
            buf = b''
            while True:
                c = self.sock.recv(1)
                buf += c
                if c == b'#':
                    buf += self.sock.recv(2)
                    break
            text = buf.decode('ascii', errors='replace')
            if '$' in text:
                start = text.index('$') + 1
                end = text.index('#')
                return text[start:end]
        except socket.timeout:
            return None
        return None

    def close(self):
        self.sock.close()


def instrument_firmware(host, port, hooks, duration=30):
    """
    Connect to QEMU GDB stub and instrument firmware functions.

    hooks: list of dicts with:
        - name: human-readable hook name
        - address: guest virtual address to break on
        - log_args: list of register names to log as arguments
        - log_string_args: list of register names to dereference as strings
        - log_retval: whether to log return value (v0)
    """
    print(f"[FAT-Instrument] Connecting to {host}:{port}...")
    gdb = GDBClient(host, port)

    # Read initial register state
    regs = gdb.read_registers()
    if regs:
        print(f"[FAT-Instrument] Connected. PC=0x{regs.get('pc', 0):08x}")
    else:
        print("[FAT-Instrument] Connected but couldn't read registers")

    # Set breakpoints
    for hook in hooks:
        addr = hook['address']
        name = hook['name']
        ok = gdb.set_breakpoint(addr)
        print(f"[FAT-Instrument] Breakpoint at 0x{addr:08x} ({name}): {'OK' if ok else 'FAILED'}")

    # Continue and wait for hits
    print(f"[FAT-Instrument] Monitoring for {duration} seconds...")
    print("=" * 60)

    start_time = time.time()
    hit_count = 0

    try:
        gdb.continue_execution()

        while time.time() - start_time < duration:
            stop = gdb.wait_for_stop(timeout=5)
            if stop is None:
                continue

            # Read registers at breakpoint
            regs = gdb.read_registers()
            if not regs:
                gdb.continue_execution()
                continue

            pc = regs.get('pc', 0)
            hit_count += 1

            # Find which hook was hit
            for hook in hooks:
                if hook['address'] == pc:
                    timestamp = time.time() - start_time
                    print(f"\n[{timestamp:6.2f}s] === {hook['name']} hit (#{hit_count}) ===")
                    print(f"  PC=0x{pc:08x}  RA=0x{regs.get('ra', 0):08x}  SP=0x{regs.get('sp', 0):08x}")

                    # Log requested argument registers
                    for reg_name in hook.get('log_args', []):
                        val = regs.get(reg_name, 0)
                        print(f"  {reg_name}=0x{val:08x} ({val})")

                    # Log string arguments (dereference pointers)
                    for reg_name in hook.get('log_string_args', []):
                        val = regs.get(reg_name, 0)
                        if val > 0x400000:  # valid address range
                            s = gdb.read_string(val)
                            print(f"  {reg_name}=0x{val:08x} → \"{s}\"")
                        else:
                            print(f"  {reg_name}=0x{val:08x} (null or invalid)")

                    break

            # Continue
            gdb.continue_execution()

    except KeyboardInterrupt:
        print("\n[FAT-Instrument] Interrupted")
    except Exception as e:
        print(f"\n[FAT-Instrument] Error: {e}")

    print("=" * 60)
    print(f"[FAT-Instrument] {hit_count} breakpoint hits in {time.time() - start_time:.1f}s")

    # Clean up breakpoints
    for hook in hooks:
        gdb.remove_breakpoint(hook['address'])

    gdb.close()


if __name__ == '__main__':
    # DCS-930L alphapd hooks
    hooks = [
        {
            'name': 'hardware_register_access',
            'address': 0x0043a070,  # The function we patched
            'log_args': ['a0', 'a1'],
            'log_string_args': [],
        },
        {
            'name': 'alphapd_entry',
            'address': 0x00400140,  # ELF entry point
            'log_args': ['a0', 'a1', 'a2', 'a3'],
            'log_string_args': [],
        },
    ]

    import argparse
    parser = argparse.ArgumentParser(
        description='FAT Instrument — Frida-like firmware instrumentation via QEMU GDB stub')
    parser.add_argument('--host', default='127.0.0.1',
                        help='GDB stub host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=1234,
                        help='GDB stub port (default: 1234)')
    parser.add_argument('--duration', type=int, default=15,
                        help='Monitoring duration in seconds (default: 15)')
    # Also accept positional args for backwards compatibility
    parser.add_argument('pos_host', nargs='?', default=None)
    parser.add_argument('pos_port', nargs='?', type=int, default=None)
    parser.add_argument('pos_duration', nargs='?', type=int, default=None)
    args = parser.parse_args()

    host = args.pos_host or args.host
    port = args.pos_port or args.port
    duration = args.pos_duration or args.duration

    instrument_firmware(host, port, hooks, duration)
