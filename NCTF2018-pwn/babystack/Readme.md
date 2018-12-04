
```
$ cat /proc/self/maps
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
vsyscall地址固定，用于程序调用内核函数

```
0xffffffffff600000:	mov    rax,0x60
0xffffffffff600007:	syscall 
0xffffffffff600009:	ret
```
上述代码片段相当于ret，可以在栈中覆盖0xffffffffff600000，一直ret到system函数的地址。