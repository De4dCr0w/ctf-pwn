
### 说明

exp.py 通过fastbin攻击覆盖got表的strtol地址为system地址

exp-stdout.py 通过fastbin攻击覆盖stdout中vtable->__xsputn函数地址为system地址

### 参考链接

https://hpasserby.me/post/aaf4d161.html#more

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/fake-vtable-exploit/