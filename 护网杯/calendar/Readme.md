
### 解题思路

通过House-of-Roman技术完成利用，但这题限制了创建堆块的大小，通过正常操作不能释放处unsorted bin，所以需要通过off-by-one改写size大小

漏洞点存在两个（1）uaf （2）off-by-one

利用过程：

（1）通过fastbin attack分配到__malloc_hook-0x23的地址，此时size为0x7f，可以绕过检查

（2）通过unsorted bin attack将main_arena+88的地址写入__malloc_hook处，方便后面one_gadget覆盖后三个字节

（3）将__malloc_hook保存的地址后三个字节覆盖成one_gadget，double free触发__malloc_hook

### 说明 

calendar-exp.py是关闭随机化的情况下进行利用

calendar-exp-test.py是开启随机化后，进行爆破测试的，但是没有成功

### 参考链接

https://www.anquanke.com/post/id/162121?from=timeline#h3-10

https://www.jianshu.com/p/6ba2bea1079e

