### 说明

final.py是在关闭随机化的情况下进行利用的

final.py是关闭随机化后，测试直接覆盖__malloc_hook为one_gadget地址，不经过unsorted bin attack这一步，将覆盖3个字节变成覆盖8个字节

### 参考链接：

https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc

https://github.com/romanking98/House-Of-Roman

https://www.jianshu.com/p/6ba2bea1079e