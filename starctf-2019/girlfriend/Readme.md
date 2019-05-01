### 解题思路

使用了libc 2.29，对tcache加入了保护机制
程序漏洞很明显，对free后的指针为置空，导致uaf
首先可以直接用过unsortbin来leak libc
无法直接tcache double free，可以将tcache填满，构造fastbin double free进行绕过
而后申请到fastbin时覆盖fd指向malloc_hook，最后修改其为one_gadget，再进行malloc操作即可。

### libc 2.29新特性及其绕过

Tcache在2.29版本中对进入tcache的堆块进行了标记，malloc的时候清空标志，再次free时检查标志，如果有就报double free错误。
同时free的时候还会遍历一次tcache，查看是否有相同的堆块，二次保证不会double free


参考链接：http://www.auxy.xyz/research/2018/11/22/TCache-Exp.html
