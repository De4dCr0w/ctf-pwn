参考链接：

https://0x48.pw/2018/01/16/0x41/

House-of-einherjar：能修改一个临近top chunk的chunk的presize，使其等于fake chunk（在目的地址上构造一个chunk）到该chunk的距离，free该chunk时，与top chunk合并，使其top chunk将我们的fake chunk一起合并，top chunk的地址就变为目的地址。