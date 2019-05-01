### 解题思路

获取数字时采用gets，存在栈溢，从而覆盖掉栈中的i和预先分配的堆地址，改到got表即可leak，在leak同时修改free为main_func地址即可再次利用栈溢出

修改另一个got表中free函数到system即可get shell,这里注意利用时覆盖i和最开始的数目时的大小问题，即时停止防止crash

注意：
（1）比赛中覆盖got表函数为one_gadget无法成功，本地可以  

（2）atoi可以转化负数，如“-0x123”，比赛中传入0xf7xxxxxx的地址超出有符号整形的范围，变成0x7fffffff，就拆开传输，麻烦不少