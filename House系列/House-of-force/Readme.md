参考链接：

https://0x48.pw/2018/01/16/0x41/


House-of-force:可以修改top_chunk的size，将其修改成0xffffffff(x86)，假设这个时候的top_chunk=0x601200, 然后malloc(0xffe00020)，然后对malloc申请的size进行检查，0xffe00030 < top_chunk_size，所以可以成功malloc内存，然后计算top_chunk的新地址：0xffe00030+0x601200=0x100401230, 因为是x86环境，最高位溢出了，所以top_chunk=0x401230

再次malloc的时候，返回的地址就是0x401238