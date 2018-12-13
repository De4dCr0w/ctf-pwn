
和children_tcache的漏洞点一样，溢出一个null字节。但是缺少显示操作，不能像children_tcache那样进行信息泄露

所以要通过_IO_FILE的fwrite操作中

```
_IO_do_write (f, f->_IO_write_base,  // our target
			 f->_IO_write_ptr - f->_IO_write_base);
```

修改f->_IO_write_base地址进行任意读，进行信息泄露。

### 参考链接

https://hpasserby.me/post/8e1cd5dc.html

https://znqt.github.io/hitcon2018-babytcache/

https://vigneshsrao.github.io/babytcache/

angelboy的slide：https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

演讲视频：https://www.youtube.com/watch?v=Fr3VU5hdL4s