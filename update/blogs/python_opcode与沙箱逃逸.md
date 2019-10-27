# 概念和定理

## python中的代码对象`code_object`与`__code__`属性

在`函数.__code__`中，所有不以下划线开头的属性，一共有15个。

![](/home/cookie/Pictures/blogs/5.png)

参考文章：[Python 中的代码对象 code object 与 __code__ 属性](https://blog.csdn.net/jpch89/article/details/86764245)

`co_code`:

二进制格式的字节码 `bytecode`，以字节串 `bytes` 的形式存储（在 `Python 2` 中以 `str` 类型存储）。它为虚拟机提供一系列的指令。函数从第一条指令开始执行，在碰到 `RETURN_VALUE` 指令的时候停止执行。



## 利用`OpCode`改变程序运行逻辑

参考文章：[利用OpCode绕过Python沙箱](https://xz.aliyun.com/t/6159#toc-10)

### 如何查看一个函数的Opcode?

```python
def a():
    if 1 == 2:
        print("flag{****}")

        
import dis
print "Opcode of a():",a.__code__.co_code.encode('hex')
code = a.__code__.co_code.encode('hex')
dis.dis(code.decode('hex'))
```



取得反编译结果为：

```
0 LOAD_CONST          1 (1)
      3 LOAD_CONST          2 (2)
      6 COMPARE_OP          2 (==)
      9 POP_JUMP_IF_FALSE    20
     12 LOAD_CONST          3 (3)
     15 LOAD_BUILD_CLASS
     16 YIELD_FROM     
     17 JUMP_FORWARD        0 (to 20)
>>   20 LOAD_CONST          0 (0)
     23 RETURN_VALUE
```

