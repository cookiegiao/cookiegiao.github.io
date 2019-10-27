# 前言

记录我在学习python过程中的一些笔记

# 0001

```python
>>> import hashlib
>>> m=hashlib.md5()
>>> m.update('1')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: Unicode-objects must be encoded before hashing
```

在进行md5哈希运算前，需要对数据进行编码

所以改成

```python
>>> m.update('1'.encode('utf-8'))
```



# 0002

python中yield的用法详解——最简单，最清晰的解释

迭代器是一个对象，通过一系列的值来管理迭代。

(1).迭代器对象，接下来每次调用内置函数next(i)，都会从当前序列中产生一个后续元素。，要是没有后续元素，则将抛出一个`StopIteration`异常。

(2)对象obj是可迭代的，那么通过语法`iter(obj)`可以产生一个迭代器。

python中创建一个迭代器最方便的技术是使用生成器。生成器的语法实现类似于函数，但是不返回值。



传统的函数可能会产生并返回一个包含所有因子的列表，实现如下：

```python
def factors(n):
    results = []
    for k in range(1,n+1):
        if n%k == 0:
            results.append(k)
    return results
```

而生成器中计算这些因子的实现如下：

```python
def factors(n):
    for k in range(1,n+1):
        if n%k==0:
            yield k
```



解释一下`yield`的用法

如果你还没有对yield有个初步分认识，那么你先把yield看做“return”，这个是直观的，它首先是个return，普通的return是什么意思，就是在程序中返回某个值，返回之后程序就不再往下运行了。看做return之后再把它看做一个是生成器（generator）的一部分（带yield的函数才是真正的迭代器），好了，如果你对这些不明白的话，那先把yield看做return,然后直接看下面的程序.

```python
def foo():
    print("starting....")
    while True:
        print("world")
        res = yield 4
        print("hello")
g = foo()
print(next(g))
print("*"*20)
print(next(g))
```

这个程序的执行结果

```python
starting....
world
4
********************
hello
world
4
```

先生成一个生成器g，然后执行next(g)，到函数中迭代出一个4后，退出函数，等下一次执行next(g)的时候，从我们之前停止的地方继续执行。



另一个传统的代码

```python
def foo():
    print("starting....")
    while True:
        print("world")
        return 4
        print("hello")


print(foo())
print("*"*20)
print(foo())
```

执行结果:

```python
starting....
world
4
********************
starting....
world
4
```



到这里你可能就明白yield和return的关系和区别了，带yield的函数是一个生成器，而不是一个函数了，这个生成器有一个函数就是next函数，next就相当于“下一步”生成哪个数，这一次的next开始的地方是接着上一次的next停止的地方执行的，所以调用next的时候，生成器并不会从`foo()`函数的开始执行，只是接着上一步停止的地方开始，然后遇到yield后，return出要生成的数，此步就结束。



****

再一个例子：

```python
def foo():
    print("starting...")
    while True:
        res = yield 4
        print("res:",res)
g = foo()
print(next(g))
print("*"*20)
print(next(g))
```

这个函数的执行结果

