# 前言

重新捡起，之前学习的红日安全代码审计项目  [红日安全](https://xz.aliyun.com/search?keyword=%E7%BA%A2%E6%97%A5%E5%AE%89%E5%85%A8)

这次学习**escapeshellarg参数绕过和注入**



# 前情提要

escapeshellarg()

**功能** ：escapeshellarg() 将**给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号**，这样以确保能够直接将一个字符串传入 shell 函数，shell 函数包含 exec(), system() 执行运算符(反引号)

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/1.png)

对于已存在的单引号，除了在前加一个`\`之外，还会再使用一对单引号将其包住。

经过 **escapeshellarg** 函数处理过的参数被拼凑成 **shell** 命令，并且被双引号包裹这样就会造成漏洞，这主要在于bash中双引号和单引号解析变量是有区别的。

在解析单引号的时候 , 被**单引号包裹的内容中如果有变量 , 这个变量名是不会被解析成值的**，但是双引号不同 ,**当变量被双引号包裹的，bash 会将变量名解析成变量的值再使用**。

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/2.png)



数在拼接命令的时候用了双引号的话还是会导致命令执行的漏洞。



escapeshellcmd()

功能：**escapeshellcmd()** 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。 此函数保证用户输入的数据在传送到 [exec()](http://php.net/manual/zh/function.exec.php) 或 [system()](http://php.net/manual/zh/function.system.php) 函数，或者 [执行操作符](http://php.net/manual/zh/language.operators.execution.php) 之前进行转义。

反斜线（\）会在以下字符之前插入： &#;`|\*?~<>^()[]{}$, \x0A 和 \xFF。' 和 " 仅在不配对儿的时候被转义。 在 Windows 平台上，所有这些字符以及  %  和  !  都会被空格代替。

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/3.png)



那么如果escapeshellarg()和escapeshellcmd()一起用的话，会出现什么问题呢？

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/4.png)



对于单个单引号, **escapeshellarg** 函数转义后,还会在左右各加一个单引号,但 **escapeshellcmd** 函数是直接加一个转义符，对于成对的单引号, **escapeshellcmd** 函数默认不转义,但 **escapeshellarg** 函数转义。

当他们一起用的时候，举个例子，如下所示：

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/6.png)

![](/home/cookie/Pictures/blogs/依葫芦画瓢之escapeshellarg参数绕过和注入/5.png)

经过一顿操作：
（1）传入参数是：**127.0.0.1' -v -d a=1**



（2）由于`escapeshellarg`先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。

​          效果如下：**'127.0.0.1'\'' -v -d a=1'** 

（3）经过`escapeshellcmd`针对第二步处理之后的参数中的`\`以及`a=1'`中的单引号进行处理转义：。

​          效果如下：**'127.0.0.1'\\'' -v -d a=1\'**

   最终，`\\`不再是是转义字符，所以单引号配对连接之后将payload分割为三个部分，具体如下所示：

```
curl '127.0.0.1'\\ '' -v -d a=1\'
```

所以这个payload可以简化为`curl 127.0.0.1\ -v -d a=1'`，即向`127.0.0.1\`发起请求，POST 数据为`a=1'`。

 

