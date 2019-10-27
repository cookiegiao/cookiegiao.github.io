## 前言

这实际上是i春秋的一道题，上网搜到`POC`后，我就直接一把梭地打过去,没有去深究漏洞产生的原因。

这里利用的是缓存文件没有合理过滤造成的漏洞，从而前台`getshell`了。因为没有遇到过这种情况，所以这里也就复现一下这个漏洞。

`php5.6+deepin5.11`

`onethink1.0`



### 代码审计

这套`cms`是基于`thinkphp3`进行的二次开发

`./Application/Home/Model/MemberModel.class.php--function login() line 35`

```php

   　 /**
     　* 登录指定用户
    　 * @param  integer $uid 用户ID
    　 * @return boolean      ture-登录成功，false-登录失败
    　 */    
　　　　public function login($uid){
        /* 检测是否在当前应用注册 */
        $user = $this->field(true)->find($uid);
        if(!$user){ //未注册
            /* 在当前应用中注册用户 */
        	$Api = new UserApi();
        	$info = $Api->info($uid);
            $user = $this->create(array('nickname' => $info[1], 'status' => 1));
            $user['uid'] = $uid;
            if(!$this->add($user)){
                $this->error = '前台用户信息注册失败，请重试！';
                return false;
            }
        } elseif(1 != $user['status']) {
            $this->error = '用户未激活或已禁用！'; //应用级别禁用
            return false;
        }

        /* 登录用户 */
        $this->autoLogin($user);

        //记录行为
        action_log('user_login', 'member', $uid, $uid);

        return true;
    }
```

这个函数是用于登录指定用户时被调用的，由于我们之前已经将注册过了，所以用户信息已经被存入数据库中。

![](/home/cookie/Pictures/blogs/onethink1.0缓存文件getshell[复现]/１.png)

`login()`的参数是`$uid`，这个参数来自于数据库中的记录，在数据库中查找该用户的id，正确情况下跟踪到函数`$this->autoLogin($user);`

```php
    private function autoLogin($user){
        /* 更新登录信息 */
        $data = array(
            'uid'             => $user['uid'],
            'login'           => array('exp', '`login`+1'),
            'last_login_time' => NOW_TIME,
            'last_login_ip'   => get_client_ip(1),
        );
        $this->save($data);

        /* 记录登录SESSION和COOKIES */
        $auth = array(
            'uid'             => $user['uid'],
            'username'        => get_username($user['uid']),
            'last_login_time' => $user['last_login_time'],
        );

        session('user_auth', $auth);
        session('user_auth_sign', data_auth_sign($auth));

    }
}
```

调用函数`get_username()`，跟踪这个函数

```php
/**
 * 根据用户ID获取用户名
 * @param  integer $uid 用户ID
 * @return string       用户名
 */
function get_username($uid = 0){
    static $list;
    if(!($uid && is_numeric($uid))){ //获取当前登录用户名
        return session('user_auth.username');
    }

    /* 获取缓存数据 */
    if(empty($list)){
        $list = S('sys_active_user_list');
    }

    /* 查找用户信息 */
    $key = "u{$uid}";
    if(isset($list[$key])){ //已缓存，直接使用
        $name = $list[$key];
    } else { //调用接口获取用户信息
        $User = new User\Api\UserApi();
        $info = $User->info($uid);
        if($info && isset($info[1])){
            $name = $list[$key] = $info[1];
            /* 缓存用户 */
            $count = count($list);
            $max   = C('USER_MAX_CACHE');
            while ($count-- > $max) {
                array_shift($list);
            }
            S('sys_active_user_list', $list);
        } else {
            $name = '';
        }
    }
    return $name;
}
```

关键代码如下

```php
        $User = new User\Api\UserApi();
        $info = $User->info($uid);
        if($info && isset($info[1])){
            $name = $list[$key] = $info[1];
            /* 缓存用户 */
            $count = count($list);
            $max   = C('USER_MAX_CACHE');
            while ($count-- > $max) {
                array_shift($list);
            }
            S('sys_active_user_list', $list);
```

这里调用了`S()`函数,可以看到`$name=>'sys_active_user_list',$value=>$list=>$info[1]`，其中`$info[1]`

来自数据库查询的结果，查询结果中的`nickname`。可以看到这里调用了函数`set()`。

```php
function S($name,$value='',$options=null) {
    static $cache   =   '';
    if(is_array($options) && empty($cache)){
        // 缓存操作的同时初始化
        $type       =   isset($options['type'])?$options['type']:'';
        $cache      =   Think\Cache::getInstance($type,$options);
    }elseif(is_array($name)) { // 缓存初始化
        $type       =   isset($name['type'])?$name['type']:'';
        $cache      =   Think\Cache::getInstance($type,$name);
        return $cache;
    }elseif(empty($cache)) { // 自动初始化
        $cache      =   Think\Cache::getInstance();
    }
    if(''=== $value){ // 获取缓存
        return $cache->get($name);
    }elseif(is_null($value)) { // 删除缓存
        return $cache->rm($name);
    }else { // 缓存数据
        if(is_array($options)) {
            $expire     =   isset($options['expire'])?$options['expire']:NULL;
        }else{
            $expire     =   is_numeric($options)?$options:NULL;
        }
        return $cache->set($name, $value, $expire);
    }
}
```

跟进函数`set()`，缓存文件的操作类`./Library/Think/Cache/Driver/File.class.php`

```php
    /**
     * 写入缓存
     * @access public
     * @param string $name 缓存变量名
     * @param mixed $value  存储数据
     * @param int $expire  有效时间 0为永久
     * @return boolen
     */
    public function set($name,$value,$expire=null) {
        N('cache_write',1);
        if(is_null($expire)) {
            $expire =  $this->options['expire'];
        }
        $filename   =   $this->filename($name);
        $data   =   serialize($value);
        if( C('DATA_CACHE_COMPRESS') && function_exists('gzcompress')) {
            //数据压缩
            $data   =   gzcompress($data,3);
        }
        if(C('DATA_CACHE_CHECK')) {//开启数据校验
            $check  =  md5($data);
        }else {
            $check  =  '';
        }
        $data    = "<?php\n//".sprintf('%012d',$expire).$check.$data."\n?>";
        $result  =   file_put_contents($filename,$data);
        if($result) {
            if($this->options['length']>0) {
                // 记录缓存队列
                $this->queue($name);
            }
            clearstatcache();
            return true;
        }else {
            return false;
        }
    }
```

这个函数用于写入缓存。关键代码如下：

```php
$filename   =   $this->filename($name);
$data   =   serialize($value);
$data    = "<?php\n//".sprintf('%012d',$expire).$check.$data."\n?>";
$result  =   file_put_contents($filename,$data);
```

这个`filename()`如下：

```php

    /**
     * 取得变量的存储文件名
     * @access private
     * @param string $name 缓存变量名
     * @return string
     */
    private function filename($name) {
        $name	=	md5($name);
        if(C('DATA_CACHE_SUBDIR')) {
            // 使用子目录
            $dir   ='';
            for($i=0;$i<C('DATA_PATH_LEVEL');$i++) {
                $dir	.=	$name{$i}.'/';
            }
            if(!is_dir($this->options['temp'].$dir)) {
                mkdir($this->options['temp'].$dir,0755,true);
            }
            $filename	=	$dir.$this->options['prefix'].$name.'.php';
        }else{
            $filename	=	$this->options['prefix'].$name.'.php';
        }
        return $this->options['temp'].$filename;
    }
```

我们查看`./ThinkPHP/Conf/convertion.php`

```php
    /* 数据缓存设置 */
    ....
    'DATA_CACHE_PATH'       =>  TEMP_PATH,// 缓存路径设置 (仅对File方式缓存有效)
    'DATA_CACHE_SUBDIR'     =>  false,    // 使用子目录缓存 (自动根据缓存标识的哈希创建子目录)
    'DATA_PATH_LEVEL'       =>  1,        // 子目录缓存级别
```

查看`./ThinkPHP/ThinkPHP.php`

```php
defined('TEMP_PATH')    or define('TEMP_PATH',      RUNTIME_PATH.'Temp/'); // 项目缓存目录
```



所以最终文件存放位置就是`./Runtime/temp/md5($).php`由于这里的`$name`为`sys_active_user_list`，知道文件存放位置后，我们就可以去构造payload了。

```php
$data    = "<?php\n//".sprintf('%012d',$expire).$check.$data."\n?>";
```

我们构造payload：`%0aphpinfo();#`

`%0` 使得我们传入的参数不被注释，`#`使得序列化后的字符失效。

注册一个用户，使得用户名为payload，不过在注册时，要抓包，将`%0a`解码一下。

登录该用户，使得用户名为payload，不过在登录时，要抓包，将`%0a`解码一下。

然后查看缓存文件

![](/home/cookie/Pictures/blogs/onethink1.0缓存文件getshell[复现]/2.png)



![](/home/cookie/Pictures/blogs/onethink1.0缓存文件getshell[复现]/3.png)



## 总结

漏洞不是很复杂，但是对tp的框架的理解还有待提高