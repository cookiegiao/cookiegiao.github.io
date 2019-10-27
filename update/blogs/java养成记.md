# java养成记

## 例一

```java
package test;

public class HelloWorld {
      public static void main(String[] args) {
    	  System.out.println("Hello world");
    	  System.out.println("我是中国人");
      }  
}
```



## 例二

```java
package test;

public class A {
    public static  void main(String[] args){
    	 System.out.println("A的main方法在执行");
     }
}

class B{
	public static void main(String[] args){
		System.out.println("B的main方法在执行");
	}
}

class Cc{
    public static void main(String[] args) {
    	System.out.println("C的main方法在执行");
    }
}
```

注意：public的class定义的类名必须和.java文件名一致，如果要定义public的class，那么这个public的class只能有一个。



## 例三

```java
package test;

public class Method1 {
    public static void main(String[] args) {
    	Method1.SumInt(100,200);
    	Method1.SumInt(100,300);
    }
    
    public static void SumInt(int a,int b) {
    	int c = a+b;
    	System.out.println(a+"+"+b+"="+c);
    }
}
```

注意：加有static的方法，调用的时候必须采取"类名."的方式调用。



## 例四

```php
package test;

public class Method2 {
     public static void main(String[] args) {
    	 Method2.pringln("hello wrold");
    	 Method22.m1();
    	 int a = Method22.m2(5,6);
    	 System.out.println("计算结果："+a);
     }
     
     public static void pringln(String msg) {
    	 System.out.println(msg);
     }
}

class Method22{
	public static void m1() {
		System.out.println("Method22的m1的方法被调用");
	}
	
	public static int m2(int i,int j) {
		int k = i+j;
		return k;
	}
}
```

注意：调用某一个类的函数时，要加上某个类的名字。



## 例五

未使用方法重载的时候

```php
package test;

public class Method3 {
    public static void main(String[] args) {
    	System.out.println(Computer.SumInt(10,20));
    	System.out.println(Computer.SumInt(10,20));
    	System.out.println(Computer.SumInt(10,20));
    }
}

class Computer{
	public static int SumInt(int a,int b) {
		return a+b;
	}
	
	public static double SumDouble(double a,double b) {
		return a+b;
	}
	
	public static long SumLong(long a,long b) {
		return a+b;
	}
	
}
```



使用方法重载之后

```java
package test;

public class Method4 {
	public static void main(String[] args) {
		System.out.println(Computer2.Sum(10, 20));
		System.out.println(Computer2.Sum(10.0, 20.0));
		System.out.println(Computer2.Sum(10L, 20L));
	}

}

class Computer2{
	public static int Sum(int a,int b){
         return a+b;
	}
	
	public static double  Sum(double a,double b) {
		return a+b;
	}
	
	public static long Sum(long a,long b) {
		return a+b;
	}
}

```

注意：方法重载发生在：（1）同一个类中     （2）方法名相同，参数列表不同（类型，个数，顺序）

