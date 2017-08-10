# 内核安全

## 安全机制

kernel ROP 非常类似于用户态的 ROP，主要区别是用户态使用`system()`来调用执行 shellcode，而内核 ROP 是通过`prepare_kernel_cred()`来提升权限,下面介绍 x86 上面 rop 构造 ret2dir。

[Linux kernel ROP](http://www.freebuf.com/articles/system/94198.html)

[ret2dir: Rethinking Kernel Isolation](http://www.cs.columbia.edu/~vpk/papers/ret2dir.sec14.pdf)

PXN 是 ARM 平台下的一项内核保护措施，该措施的目的是阻止内核执行用户态代码，保证内核的执行流程不会被劫持到用户空间。

[PXN 的研究与绕过](http://blog.csdn.net/hu3167343/article/details/47394707)

[Ownyour Android! Yet Another Universal Root](https://www.blackhat.com/docs/us-15/materials/us-15-Xu-Ah-Universal-Android-Rooting-Is-Back-wp.pdf)

## 现实案例研究

[CVE-2014-2851 group_info UAF Exploitation](http://www.freebuf.com/vuls/92465.html)

[(CVE-2015-3636) CVE-2015-3636 kernel: ping sockets: use-after-free leading to local privilege escalation](https://bugzilla.redhat.com/show_bug.cgi?id=1218074)

[ANALYSISAND EXPLOITATION OF A LINUX KERNEL VULNERABILITY (CVE-2016-0728)](http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/)

[]
