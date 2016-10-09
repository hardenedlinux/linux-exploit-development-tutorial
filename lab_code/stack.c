/*
 * gcc -fno-stack-protector -m32 -z execstack -o level1 stack.c
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
