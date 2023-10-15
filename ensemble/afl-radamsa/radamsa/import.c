#include <dlfcn.h>
#include <stdio.h>
int (*main_func)(int argc, char **argv);
int main() {
void *d = dlopen("bin/libradamsa.so", RTLD_LAZY);
char *argv[] = {"test", "-s", "1", "/etc/passwd", NULL};
main_func = dlsym(d, "main");
for(int i = 0; i < 1000; i++)
main_func(4, argv);
}
