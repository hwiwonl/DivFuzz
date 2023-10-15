#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NOP10() asm("nop;nop;nop;nop;nop;nop;nop;nop;")

void main(){
  //char buf[100]={0x00,};
  //fgets(buf, sizeof(buf)-1, stdin);
  //read(0, buf, sizeof(buf)-1);
  //printf("buf: %s \n",buf);
//  for(i=0;i<10;i++)
//    asm("nop");
  NOP10();
  char buf[4096]={0x00,};
  //strcpy(buf, "AAAAAAA");
  static char name[] = "/dev/shm/myfileXXXXXX";
  char fname[20] = {0x00,};
  int fd;
  ssize_t ret=0;
  strcpy(fname, name);
  fd = mkstemp(fname);
  printf("fname: %s \n",fname);
//  printf("fname: %s \n",fname);
//  int i=0;
  ret = read(0, buf, sizeof(buf)-1);
  //write(0, buf, sizeof(buf));
  if(ret > sizeof(buf))
    ret = sizeof(buf);
  write(fd, buf, (size_t)ret);
  
  printf("buf: %s \n",buf);  
  close(fd);
}
