/*
   american fuzzy lop - a trivial program to test the build
   --------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {

  char buf[160];

  if (read(0, buf, 160) < 1) {
    printf("Hum?\n");
    exit(1);
  }

  if(buf[0] == 'a')
    if(buf[1] == 'b')
      if(buf[2] == 'c')
        if(buf[3] == 'd')
          if(buf[4] == 'e')
              printf(buf);

  return 0;

}
