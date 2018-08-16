#include <stdio.h>
#include <time.h>

int output = 0;
int array1_size = 25;
int array1[25] = {0,};
int array2[25] = {0,};

void vulnerable(int x) {
    if (x < array1_size)
      output = array2[array1[x]];
}

int main() {
  int x = time(NULL) % 25;
  vulnerable(x);
  return 1;
}
