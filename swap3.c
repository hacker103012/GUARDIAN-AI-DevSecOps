#include<stdio.h>
int main() {
   int a=2,b=3,c=4;
   int temp;
  printf("before swap value is:%d %d %d \n",a,b,c);
   temp = a;
   a=b;
   b=c;
   c=temp;
  printf("after swap value is:%d %d %d \n",a,b,c);
  return 0;
}
  

