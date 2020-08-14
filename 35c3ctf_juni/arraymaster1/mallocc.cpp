#include<iostream>
#include<cstring>
using namespace std;

int main()
{
char *str;
   /* Initial memory allocation */
   str = (char *) malloc(15);
   strcpy(str, "tutorialspoint");
   printf("String = %s,  Address = %u  %d", str, str,str);
}
