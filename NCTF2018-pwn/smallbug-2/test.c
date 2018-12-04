#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main()
{
	char str[100];
	int i = 1;
	//char a = 'A';
	int a = 3;
//	scanf("%s",str);
	memcpy(str,"hello\n",6);
	//printf(str);
	//printf("id:%d,%s,%c",i,str,a);
	printf("%d %d\n",a++,a++);
	printf("%d\n",a);
	return 0;
}
