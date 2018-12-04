#include<stdio.h>
#include<stdlib.h>

int main()
{
	char *a = malloc(0x20);
	char *b = malloc(0x20);
	char *c = malloc(0x20);
	
	free(a);
	free(b);
	return 0;
}
