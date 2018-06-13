#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char *a = malloc(0xf8);
	char *b = malloc(0xf8);
	strncpy(a,"aaa\0x00",10);
	free(a);
	return 0;
}
