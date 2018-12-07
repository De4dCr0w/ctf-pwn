#include<stdio.h>
#include<stdlib.h>

int main()
{
	char *a = malloc(0x20);
	char *b = malloc(0x30);
	char *b1 = malloc(0x30);
	char *b2 = malloc(0x30);
	char *b3 = malloc(0x30);
	char *b4 = malloc(0x30);
	char *b5 = malloc(0x30);
	char *b6 = malloc(0x30);
	char *b7 = malloc(0x30);
	char *b9 = malloc(0x30);

	char *c = malloc(0x40);
	/*
	char *c1 = malloc(0x40);
	char *c2 = malloc(0x40);
	char *c3 = malloc(0x40);
	char *c4 = malloc(0x40);
	char *c5 = malloc(0x40);
	char *c6 = malloc(0x40);
	char *d = malloc(0x50);
	char *e = malloc(0x60);
*/
	free(b);
	free(b1);
	free(b2);
	free(b3);
	free(b4);
	free(b5);
	free(b6);
	free(b7);
	free(b9);

	char *b8 = malloc(0x30);
	b = malloc(0x30);
	b1 = malloc(0x30);
	b2 = malloc(0x30);
	b3 = malloc(0x30);
	b4 = malloc(0x30);
	b5 = malloc(0x30);
	b7 = malloc(0x40);
	b6 = malloc(0x30);
	a = malloc(0x30);

	/*
	free(c);
	free(c1);
	free(c2);
	free(c3);
	free(c4);
	free(c5);
	free(c6);
	free(d);
	*/
}
