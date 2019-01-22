#include<stdio.h>
int main()
{
	FILE *fp;
	char *path = "/usr/foo/bar/foo.txt";
	const char *text = "Write this to the file";

	fp=fopen(path, "w");
	if(fp == 0)
	{
		printf("\nUnable to open the file for read!\n");
	}
	printf("\nFile was opened for read\n");
	fprintf(fp, "Random text: %s\n", text);
	fclose(fp);
	return 0;
}
