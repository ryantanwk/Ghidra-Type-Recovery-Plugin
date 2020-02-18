#include <stdio.h>
#include <string.h>

struct Books {
   int a;
   char title[2];
   int b;
} book;  

int main() {
	int i = 3;
	struct Books obj;
	obj.a = 7;
	strcpy(obj.title,"ab");
	obj.b = 11;
	//struct Books obj = {3,5};
	int j = 5;
	return 0;
}



