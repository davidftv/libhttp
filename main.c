#include <stdio.h>
#include <stdlib.h>
#include "http.h"

int main()
{
	printf("hello\n");
	struct http_data *hd = http_create();
	http_set_uri(hd, "https://www.securepilot.com:92/hello?kkk");
	http_perform(hd);
	return 0;
}
