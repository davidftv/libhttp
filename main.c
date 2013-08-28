#include <stdio.h>
#include <stdlib.h>
#include "http.h"

int main()
{
	struct http_data *hd = http_create();
	http_set_uri(hd, "https://www.google.com/");
	//http_set_uri(hd, "http://localhost/");
	//http_set_uri(hd, "http://www.mobile01.com/");
	//http_set_uri(hd, "http://www.securepilot.com/");
	http_perform(hd);
	printf("\n===============================================\n");
	printf("%s\n",hd->http.body.start);
	printf("===============================================\n");
	//http_destroy_hd(hd);
	return 0;
}
