#include <stdio.h>
#include <stdlib.h>
#include "http.h"

int main()
{
	struct http_data *hd = http_create();
#if 1
	http_set_uri(hd, "https://www.securepilot.com/login");
	http_set_method(hd, HTTP_POST);
	http_set_user_pass(hd, "+8979000126", "gemtek");
#endif
	//http_set_uri(hd, "https://www.google.com/");
	//http_set_uri(hd, "http://localhost/");
	//http_set_uri(hd, "http://www.mobile01.com/");
	//http_set_uri(hd, "http://www.securepilot.com/");
	http_perform(hd);
#if 1
	printf("\n===============================================\n");
	printf("%s\n",hd->http.body.start);
	printf("===============================================\n");
#endif
	http_destroy_hd(hd);
	return 0;
}
