#include <stdio.h>
#include <stdlib.h>
#include "http.h"


int test_digest_login()
{
	struct http_data *hd = http_create();
	http_set_uri(hd, "http://www-dev.securepilot.com:8080/v1/user/login");
	http_set_method(hd, HTTP_GET);
	http_set_user_pass(hd, "+8979000126", "haha");
	if(http_perform(hd) == 0){
		printf("\n===============================================\n");
		printf("%s\n",hd->http.body.start);
		printf("===============================================\n");
	}
	http_destroy_hd(hd);
    return 0;
}

int test_http_post_with_data(){
	struct http_data *hd = http_create();
	http_set_uri(hd, "http://www-dev.securepilot.com:8080/msg/v1/get");
	http_set_method(hd, HTTP_POST);
    char buf[1024];
    int len = sprintf(buf, "token=%%2B8979000126%%3A24b2a6f443168b5a8bba85b38f9a1f361be8e4b4&clear=false");
    printf("%s\n%d\n",buf, len);
    http_set_body(hd, buf, len);
	if(http_perform(hd) == 0){
		printf("\n===============================================\n");
		printf("%s\n",hd->http.body.start);
		printf("===============================================\n");
	}
	http_destroy_hd(hd);
    return 0;
}

int main()
{
    test_digest_login();
    test_http_post_with_data();
	return 0;
}
