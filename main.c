#include <stdio.h>
#include <stdlib.h>
#include "http.h"

char session[256];

int json_body_get_field(struct http_data *hd, char *field, char *data)
{
    if(!hd || !field || !data) return -1;
    char *body = malloc(hd->http.content_len);
    char *pch = NULL;
    char *rest = NULL;
    int count = 0;
    if(body) {
        memcpy(body, hd->http.body.start, hd->http.content_len);
        pch = strstr(body, field);
        if(pch == NULL) return -1;
        pch = strstr(pch, ":");
        if(pch == NULL) return -1;
        strtok_r(pch, "\"", &rest);
        if(rest == NULL) return -1;
        int rest_len = hd->http.content_len - (rest - body);
        while(count < rest_len && rest[count] != '\"')
        {
            data[count] = rest[count];
            count++;
        }
        free(body);
    }
    return 0;
}


int test_digest_login()
{
	struct http_data *hd = http_create();
	http_set_uri(hd, "http://www-dev.securepilot.com:8080/v1/user/login");
	http_set_method(hd, HTTP_GET);
	http_set_user_pass(hd, "+8979000126", "gemtek");
	if(http_perform(hd) == 0){
		printf("\n===============================================\n");
		printf("%s\n",hd->http.body.start);
		printf("===============================================\n");
	}
    memset(session, 0, 256);
    json_body_get_field(hd, "toekn", session);
    printf("|%s|\n", session);
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
