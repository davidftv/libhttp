#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "http.h"


struct http_data *http_create() {
	struct http_data *hd = malloc(sizeof(struct http_data));
	memset(hd, 0, sizeof(struct http_data));
	hd->tv.tv_sec = HTTP_TIMEOUT;
	return hd;
}

int http_set_uri(struct http_data *hd, char *uri) {
	if(hd){
		strncpy(hd->uri.server, uri, HTTP_PATH_LEN);
		return 0;
	}
	return -1;
}

int http_send(struct http_data *hd, void *buf, int len) {
	int ret = -1, sent = 0;
	if(hd->sk > 0){
		do{
			ret = send(hd->sk, (char *)buf + sent, len - sent, 0);
			if(len > 0){
				sent += ret;
			}else{
				//FIXME add error handle break do while
				LOG("Error: send data failure %s\n", strerror(errno));
			}
		}while(len > 0 && sent < len);
	}
	if(ret >= 0 )
		return sent;
	else
		return ret;
}
int http_recv(struct http_data *hd, void *buf, int len) {
	int ret = -1;
	if(hd->sk > 0) {
		fd_set fd_set;
		FD_ZERO(&fd_set);
		FD_SET(hd->sk , &fd_set);
		ret = select(hd->sk + 1, &fd_set, NULL, NULL, &hd->tv);
		if(ret > 0){
			ret = recv(hd->sk, buf, len, 0);
			if(ret <= 0) {
				LOG("Error: receive data failure %s\n", strerror(errno));
			}
		}else{
			LOG("Error: select socket failure %s\n", strerror(errno));
		}
	}
	return ret;
}
#ifdef HAVE_OPENSSL
int https_send(struct http_data *hd, void *buf, int len) {
	return 0;
}
int https_recv(struct http_data *hd, void *buf, int len) {
	return 0;
}
#endif



int http_host_parse(struct http_data *hd) {
	char *ppath, *pport;
	char *host = NULL;
	char *serv = NULL;
	serv = hd->uri.server;
	if(hd){
		if(strncasecmp(hd->uri.server, "https://", 8) == 0){
			hd->uri.proto = PROTO_HTTPS;
			host = serv + strlen("https://");;
			LOG("perform a https request\n");
		}else if(strncasecmp(hd->uri.server, "http://", 7) == 0){
			hd->uri.proto = PROTO_HTTP;
			host = serv + strlen("http://");;
			LOG("perform a http request\n");
		}else{
			LOG("protocol not support!\n");
			hd->uri.proto = PROTO_HTTP; // Default protocol http
		}
		if((ppath = strchr(host, '/')) != NULL) {
			snprintf(hd->uri.path, HTTP_PATH_LEN, "%s", ppath);
			*ppath = '\0';
		}else{
			snprintf(hd->uri.path, HTTP_PATH_LEN, "*");
		}
		if((pport = strchr(host, ':'))!=NULL) {
			if(*(pport+1) != '\0'){
				hd->uri.port = atoi(pport + 1);
				*pport = '\0';
				snprintf(hd->uri.host, HTTP_HOST_LEN, "%s", host);
			}else{
				*pport = '\0';
				goto no_port;
			}
		}else{
no_port:
			snprintf(hd->uri.host, HTTP_HOST_LEN, "%s", host);
			if(hd->uri.port == 0){
				if(hd->uri.proto == PROTO_HTTPS)
					hd->uri.port = DEFAULT_HTTPS_PORT;
				else
					hd->uri.port = DEFAULT_HTTP_PORT;
			}
		}
		if(hd->uri.port > 65535) {
			LOG("Error: http port out of range!\n");
			if(hd->uri.proto == PROTO_HTTPS)
                hd->uri.port = DEFAULT_HTTPS_PORT;
            else
                hd->uri.port = DEFAULT_HTTP_PORT;
		}
	}else{
		goto err;
	}
	return 0;
err:
	return -1;
}

int http_perform(struct http_data *hd) {
	struct hostent *server = NULL;
	if(http_host_parse(hd) != 0) {
		LOG("Error: URL parsing error!\nHOST:%s\nPORT:%d\nPATH:%s\n",
			hd->uri.host, hd->uri.port, hd->uri.path);
	}else{
		LOG("Connect to\nHOST:%s\nPORT:%d\nPATH:%s\n",
			hd->uri.host, hd->uri.port, hd->uri.path);
	}
	server = gethostbyname(hd->uri.host);
	if(server == NULL) {
		LOG("Error: Gethostbyname failure\n");
		return -1;
	}
	memcpy(&hd->srv_addr.sin_addr, server->h_addr, sizeof(hd->srv_addr.sin_addr));
	hd->srv_addr.sin_family = AF_INET;
	hd->srv_addr.sin_port = htons(hd->uri.port);
	hd->sk = socket(AF_INET, SOCK_STREAM, 0);
	if(hd->sk < 0) {
		LOG("Error: create socket failure %d\n", hd->sk);
		return -1;
	}
	unsigned long fc = 1;
    ioctl(hd->sk, FIONBIO, &fc);

	return 0;
}

