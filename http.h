#ifndef __HTTP_H
#define __HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netdb.h>

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ssl23.h>
#include <openssl/ssl2.h>
#endif //HAVE_OPENSSL

#define HTTP_PATH_LEN	512
#define HTTP_HOST_LEN	512
#define HTTP_URI_LEN	1024

#define DEFAULT_HTTP_PORT	80
#define DEFAULT_HTTPS_PORT	443

#define HTTP_TIMEOUT	3

#ifdef DEBUG_HTTP
#define LOG printf
#else
#define LOG
#endif



enum{
	PROTO_HTTP,
	PROTO_HTTPS
};

struct http_uri {
	int					proto;
	char 				url[HTTP_URI_LEN];
	char 				server[HTTP_HOST_LEN];
	char 				host[HTTP_HOST_LEN];
	char 				path[HTTP_PATH_LEN];
	int					port;
};
struct http_data {
	int 				sk;
	struct sockaddr_in 	srv_addr;
	struct http_uri		uri;
	struct timeval 		tv;
#ifdef HAVE_OPENSSL
	BIO 				*bio;
	SSL_CTX				*ctx;
	SSL					*ssl;
#endif //HAVE_OPENSSL
};

struct http_data *http_create();
int http_set_uri(struct http_data *hd, char *uri);
int http_perform(struct http_data *hd);

#endif
