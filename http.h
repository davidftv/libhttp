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


#define HTTP_HEADER_NUM 32
#define HTTP_NONCE_LEN	34
#define HTTP_USER_LEN	64
#define HTTP_PASS_LEN	64

#define HTTP_AUTH_LEN	128
#define HTTP_PATH_LEN	512
#define HTTP_HOST_LEN	512

#define HTTP_URI_LEN	1024
#define HTTP_RECV_BUF	1000

#define HTTP_HEADER_LEN	512

#define DEFAULT_HTTP_PORT	80
#define DEFAULT_HTTPS_PORT	443

#define FILE_PATH_LEN	128

#define HTTP_TIMEOUT	3
#define HTTP_KEEP_TIMEOUT    1

#define SSL_DEPTH 		1
#define SSL_KEY_PW_LEN	64
#define SSL_DATA_LEN	256

#ifdef DEBUG_HTTP
#define LOG printf
#else
#define LOG
#endif



enum{
	PROTO_HTTP,
	PROTO_HTTPS
};

enum{
	HTTP_GET,
	HTTP_POST,
	HTTP_UPDATE,
	HTTP_DELETE
};

enum{
	HTTP_AUTH_DIGEST,
	HTTP_AUTH_BASIC
};

struct http_uri {
	int					proto;
	char 				url[HTTP_URI_LEN];
	char 				server[HTTP_HOST_LEN];
	char 				host[HTTP_HOST_LEN];
	char 				path[HTTP_PATH_LEN];
	int					port;
};
struct hdb {
	int					req_type;
	char				req[HTTP_HEADER_LEN];
    char                *header[HTTP_HEADER_NUM];
    int                 header_count;
    char                version[8];
    char                code[8];
    char                phrase[32];
	char				auth[8];
	char				realm[16];
	char				nonce[HTTP_NONCE_LEN];
	int					chunked;
	int					content_len;	//Total length
	struct {
		int				offset;			//Data read
		int				size; 			//Buffer size
		char			*start;			//Body start
	} body;
	char				buf[HTTP_RECV_BUF];		//Buffer
	int					buf_offset;		//Buffer read
};
struct http_data {
	int 				sk;
	struct sockaddr_in 	srv_addr;
	struct http_uri		uri;
	struct timeval 		tv;
	int					phase;
	int					cert_auth;
	char				cert_path[FILE_PATH_LEN];
	char				key_path[FILE_PATH_LEN];
	char				passwd[SSL_KEY_PW_LEN];
	char				username[HTTP_USER_LEN];
	char				password[HTTP_PASS_LEN];
    void                *body_send;
    int                 body_send_len;
	int (*send)(struct http_data *, void *, int);
	int (*recv)(struct http_data *, void *, int, int);
#ifdef HAVE_OPENSSL
	BIO 				*bio;
	SSL_CTX				*ctx;
	SSL					*ssl;
#endif //HAVE_OPENSSL
	struct hdb			http;
};

#define DBGHTTP(fmt, args...)  printf("[%s:%d]" fmt, __FILE__,__LINE__,##args)

char *http_url_encode(char *str);
char *http_url_decode(char *str);
struct http_data *http_create();
int http_set_uri(struct http_data *hd, char *uri);
int http_set_cert_path(struct http_data *hd, char *cert, int verify_serv);
int http_set_key_path(struct http_data *hd, char *key, char *pw);
int http_perform(struct http_data *hd);
int http_set_method(struct http_data *hd, int type);
void http_destroy_hd(struct http_data *hd);
int http_set_user_pass(struct http_data *hd, char *user, char *pass);
int http_set_body(struct http_data *hd, void *data, int len);
#endif
