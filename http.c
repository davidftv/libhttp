#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include "http.h"



struct http_data *http_create() {
	struct http_data *hd = malloc(sizeof(struct http_data));
	memset(hd, 0, sizeof(struct http_data));
	hd->tv.tv_sec = HTTP_TIMEOUT;
	return hd;
}

void http_nonblock_socket(int sk)
{
	unsigned long fc = 1;
    ioctl(sk, FIONBIO, &fc);
}
void http_block_socket(int sk)
{
	unsigned long fc = 0;
    ioctl(sk, FIONBIO, &fc);
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
		fd_set fset;
		FD_ZERO(&fset);
		FD_SET(hd->sk , &fset);
		ret = select(hd->sk + 1, &fset, NULL, NULL, &hd->tv);
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
	int ret = -1, sent = 0;
	if(hd->sk > 0){
		do{
			ret = SSL_write(hd->ssl, (char *)buf + sent, len - sent);
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
int https_recv(struct http_data *hd, void *buf, int len) {
	int ret = -1;
	if(SSL_pending(hd->ssl) > 0) {
		ret = SSL_read(hd->ssl, buf, len);
		if(ret <= 0) {
			LOG("Error: receive ssl data failure %s\n", strerror(errno));
		}
	}else{
		fd_set fset;
		FD_ZERO(&fset);
		FD_SET(hd->sk , &fset);
		ret = select(hd->sk + 1, &fset, NULL, NULL, &hd->tv);
		if(ret > 0){
			ret = SSL_read(hd->ssl, buf, len);
			if(ret <= 0) {
				LOG("Error: receive data failure %s\n", strerror(errno));
			}
		}else{
			LOG("Error: select socket failure %s\n", strerror(errno));
		}
	}
	return ret;
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
#ifdef HAVE_OPENSSL
			hd->send = https_send;
			hd->recv = https_recv;
#else
			return -1;
#endif // HAVE_OPENSSL
		}else if(strncasecmp(hd->uri.server, "http://", 7) == 0){
			hd->uri.proto = PROTO_HTTP;
			host = serv + strlen("http://");;
			LOG("perform a http request\n");
			hd->send = http_send;
			hd->recv = http_recv;
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
#ifdef HAVE_OPENSSL
static int ca_verify_cb(int ok, X509_STORE_CTX *store)
{
	int depth, err;
	X509 *cert = NULL;
	char data[256];
	if(!ok) {
		cert = X509_STORE_CTX_get_current_cert(store);
		depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);
        LOG("Error with certificate at depth: %i", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        LOG(" issuer = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        LOG(" subject = %s", data);
        LOG(" err %i:%s", err, X509_verify_cert_error_string(err));
		return 0;
	}
	return ok;
}

int http_ssl_setup(struct http_data *hd) {
		SSL_load_error_strings();
		if(SSL_library_init() != 1) {
			LOG("Error: SSL lib init failure\n");
			return -1;
		}
		if((hd->ctx = SSL_CTX_new(SSLv3_method())) == NULL) {
			LOG("Create SSLv3 failure\n");
			if((hd->ctx = SSL_CTX_new(TLSv1_method())) == NULL) {
				LOG("Create TLSv1 failure\n");
				return -1;
			}
		}
		if(hd->cert_auth == 0){
			SSL_CTX_set_verify(hd->ctx, SSL_VERIFY_NONE, NULL);
		}else{
			SSL_CTX_set_verify(hd->ctx, SSL_VERIFY_PEER, ca_verify_cb);
			SSL_CTX_set_verify_depth(hd->ctx, SSL_DEPTH);
			if(SSL_CTX_load_verify_locations(hd->ctx, hd->cert_path, NULL) != 1) {
				return -1;
			}
		}
		SSL_CTX_set_default_passwd_cb_userdata(hd->ctx, hd->passwd);
		if(SSL_CTX_use_certificate_chain_file(hd->ctx, hd->cert_path) == 1){
			LOG("Load certificate success\n");
		}
		if(SSL_CTX_use_PrivateKey_file(hd->ctx, hd->key_path, SSL_FILETYPE_PEM) == 1) {
			LOG("Load private key success\n");
		}
		if(SSL_CTX_check_private_key(hd->ctx) == 1) {
			LOG("Check private key success\n");
		}
		if((hd->ssl = SSL_new(hd->ctx)) == NULL) {
			LOG("Error: create SSL failure\n");
			return -1;
		}
		if(SSL_set_fd(hd->ssl, hd->sk) != 1) {
			LOG("Error: set SSL fd failure\n");
		}
		if(SSL_connect(hd->ssl) != 1) {
			return -1;
		}
		LOG("Connected to SSL success\n");
	return 0;
}
#endif

void destroy_ssl(struct http_data *hd) {
#ifdef HAVE_OPENSSL
	if(hd->ssl) {
		SSL_set_shutdown(hd->ssl, 2);
		SSL_shutdown(hd->ssl);
		SSL_free(hd->ssl);
	}
	if(hd->ctx) SSL_CTX_free(hd->ctx);
	hd->ssl = NULL;
	hd->ctx = NULL;
#endif
}

void destroy_http(struct http_data *hd) {
	if(hd->sk > 0) {
		close(hd->sk);
		hd->sk = -1;
	}
}

int http_send_req(struct http_data *hd) {
	char	*header;
	int		len;
	header = hd->http.req;
	if(hd->http.req_type == HTTP_GET) {
		len = snprintf(header, HTTP_HEADER_LEN, "GET %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Accept: *\r\n"
				"User-Agent: Kaija Agent\r\n"
				"Cache-Control: no-cache\r\n"
				"Connection: close\r\n"
				"\r\n\r\n", hd->uri.path, hd->uri.host);
	}
	printf("\n=====================\n%s\n=====================\n", header);
	hd->send(hd, header, len);
	return 0;
}

int http_recv_resp(struct http_data *hd) {
	char buf[HTTP_RECV_BUF];
	int len;
	memset(buf, 0, HTTP_RECV_BUF);
	for(;;)
	{
		len = hd->recv(hd, buf, HTTP_RECV_BUF);
		if(len > 0)
			printf("\n=====================\n%s\n=====================\n", buf);
		if(len == 0) break;
	}
	return 0;
}

int http_perform(struct http_data *hd) {
	struct hostent *server = NULL;
	fd_set  fset;
	int err;
	struct timeval tv;
	int ret = 0;
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
	memcpy(&(hd->srv_addr.sin_addr), server->h_addr, sizeof(hd->srv_addr.sin_addr));
	hd->srv_addr.sin_family = AF_INET;
	hd->srv_addr.sin_port = htons(hd->uri.port);
	hd->sk = socket(AF_INET, SOCK_STREAM, 0);
	if(hd->sk < 0) {
		LOG("Error: create socket failure %d\n", hd->sk);
		return -1;
	}
	http_nonblock_socket(hd->sk);
	if(connect(hd->sk, (struct sockaddr *)&(hd->srv_addr), sizeof(struct sockaddr)) == -1 &&
		 errno != EINPROGRESS) {
		LOG("Error: Cannot connect to server\n");
		destroy_http(hd);
		return -1;
	}
	tv.tv_sec = hd->tv.tv_sec;
	tv.tv_usec = 0;
	if( (ret = select(hd->sk + 1, NULL, &fset, NULL, &tv)) > 0) {
		socklen_t elen;
		getsockopt(hd->sk, SOL_SOCKET, SO_ERROR, &err, &elen);
		if(err != 0) {
			LOG("Error: getsocketopt failure\n");
			destroy_http(hd);
			return -1;
		}
	}else{
		LOG("Error: Connection timeout\n");
		destroy_http(hd);
		return -1;
	}
	LOG("Connected to server\n");
	http_block_socket(hd->sk);
	if(hd->uri.proto == PROTO_HTTPS) {
#ifdef HAVE_OPENSSL
		if(http_ssl_setup(hd) == -1){
			destroy_ssl(hd);
			destroy_http(hd);
			return -1;
		}
#endif //HAVE_OPENSSL
	}
	ret = http_send_req(hd);
	if(ret == 0) {
		ret = http_recv_resp(hd);
	}else{
		LOG("Error: send http request error\n");
	}
	return 0;
}

