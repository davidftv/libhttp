#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "http.h"
#include <openssl/md5.h>


struct http_data *http_create() {
	int i = 0;
    struct http_data *hd = malloc(sizeof(struct http_data));
    memset(hd, 0, sizeof(struct http_data));
	hd->http.body.start = NULL;
	for(i = 0; i < HTTP_HEADER_NUM ; i++) {
		hd->http.header[i] = NULL;
	}
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

char *http_skip_break(char *ptr)
{
	while(*ptr == '\r' || *ptr == '\n') ptr ++;
	return ptr;
}

char *http_skip_blank(char *ptr)
{
    while(*ptr == ' ') ptr ++;

    return ptr;
}

int http_find_header(struct http_data *hd, char *title, char *out) {
    int count = 0;
    char *header = NULL;
    char *ptr = NULL;
    if(title == NULL || out == NULL) return -1;
    for(count = 0; count < hd->http.header_count; count ++){
        header = hd->http.header[count];
        if(strncasecmp(header, title, strlen(title)) == 0){
            if((ptr = strchr(header, ':')) != NULL) {
                ptr ++;
                ptr = http_skip_blank(ptr);
                strcpy(out, ptr);
            }
            return 0;
        }
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
                //LOG("Error: receive data failure %s\n", strerror(errno));
                return ret;
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
                //LOG("Error: receive data failure %s\n", strerror(errno));
                return ret;
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
#ifdef HAVE_OPENSSL
            hd->send = https_send;
            hd->recv = https_recv;
#else
            return -1;
#endif // HAVE_OPENSSL
        }else if(strncasecmp(hd->uri.server, "http://", 7) == 0){
            hd->uri.proto = PROTO_HTTP;
            host = serv + strlen("http://");;
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
    char data[SSL_DATA_LEN];
    if(!ok) {
        cert = X509_STORE_CTX_get_current_cert(store);
        depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);
        LOG("Error with certificate at depth: %i", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, SSL_DATA_LEN);
        LOG(" issuer = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, SSL_DATA_LEN);
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


void http_clean_hd(struct http_data *hd)
{
	if(hd == NULL) return;
    int i = 0;
    for (i = 0; i < hd->http.header_count; i++) {
        if(hd->http.header[i] != NULL) {
            free(hd->http.header[i]);
            hd->http.header[i] = NULL;
        }
    }
    if(hd->http.body.start != NULL) {
        free(hd->http.body.start);
        hd->http.body.start = NULL;
    }

    hd->http.body.size = 0;
}
void http_destroy_hd(struct http_data *hd) {
	http_clean_hd(hd);
	free(hd);
}

int http_set_user_pass(struct http_data *hd, char *user, char *pass)
{
	if(hd!=NULL && user!=NULL && pass!=NULL) {
		strncpy(hd->username, user, HTTP_USER_LEN);
		strncpy(hd->password, pass, HTTP_PASS_LEN);
		return 0;
	}
	return -1;
}
int http_copy_field(char *in, char *out, int len)
{
	int count = 0;
	if(in != NULL && out != NULL) {
		for(count = 0; count < len; count ++) {
			if(in[count] != '"') {
				out[count] = in[count];
			}else{
				break;
			}
		}
		return 0;
	}
	return -1;
}
int http_parse_auth(struct http_data *hd)
{
	char *ptr;
	char *realm;
	char *nonce;
	char auth_str[HTTP_AUTH_LEN];
	if(http_find_header(hd, "WWW-Authenticate", auth_str)==0) {
		ptr = auth_str;
		if(strncmp(auth_str, "Digest", strlen("Digest") )==0) {
			strcpy(hd->http.auth,"Digest");
			if((realm = strstr(ptr, "realm")) != NULL) {
				realm = realm + strlen("realm:\"");
				http_copy_field(realm, hd->http.realm, HTTP_AUTH_LEN);
			}
			if((nonce = strstr(ptr, "nonce")) != NULL) {
				nonce = nonce + strlen("nonce:\"");
				http_copy_field(nonce, hd->http.nonce, HTTP_AUTH_LEN);
			}
		}else if(strncmp(auth_str, "Basic", strlen("Basic") )==0) {
			strcpy(hd->http.auth,"Basic");
		}
	}
	return 0;
}

int http_set_method(struct http_data *hd, int type)
{
	if(hd == NULL || type < HTTP_GET || type > HTTP_DELETE) {
		return -1;
	}
	hd->http.req_type = type;
	return 0;
}

int http_send_req(struct http_data *hd) {
    char    *header;
    int     len;
    header = hd->http.req;
    if(hd->http.req_type == HTTP_GET) {
        len = snprintf(header, HTTP_HEADER_LEN, "GET %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Accept: */*\r\n"
                "User-Agent: Kaija/Agent\r\n"
                "\r\n\r\n", hd->uri.path, hd->uri.host,hd->uri.port);
    }else if(hd->http.req_type == HTTP_POST) {
        len = snprintf(header, HTTP_HEADER_LEN, "POST %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Accept: */*\r\n"
                "User-Agent: Kaija/Agent\r\n"
                "\r\n", hd->uri.path, hd->uri.host, hd->uri.port);
    }
#ifdef DEBUG_HTTP
	LOG(">>>>>>>>>>>>>>>>>>\n%s\n>>>>>>>>>>>>>>>>>>\n", header);
#endif
    hd->send(hd, header, len);
    return 0;
}

int http_md5sum(char *input, int len, char *out)
{
    int ret = 0, i = 0;
    MD5_CTX ctx;
    char buf[3] = {'\0'};
    unsigned char md5[MD5_DIGEST_LENGTH];
    if(input == NULL || len < 1 || out == NULL)
        return -1;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, len);
    MD5_Final(md5, &ctx);
    out[0] = '\0';
    for(i=0;i<MD5_DIGEST_LENGTH;i++)
    {
        sprintf(buf, "%02x", md5[i]);
        strcat(out, buf);
    }
    //LOG("MD5:[%s]\n", out);DER_LEN
    return ret;
}

int http_send_auth_req(struct http_data *hd) {
    char    *header;
    int     len;
	char	ha1[HTTP_NONCE_LEN];
	char	ha2[HTTP_NONCE_LEN];
	char	response[HTTP_NONCE_LEN];
	char	cnonce[HTTP_NONCE_LEN];
	char	str[HTTP_HEADER_LEN];
	memset(cnonce, 0, HTTP_NONCE_LEN);
	memset(str, 0, HTTP_HEADER_LEN);
	len = sprintf(cnonce, "%s:%s:%s",hd->username, hd->http.realm, hd->password);
	http_md5sum(cnonce, len ,ha1);

    header = hd->http.req;
    if(hd->http.req_type == HTTP_GET) {
		memset(str, 0, HTTP_HEADER_LEN);
		len = sprintf(str, "GET:%s",hd->uri.path);
		http_md5sum(str, len ,ha2);
		memset(cnonce, 0, HTTP_NONCE_LEN);
		sprintf(cnonce, "%lld", (long long)time(NULL));
		http_md5sum(cnonce, strlen(cnonce), cnonce);
		memset(str, 0, HTTP_HEADER_LEN);
		len = sprintf(str, "%s:%s:00000001:%s:%s:%s",ha1, hd->http.nonce, cnonce, "auth",ha2);
		http_md5sum(str, len ,response);


		//http_md5sum(str, len ,cnonce);
        len = snprintf(header, HTTP_HEADER_LEN,
			"GET %s HTTP/1.1\r\n"
			"Authorization: %s username=\"%s\", realm=\"%s\","
			"nonce=\"%s\", uri=\"%s\","
			"cnonce=\"%s\", nc=00000001, qop=auth,"
			"response=\"%s\"\r\n"
            "User-Agent: Kaija/Agent\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n\r\n\r\n",
			hd->uri.path,
			hd->http.auth, hd->username, hd->http.realm,
			hd->http.nonce, hd->uri.path,
			cnonce,
			response,
			hd->uri.host,hd->uri.port);
    }else if(hd->http.req_type == HTTP_POST) {
		memset(str, 0, HTTP_HEADER_LEN);
		len = sprintf(str, "POST:%s",hd->uri.path);
		http_md5sum(str, len ,ha2);
		memset(cnonce, 0, HTTP_NONCE_LEN);
		sprintf(cnonce, "%lld", (long long)time(NULL));
		http_md5sum(cnonce, strlen(cnonce), cnonce);
		memset(str, 0, HTTP_HEADER_LEN);
		len = sprintf(str, "%s:%s:00000001:%s:%s:%s",ha1, hd->http.nonce, cnonce, "auth",ha2);
		http_md5sum(str, len ,response);


		//http_md5sum(str, len ,cnonce);
        len = snprintf(header, HTTP_HEADER_LEN,
			"POST %s HTTP/1.1\r\n"
			"Authorization: %s username=\"%s\", realm=\"%s\","
			"nonce=\"%s\", uri=\"%s\","
			"cnonce=\"%s\", nc=00000001, qop=auth,"
			"response=\"%s\"\r\n"
            "User-Agent: Kaija/Agent\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n\r\n\r\n",
			hd->uri.path,
			hd->http.auth, hd->username, hd->http.realm,
			hd->http.nonce, hd->uri.path,
			cnonce,
			response,
			hd->uri.host,hd->uri.port);
    }
#ifdef DEBUG_HTTP
	LOG(">>>>>>>>>>>>>>>>>>\n%s\n>>>>>>>>>>>>>>>>>>\n", header);
#endif
    hd->send(hd, header, len);
    return 0;
}

int http_add_header(struct http_data *hd, char *header)
{
    char *ver;
    char *code;
    char *phrase;
    if(header) {
        if(strncmp(header, "HTTP/", strlen("HTTP/"))==0) {
            ver = header + 5;
            code = ver;
            while(!isspace(*code)) code ++;
            *code = '\0';
            strcpy(hd->http.version, ver);

            code ++;
            while(isspace(*code))  code++;//skip blank
            phrase = code + 1;
            while(!isspace(*phrase)) phrase ++;
            *phrase = '\0';
            strcpy(hd->http.code, code);

            phrase ++;
            strcpy(hd->http.phrase, phrase);
        }else{
            hd->http.header[hd->http.header_count++] = strdup(header);
        }
    }
    return 0;
}
char *http_skip2break(char *ptr)
{
	while(*ptr != '\r') ptr ++;
	return ptr;
}
int http_recv_resp(struct http_data *hd) {
	char	content_len[HTTP_HEADER_LEN];
    char    buf[HTTP_RECV_BUF];
    //char    *head  = buf;
    char    *start = buf;
    int     len;
    char    *header;
    char    *next_line;
    int     header_parsed = 0;
    int     read_count = 0;
    for(;;)
    {
        memset(buf, 0, HTTP_RECV_BUF);
        len = hd->recv(hd, buf, HTTP_RECV_BUF);
        if(len > 0){
#ifdef DEBUG_HTTP
			printf("<<<<<<<<<<<<<<<<<<\n%s\n<<<<<<<<<<<<<<<<<<<<\n",buf);
#endif
            if(header_parsed == 0) {
                while( (next_line = strstr(start, "\r\n")) != NULL )  {
                    header_parsed = 1;
                    *next_line = '\0';
                    next_line += 2;
                    header = start;
                    if(*header == '\0'){
                        break;
                    }else{
                        http_add_header(hd, header);
                    }
                    start = next_line;
                }
                if(header_parsed  == 1){
					http_find_header(hd, "Transfer-Encoding", content_len);
					if(strncmp(content_len, "chunked", strlen("chunked")) == 0) {
						hd->http.chunked = 1;
					}
                    start = next_line;
					long chunk = strtol(start, NULL, 16);
					start = http_skip2break(start);
					start = http_skip_break(start);
                    hd->http.body.size = chunk;
                    hd->http.body.start = malloc(hd->http.body.size);
                    if(hd->http.body.start){
                        memcpy(hd->http.body.start, start , hd->http.body.size);
						hd->http.body.start[hd->http.body.size] = '\0';
                    }
                }
            }else{
				if(hd->http.body.start == NULL) {
					char *ptr = malloc(len + 1);
					hd->http.body.start = ptr;
					memcpy(hd->http.body.start, buf, len);
					hd->http.body.size += len;
					hd->http.body.start[hd->http.body.size] = '\0';
				}else{
					char *ptr = realloc(hd->http.body.start, hd->http.body.size + len);
					hd->http.body.start = ptr;
					memcpy(ptr + hd->http.body.size , buf, len);
					hd->http.body.size += len;
					hd->http.body.start[hd->http.body.size] = '\0';
				}
            }
			if(len < HTTP_RECV_BUF) break;
        }else{
			break;
		}
        read_count ++;
    }
    return 0;
}

int http_perform(struct http_data *hd) {
    struct hostent *server = NULL;
    int ret = 0;
    char loc[HTTP_HOST_LEN];
    if(http_host_parse(hd) != 0) {
        LOG("Error: URL parsing error!\nHOST:%s\nPORT:%d\nPATH:%s\n",
            hd->uri.host, hd->uri.port, hd->uri.path);
#ifdef DEBUG
    }else{
        LOG("Connect to\nHOST:%s\nPORT:%d\nPATH:%s\n",
            hd->uri.host, hd->uri.port, hd->uri.path);
#endif
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
    //http_nonblock_socket(hd->sk);
    if(connect(hd->sk, (struct sockaddr *)&(hd->srv_addr), sizeof(struct sockaddr)) == -1 &&
         errno != EINPROGRESS) {
        LOG("Error: Cannot connect to server\n");
        destroy_http(hd);
        return -1;
    }
    if(hd->uri.proto == PROTO_HTTPS) {
#ifdef HAVE_OPENSSL
        if(http_ssl_setup(hd) == -1){
            destroy_ssl(hd);
            destroy_http(hd);
            return -1;
        }
#endif //HAVE_OPENSSL
    }
	struct http_data *hd2 = NULL;
    for(;;) {
        ret = http_send_req(hd);
        if(ret == 0) {
            ret = http_recv_resp(hd);
            if(ret == 0){
                int code = atoi(hd->http.code);
                switch(code){
                    case 302:
                        LOG("GOT 302 redirect\n");
                        memset(loc, 0, HTTP_HOST_LEN);
                        http_find_header(hd, "Location:", loc);
                        hd2 = http_create();

                        http_set_uri(hd2, loc);
                        http_perform(hd2);
						//if(hd->http.body.start != NULL) free(hd->http.body.start);

						hd->http.body.start = malloc(hd2->http.body.size);
						memcpy(hd->http.body.start, hd2->http.body.start, hd2->http.body.size);
                        http_destroy_hd(hd2);
                        break;
                    case 200:
						break;
                    case 401:
						LOG("GOT 401 Unauthorized\n");
						http_parse_auth(hd);
						ret = http_send_auth_req(hd);
						if(ret == 0) {
							ret = http_recv_resp(hd);
						}
						break;
                    case 404:
                        break;
                    default:
                        break;
                }
                break;
            }
        }else{
            LOG("Error: send http request error\n");
        }
    }
    return 0;
}

