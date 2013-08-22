#include <stdio.h>
#include <stdlib.h>
#include "http.h"

int main()
{
	struct http_data *hd = http_create();
	http_set_uri(hd, "https://www.google.com/");
	//http_set_uri(hd, "http://www.securepilot.com/");
	http_perform(hd);
	return 0;
}
