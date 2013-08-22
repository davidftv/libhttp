

OBJS=http.o main.o
EXEC=httptest.app

CFLAGS  =  	-DHAVE_OPENSSL
CFLAGS  +=  -DDEBUG_HTTP
CFLAGS  += 	-Wall
LDFLAGS =	-lssl

all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(CFLAGS) $(LDFLAGS)


clean:
	rm *.o $(EXEC) -rf
