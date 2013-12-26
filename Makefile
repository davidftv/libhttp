

OBJS=http.o main.o
EXEC=httptest.exe

CFLAGS  =  	-DHAVE_OPENSSL
CFLAGS  +=  -DDEBUG_HTTP
CFLAGS  += 	-Wall
LDFLAGS =	-lssl

all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(CFLAGS) $(LDFLAGS)


clean:
	rm *.o $(EXEC) -rf
