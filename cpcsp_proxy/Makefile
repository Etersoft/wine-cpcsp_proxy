CC=winegcc
#CFLAGS=-I../../wine/include -D__WINESRC__ -Wall
CFLAGS=-I/usr/include/wine
DEPS=api_hook.h
OBJ=api_hook.o proxy.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy.dll.so: $(OBJ)
	$(CC) -o $@ $^ -shared $(CFLAGS)

clean:
	rm -f *.o *.dll.so
