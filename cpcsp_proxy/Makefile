#CC	= winegcc -m64
CC	= winegcc
CFLAGS	= -O2 -Wall -D__WINESRC__
DEPS	= Makefile api_hook.h
OBJ	= api_hook.o proxy.o cpcsp_proxy.spec

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy.dll.so: $(OBJ)
	$(CC) -o $@ $^ -shared $(CFLAGS)
	strip $@

clean:
	rm -f *.o *.dll.so
