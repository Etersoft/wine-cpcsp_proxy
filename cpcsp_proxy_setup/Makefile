#CC	= winegcc -m64
CC	= winegcc
CFLAGS	= -O2 -Wall -D__WINESRC__
OBJ	= cpcsp_proxy_setup.o
DEPS	= Makefile

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy_setup.exe: $(OBJ)
	$(CC) -o $@ $^ -mconsole $(CFLAGS) -lkernel32 -ladvapi32 -lcrypt32
	strip $@.so

clean:
	rm -f *.o *.exe *.exe.so
