CC=winegcc
#CFLAGS=-I../../wine/include -D__WINESRC__ -Wall
CFLAGS=-Wall -D__WINESRC__
OBJ=cpcsp_proxy_setup.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy_setup.exe: $(OBJ)
	$(CC) -o $@ $^ -mconsole $(CFLAGS)

clean:
	rm -f *.o *.exe
