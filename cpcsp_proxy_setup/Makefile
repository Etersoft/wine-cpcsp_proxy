WINEARCH = 
WINEGCC	= winegcc $(WINEARCH)
CFLAGS	= -g -fPIC -O2 -Wall -D__WINESRC__
LIBS	= -lkernel32 -ladvapi32 -lcrypt32 -ldl
OBJ	= cpcsp_proxy_setup.o
DEPS	= Makefile

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy_setup.exe: $(OBJ)
	$(WINEGCC) -o $@ $^ -mconsole $(CFLAGS) $(LIBS)
	strip $@.so

clean:
	rm -f *.o *.exe *.exe.so
