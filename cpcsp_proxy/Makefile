WINEARCH =
WINEGCC	= winegcc $(WINEARCH)
CFLAGS	= -g -O2 -fPIC -Wall -D__WINESRC__
DEPS	= Makefile api_hook.h
OBJ	= api_hook.o proxy.o cpcsp_proxy.spec

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy.dll.so: $(OBJ)
	$(WINEGCC) -o $@ $^ -shared $(CFLAGS)
	strip $@

clean:
	rm -f *.o *.dll.so
