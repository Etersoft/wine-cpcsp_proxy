WINEARCH = -m32
SRCDIR	= ../../../wine.src
WINEGCC	= ../../tools/winegcc/winegcc $(WINEARCH) --wine-objdir ../.. -I$(SRCDIR)/include
CFLAGS	= -g -O2 -fPIC -Wall -D__WINESRC__ -shared
IMPORTS	= kernel32 ntdll
LIBS	= $(IMPORTS:%=-L../%) $(IMPORTS:%=-l%) -ldl
DEPS	= Makefile api_hook.h
OBJ	= api_hook.o proxy.o cpcsp_proxy.spec

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy.dll.so: $(OBJ)
	$(WINEGCC) -o $@ $^ -shared $(CFLAGS) $(LIBS)
	#strip $@

clean:
	rm -f *.o *.dll.so
