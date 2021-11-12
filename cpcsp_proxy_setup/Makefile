WINEARCH = -m32
SRCDIR	= ../../../wine.src
WINEGCC	= ../../tools/winegcc/winegcc $(WINEARCH) --wine-objdir ../.. -I $(SRCDIR)/include
CFLAGS	= -g -fPIC -O2 -Wall -D__WINESRC__
IMPORTS	= advapi32 crypt32 kernel32 ntdll
LIBS	= $(IMPORTS:%=-L../%) $(IMPORTS:%=-l%) -ldl
OBJ	= cpcsp_proxy_setup.o
DEPS	= Makefile

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy_setup.exe: $(OBJ)
	$(WINEGCC) -o $@ $^ -mconsole -mcygwin $(CFLAGS) $(LIBS)
	#strip $@.so

clean:
	rm -f *.o *.exe *.exe.so
