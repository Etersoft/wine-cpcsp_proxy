WINEARCH =
WINEGCC = winegcc $(WINEARCH)
CFLAGS	= -g -O2 -fPIC -Wall -D__WINESRC__ -shared
IMPORTS	= kernel32 ntdll
LIBS	= $(IMPORTS:%=-l%) -ldl
DEPS	= Makefile api_hook.h
OBJ	= api_hook.o proxy.o cpcsp_proxy.spec

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

all: cpcsp_proxy.dll.so cpcsp_proxy.dll
	

cpcsp_proxy.dll.so: $(OBJ)
	$(WINEGCC) -o $@ $^ -shared $(CFLAGS) $(LIBS)
	#ln -s $@ cpcsp_proxy.dll
	#strip $@

cpcsp_proxy.dll: cpcsp_proxy.spec
	$(WINEGCC) -o $@ -Wb,--fake-module -shared $^ -mno-cygwin

clean:
	rm -f *.o *.dll.so
