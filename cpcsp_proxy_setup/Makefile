WINEARCH =
WINEGCC = winegcc $(WINEARCH)
CFLAGS	= -g -fPIC -O2 -Wall -D__WINESRC__
IMPORTS	= advapi32 crypt32 kernel32 ntdll
LIBS	= $(IMPORTS:%=-l%) -ldl
OBJ	= cpcsp_proxy_setup.o
DEPS	= Makefile

%.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

all: cpcsp_proxy_setup.exe.so cpcsp_proxy_setup.exe
	

cpcsp_proxy_setup.exe.so: $(OBJ)
	$(WINEGCC) -o $@ $^ -mconsole -municode -mcygwin $(CFLAGS) $(LIBS)
	#strip $@.so

cpcsp_proxy_setup.exe:
	$(WINEGCC) -o $@ -Wb,--fake-module -mconsole -municode -mno-cygwin $(CFLAGS)

clean:
	rm -f *.o *.exe *.exe.so
