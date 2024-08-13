MODULE   = cpcsp_proxy.dll
UNIXLIB  = cpcsp_proxy.so
# -m32
CROSSBUILD =
LIBDIR = /usr/lib
UNIXGCC  = gcc $(CROSSBUILD) -DWINE_UNIX_LIB -fPIC -I/usr/include/wine/windows
ifeq ($(LIBDIR),/usr/lib)
WINEARCH = i686-windows
UNIXARCH = i386-unix
else
WINEARCH = x86_64-windows
UNIXARCH = x86_64-unix
endif
WINELIBDIR = $(LIBDIR)/wine-etersoft
WINEGCC  = winegcc -b $(WINEARCH) -D__WINE_PE_BUILD
CFLAGS   = -g -O2 -Wall -D__WINESRC__
IMPORTS  = ntdll kernel32 crypt32 advapi32
LIBS     = $(IMPORTS:%=-l%)
UNIXLIBS = -ldl $(WINELIBDIR)/$(UNIXARCH)/ntdll.so
DEPS     = Makefile api_hook.h
UNIXDEPS = Makefile api_hook.h unixlib.h
OBJ      = convert.cross.o api_hook.cross.o proxy.cross.o cpcsp_proxy.spec
UNIXOBJ  = unixlib.o

all: cpcsp_proxy.so cpcsp_proxy.dll

%.cross.o: %.c $(DEPS)
	$(WINEGCC) -c -o $@ $< $(CFLAGS)

%.o: %.c $(UNIXDEPS)
	$(UNIXGCC) -c -o $@ $< $(CFLAGS)

cpcsp_proxy.so: $(UNIXOBJ)
	$(UNIXGCC) -o $@ $^ -shared $(CFLAGS) $(UNIXLIBS)
	#strip $@

cpcsp_proxy.dll: $(OBJ)
	$(WINEGCC) -o $@ $^ -shared -Wl,--wine-builtin $(CFLAGS) $(LIBS)
	#strip $@

clean:
	rm -f *.o *.so *.dll *.lib
