# TODO:
%define optflags_lto %nil

Name: wine-etersoft-cpcsp_proxy
Version: 0.6.0
Release: alt5

Summary: Proxy for using Linux CryptoPro in Windows applications with Wine

License: LGPLv2
Group: Emulators
URL: https://github.com/Etersoft/wine-cpcsp_proxy

# Source-git: https://github.com/Etersoft/wine-cpcsp_proxy.git
Source: %name-%version.tar

BuildRequires: libwine-devel >= 6.23

ExclusiveArch: %ix86 x86_64

%ifarch x86_64 aarch64
  %def_with build64
  %define winepkgname wine-etersoft-cpcsp_proxy
%else
  %def_without build64
  %define winepkgname wine32-etersoft-cpcsp_proxy
%endif


%define libwinedir %_libdir/wine-etersoft

# TODO: move to rpm-macros-wine
# set arch dependent dirs
%ifarch %{ix86}
%define winepedir i386-windows
%define winesodir i386-unix
%endif
%ifarch x86_64
%define winepedir x86_64-windows
%define winesodir x86_64-unix
%endif
%ifarch %{arm}
%define winepedir arm-windows
%define winesodir arm-unix
%endif
%ifarch aarch64
%define winepedir aarch64-windows
%define winesodir aarch64-unix
%endif

%add_verify_elf_skiplist %libwinedir/%winesodir/cpcsp_proxy.dll.so
%add_verify_elf_skiplist %libwinedir/%winesodir/cpcsp_proxy_setup.exe.so

%ifarch x86_64
%define capilitepkg lsb-cprocsp-capilite-64
%else
%define capilitepkg lsb-cprocsp-capilite
%endif

#Conflicts: wine-p11csp

%description
Proxy for using Linux CryptoPro in Windows applications with wine.

* Using with CryptoPro:
 install %capilitepkg package
* Using with cprocsp_compat (CRYPTO@Etersoft):
 install cprocsp_compat


%if "%winepkgname" != "%name"
%package -n %winepkgname
Group: Emulators
Summary: Proxy for using Linux CryptoPro in Windows applications with Wine

%description -n %winepkgname
Proxy for using Linux CryptoPro in Windows applications with wine.

* Using with CryptoPro:
 install %capilitepkg package
* Using with cprocsp_compat (CRYPTO@Etersoft):
 install cprocsp_compat

%endif


%prep
%setup

%build
%make_build -C cpcsp_proxy
%make_build -C cpcsp_proxy_setup

%install
mkdir -p %buildroot%libwinedir/{%winesodir,%winepedir}

cp cpcsp_proxy/cpcsp_proxy.dll.so %buildroot%libwinedir/%winesodir
cp cpcsp_proxy/cpcsp_proxy.dll %buildroot%libwinedir/%winepedir
cp cpcsp_proxy_setup/cpcsp_proxy_setup.exe.so %buildroot%libwinedir/%winesodir
cp cpcsp_proxy_setup/cpcsp_proxy_setup.exe %buildroot%libwinedir/%winepedir

mkdir -p %buildroot/%_bindir/
cp %_bindir/wineapploader %buildroot/%_bindir/cpcsp_proxy_setup

%files -n %winepkgname
%libwinedir/%winesodir/cpcsp_proxy_setup.exe.so
%libwinedir/%winesodir/cpcsp_proxy.dll.so
%libwinedir/%winepedir/cpcsp_proxy_setup.exe
%libwinedir/%winepedir/cpcsp_proxy.dll
%_bindir/cpcsp_proxy_setup

%changelog
* Wed Jan 25 2023 Vitaly Lipatov <lav@altlinux.ru> 0.6.0-alt5
- put dlls to _libdir/wine-etersoft
- build 64 bit package as wine-etersoft-cpcsp_proxy
- build 32 bit package as wine32-etersoft-cpcsp_proxy

* Wed Jan 25 2023 Vitaly Lipatov <lav@altlinux.ru> 0.6.0-alt4
- upgrade spec to multiname build

* Sat Apr 09 2022 Vitaly Lipatov <lav@altlinux.ru> 0.6.0-alt3
- build and install wine stubs

* Thu Apr 07 2022 Vitaly Lipatov <lav@altlinux.ru> 0.6.0-alt2
- update README.md
- fix Makefile to build package

* Tue Feb 22 2022 Vitaly Lipatov <lav@altlinux.ru> 0.6.0-alt1
- update for wine-6.21
- further adaptation for wine-6.21 build system
- add .dll.so -> .dll link
- update build for wine-7.2

* Tue Oct 06 2020 Vitaly Lipatov <lav@altlinux.ru> 0.5.2-alt1
- add traces to public info converters, verify parameters from the backend
- print information about being saved certificate (eterbug #14660)
- also import CA store from host

* Sat Oct 03 2020 Vitaly Lipatov <lav@altlinux.ru> 0.5.1-alt1
- change debug channel to cpcsp_proxy
- move propid_to_name() to print_id_name.h

* Sat Oct 03 2020 Vitaly Lipatov <lav@altlinux.ru> 0.5-alt2
- add README.md
- update description

* Thu Oct 01 2020 Vitaly Lipatov <lav@altlinux.ru> 0.5-alt1
- cpcsp_proxy_setup: Add explicit __cdecl to main() for 64-bit compatibility
- cpcsp_proxy_setup: allow loading both libcapi10 and libcapi20
- cpcsp_proxy_setup.c: load CryptEnumProvidersA from libcapi10

* Sat Sep 12 2020 Vitaly Lipatov <lav@altlinux.ru> 0.4-alt1
- rewrite spec
- cleanup makefiles
- replace wine_dl* with dl*
- drop strip binary

* Tue Jul 14 2020 Vitaly Lipatov <lav@altlinux.ru> 0.3-alt2
- x86_64 build

* Mon Sep 16 2019 Vitaly Lipatov <lav@altlinux.ru> 0.3-alt1
- cpcsp_proxy_setup: Also add the "Provider Types" key for a being added provider

* Fri Jul 19 2019 Vitaly Lipatov <lav@altlinux.ru> 0.2-alt2
- add Conflicts: wine-p11csp

* Thu Jun 27 2019 Vitaly Lipatov <lav@altlinux.ru> 0.2-alt1
- cpcsp_proxy_setup: Various fixes
- cpcsp_proxy: Fix calling convention for CryptoPro provided APIs
- cpcsp_proxy: Pass cpcsp_proxy.spec to winegcc in order to build correct PE exports
- cpcsp_proxy_setup: Add support for certificates with strings in cp1251

* Mon May 20 2019 Konstantin Kondratyuk <kondratyuk@altlinux.ru> 0.1-alt1
- initial build for ALT Sisyphus
