Name: wine-cpcsp_proxy
Version: 0.3
Release: alt1

Summary: Proxy for using native CryptoPro in Windows applications with wine

License: Proprietary
Group: Emulators

Source: %name-%version.tar

BuildRequires: libwine-devel wine

Conflicts: wine-p11csp

%add_verify_elf_skiplist /usr/lib/wine/cpcsp_proxy.dll.so
%add_verify_elf_skiplist /usr/lib/wine/cpcsp_proxy_setup.exe.so

%description
Proxy for using native CryptoPro in Windows applications with wine.


%prep
%setup

%build
cd cpcsp_proxy/
%make_build
cd ../cpcsp_proxy_setup/
%make_build

%install
mkdir -p %buildroot/usr/lib/wine
cp cpcsp_proxy/cpcsp_proxy.dll.so %buildroot/usr/lib/wine
cp cpcsp_proxy_setup/cpcsp_proxy_setup.exe.so %buildroot/usr/lib/wine
mkdir -p %buildroot/usr/bin
cp /usr/bin/winepath %buildroot/usr/bin/cpcsp_proxy_setup

%files
/usr/lib/wine/cpcsp_proxy_setup.exe.so
/usr/lib/wine/cpcsp_proxy.dll.so
/usr/bin/cpcsp_proxy_setup

%changelog
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
