Name: wine-cpcsp_proxy
Version: 0.1
Release: alt1

Summary: Proxy for using native CryptoPro in Windows applications with wine

License: Proprietary
Group: Emulators

Source: %name-%version.tar

BuildRequires: libwine-devel wine

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
* Mon May 20 2019 Konstantin Kondratyuk <kondratyuk@altlinux.ru> 0.1-alt1
- initial build for ALT Sisyphus
