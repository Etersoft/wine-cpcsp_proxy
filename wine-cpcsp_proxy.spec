Name: wine-cpcsp_proxy
Version: 0.1
Release: alt1

Summary: Proxy for using native CryptoPro in Windows applications with wine

License: Proprietary
Group: Emulators

Source: %name-%version.tar

%description
Proxy for using native CryptoPro in Windows applications with wine.

BuildRequires: libwine-devel wine

%set_verify_elf_method textrel=relaxed

%prep
%setup

%build

%install
mkdir -p %buildroot/usr/lib/wine
cp bin/* %buildroot/usr/lib/wine
mkdir -p %buildroot/usr/bin
cp /usr/bin/winepath %buildroot/usr/bin/cpcsp_proxy_setup

%files
/usr/lib/wine/cpcsp_proxy_setup.exe.so
/usr/lib/wine/cpcsp_proxy.dll.so
/usr/bin/cpcsp_proxy_setup

%changelog
* Mon May 20 2019 Konstantin Kondratyuk <kondratyuk@altlinux.ru> 0.1-alt1
- initial build for ALT Sisyphus
