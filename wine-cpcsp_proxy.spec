Name: libwine-etersoft-cpcsp
Version: 0.1
Release: alt1

Summary: Proxy for using native cpcsp in windows applications with wine
License: Proprietary
Group: Emulators
Url: http://etersoft.ru
Source: %name-%version.tar

%description
Proxy for using native cpcsp in windows applications with wine.

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
- initial build for ALT Linux Sisyphus
