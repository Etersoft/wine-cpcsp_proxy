Сборка в составе кода Wine

1. скопировать содержимое cpcsp_proxy_setup в wine/programs/cpcsp_proxy_setup
2. выполнить git add programs/cpcsp_proxy_setup
3. скопировать содержимое dll в wine/dlls/cpcsp_proxy
4. выполнить git add dlls/cpcsp_proxy
5. выполнить ./tools/make_makefiles чтобы обновить configure.
6. выполнить ./configure
7. выполнить make
