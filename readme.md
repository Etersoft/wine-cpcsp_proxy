Сборка в составе кода Wine

1. Скопировать содержимое cpcsp_proxy_setup в wine/programs/cpcsp_proxy_setup
2. Выполнить git add programs/cpcsp_proxy_setup
3. Скопировать содержимое cpcsp_proxy в wine/dlls/cpcsp_proxy
4. Выполнить git add dlls/cpcsp_proxy
5. Выполнить ./tools/make_makefiles, чтобы обновить configure.
6. Выполнить ./configure
7. Выполнить make
