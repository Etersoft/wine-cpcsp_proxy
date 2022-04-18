
# cpcsp_proxy

ГОСТ-криптопровайдер для wine, использующий нативные библиотеки CryptoPro
(для 32-битных программ требуется установка 32-битных библиотек CryptoPro).

Также может использоваться с cprocsp_compat из состава CRYPTO@Etersoft.

## Установка

Пакеты подготовлены для ALT p9. По поводу других систем создавайте Issue.

Для 32-битных программ в wine:
 $ epmi ecryptomgr i586-wine-cpcsp_proxy

Для 64-битных программ в wine:
 $ epmi ecryptomgr wine-cpcsp_proxy

Устанавливаем CryptoPro:
 $ ecryptomgr install cryptopro both
(подробнее смотрите в описании https://github.com/Etersoft/ecryptomgr)


## Настройка

Настраиваем cpcsp_proxy:
 $ cpcsp_proxy_setup

После этого в wine будут работать программы, использующие ГОСТ-криптографию, включая CadesPlugin (он же КриптоПро ЭЦП Browser plug-in).
Конечно, CadesPlugin устанавливается в wine отдельно.

## Сборка

В общем виде сборка осуществляется командой
 $ make

Вам понадобится установленный libwine-devel.
