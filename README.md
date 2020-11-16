# А — Д: библиотека для чекеров

Библиотека для написания чекеров на Attack-Defense для [жюрейки Хакердома](https://github.com/hackerdom/checksystem).

## Пример чекера

```python
from adchecklib import BaseChecker, OK

class MyChecker(BaseChecker):
    def __init__(self):
        super().__init__(vulns=[2, 1])

    def put(self, host, flag_id, flag, vuln):
        raise OK

    def get(self, host, flag_id, flag, vuln):
        raise OK

    def check(self, host):
        raise OK

MyChecker().run()
```

## Описание

### `__init__`

Нужно корректно инициализировать родительский класс:

```python
super().__init__()
```

Опционально можно передать keyword-аргумент `vulns` (по умолчанию — `[1]`). При наличии нескольких мест для хранения флагов он задаёт отношение флагов в этих местах. Например, `vulns=[1, 2, 3]` кладёт половину флагов третьего типа, треть флагов второго типа и шестую часть флагов первого типа. Номера уязвимостей считаются, начиная с единицы.

### Вердикты

Из всех следующих функций вы должны бросить исключение с результатом проверки:

* `OK` — проверка завершена успешно
* `Corrupt` — сервис работает, но невозможно получить флаг
* `Down` — сервис работает некорректно или не работает

В исключения `Corrupt` и `Down` можно передавать аргумент — сообщение, которое будет показано участнику в скорборде.

### Логгирование

Используйте `self.logger` для логгирования ошибок. Например: `self.logger.info('Service returned %s', data)`. Эта информация будет доступна в админке жюрейки.

### put

В этой функции нужно положить флаг. Аргументы:

* `host` — IP-адрес или хостнейм вулнбокса
* `flag_id` — уникальный идентификатор флага
* `flag` — значение флага
* `vuln` — номер уязвимости (1, если `vulns` не используется)

В будущем вам понадобится доставать флаг, используя лишь `flag_id`. Вы можете заменить этот идентификатор на другой (например, логин с паролем): для этого бросьте исключение `SetFlagID(new_flag_id)` вместо `OK`.

### get

В этой функции нужно проверить флаг. Аргументы:

* `host` — IP-адрес или хостнейм вулнбокса
* `flag_id` — уникальный идентификатор флага
* `flag` — значение флага
* `vuln` — номер уязвимости (1, если `vulns` не используется)

В качестве `flag_id` передаётся то же значение, что и в `put`, если вы бросили `OK`, или выведенное вами значение, если вы бросили `SetFlagID`.

### check

Проверьте работоспособность функционала сервиса. Аргументы:

* `host` — IP-адрес или хостнейм вулнбокса
