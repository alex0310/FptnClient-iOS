# FptnProbe

Небольшой Linux-инструмент для живой проверки `FptnCore` без macOS/Xcode.
Он читает FPTN-токен из окружения или файла, логинится на сервер, получает DNS,
открывает TLS/WebSocket/YAFF-туннель и отправляет DNS-запрос через выданный IP.

## Запуск

```bash
cd Tools/LiveProbe
swift run FptnProbe
```

Токен передаётся одним из двух способов:

```bash
FPTN_LIVE_TOKEN='fptnb:...' swift run FptnProbe
```

```bash
chmod 600 /path/to/fptn-token
FPTN_LIVE_TOKEN_FILE=/path/to/fptn-token swift run FptnProbe
```

Токен не записывается в репозиторий и не печатается в выводе.

## Параметры

- `FPTN_LIVE_MODE` — `plain`, `obfuscated` или `reality`. По умолчанию:
  `reality` для censored-серверов и `obfuscated` для остальных.
- `FPTN_LIVE_SERVER` — имя или host сервера из токена, например `Greece-1`
  или `45.143.94.199`.
- `FPTN_LIVE_CLIENT=1` — проверить полный `FPTNClient`: login race, DNS,
  пул из двух туннелей и DNS через пул.

Примеры:

```bash
FPTN_LIVE_TOKEN_FILE=/tmp/fptn-token \
  FPTN_LIVE_MODE=plain FPTN_LIVE_SERVER=Greece-1 \
  swift run FptnProbe

FPTN_LIVE_TOKEN_FILE=/tmp/fptn-token \
  FPTN_LIVE_MODE=reality FPTN_LIVE_SERVER=Russia-Moscow \
  FPTN_LIVE_CLIENT=1 \
  swift run FptnProbe
```

## Что проверяется

- разбор `fptnb:`/Brotli-токена;
- login и DNS через HTTP API;
- TLS 1.3 в выбранном режиме маскировки;
- WebSocket upgrade;
- YAFF handshake и выдача IPv4/IPv6;
- отправка DNS-пакета через туннель и получение ответа;
- при `FPTN_LIVE_CLIENT=1` — login race и rolling pool из двух соединений.

Инструмент не заменяет iOS smoke-тест: NetworkExtension, маршруты и On-Demand
по-прежнему проверяются только на macOS/iOS.
