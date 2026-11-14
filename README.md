# FPTN iOS

[![CI](https://github.com/alex0310/FptnClient-iOS/actions/workflows/ci.yml/badge.svg)](https://github.com/alex0310/FptnClient-iOS/actions/workflows/ci.yml)

Независимый Swift-клиент FPTN для iOS: собственный TLS 1.3, YAFF/WebSocket,
rolling pool из двух или трёх туннелей, split tunnel и оригинальный SwiftUI-интерфейс
с двумя темами оформления.

Репозиторий намеренно разделён на две части:

- `FptnCore` — платформонезависимый Swift Package. Его можно собрать и протестировать
  на Linux и macOS без Xcode. Здесь живут протокол, TLS, HTTP/WebSocket, пул,
  split tunnel, NTP и оркестрация клиента.
- `App/`, `Tunnel/` — iOS-приложение и NetworkExtension. Они требуют macOS,
  Xcode и подписанный provisioning profile.
- `FptnShared` — небольшой общий пакет для настроек, Keychain-абстракции и
  встроенного списка доменов split tunnel; его использует и приложение, и
  расширение.

## Быстрый старт

### Только ядро

```bash
swift test
```

На текущей машине Swift установлен в `/home/vasek/opt/swift-6.4.2/usr/bin/swift`:

```bash
/home/vasek/opt/swift-6.4.2/usr/bin/swift test --package-path /home/vasek/FptnClient-iOS
```

### Живая проверка ядра

```bash
FPTN_LIVE_TOKEN_FILE=/path/to/fptn-token \
  swift run --package-path Tools/LiveProbe FptnProbe
```

Подробности — в [Tools/LiveProbe/README.md](Tools/LiveProbe/README.md).

### iOS-приложение

```bash
brew install xcodegen
xcodegen generate
open FptnClient.xcodeproj
```

Перед запуском на устройстве замените placeholder-идентификаторы:

- bundle id приложения: `com.example.fptnclient`;
- bundle id расширения: `com.example.fptnclient.tunnel`;
- App Group: `group.com.example.fptnclient`;
- `DEVELOPMENT_TEAM` в `project.yml`.

Подробности — в [docs/BUILDING.md](docs/BUILDING.md).

## Что уже реализовано

- Разбор токенов `fptn:`, `fptn://`, `fptnb:` (Brotli) и `censored_zone_servers`.
- Собственный TLS 1.3-клиент: ClientHello, X25519, HKDF, AES-GCM/ChaCha20-Poly1305,
  Finished, KeyUpdate, фрагментация. Три политики аутентификации: pinned MD5
  leaf (upstream FPTN), строгая цепочка X.509 с DER-парсером, проверкой
  подписей RSA/ECDSA, сроков, SAN/hostname, CA/EKU и `CertificateVerify`,
  а также `.systemTrust` (`SecTrust` на iOS, системный PEM-бандл на Linux).
  Отсутствие пинна по умолчанию включает системное доверие. Дополнительно:
  SPKI-pinning (`spki_sha256` в токене), OCSP (включая stapling), CRL и
  SCT/Certificate Transparency с проверкой подписей и сроков.
- Три режима маскировки: plain SNI, TLS obfuscation (`TlsObfuscator2`) и reality
  с decoy ClientHello/ServerHello.
- HTTP/1.1 API (`/api/v1/login`, `/api/v1/dns`) и WebSocket upgrade на `/api/v1/fptn`.
- YAFF-кодек с golden-векторами, `MSG_IP_ASSIGNMENT`, `MSG_IP_PACKET`,
  `MSG_BATCH_IP_PACKET`, `MSG_ERROR`.
- Перезапись source/destination IP и пересчёт контрольных сумм IPv4/IPv6.
- Keepalive 15 с, dead-peer 90 с, rolling lifetime 600 с с заменой за 60 с.
- `TunnelPool`: dual/triple, login race по случайной половине серверов,
  привязка потока по source port, staggered-замены, общий `SessionID`.
- Закреплённый сервер пробуется первым при логине; при ошибке клиент
  возвращается к обычной гонке по остальным серверам.
- Reconnect budget 5 попыток / 120 с с экспоненциальной задержкой.
- Split tunnel по CIDR и доменным правилам, включая разбор SNI и DNS A/AAAA,
  генерацию TCP RST и динамические host-маршруты `/32`/`/128`. Локальные сети и
  системный трафик (`10/8`, `172.16/12`, `192.168/16`, loopback, link-local,
  multicast, IPv6 ULA/link-local/multicast) исключаются всегда. В комплект входит
  полный список OpenWRT (2158 доменов); пользователь может импортировать свой
  `.txt`-список и дополнить или заменить его.
- SNTP-клиент и `TimeProvider` на монотонном клоке.
- iOS UI: две оригинальные темы (`Aurora`, `Ember`), orb-статус, список серверов,
  импорт токена, настройки, диагностика.
- `Assets.xcassets` с оригинальной app icon; PNG генерируется воспроизводимым
  скриптом `Tools/AppIcon/generate.py` без внешних графических зависимостей.
- Локализация RU/EN с выбором языка: системный, English или Русский. Строки
  вынесены в `FptnShared` и покрыты тестами на полноту обоих словарей.
- On-Demand по умолчанию: после первого ручного подключения iOS автоматически
  поднимает туннель; в настройках есть переключатель на ручной режим.
- Токен хранится в Keychain приложения с миграцией из старого App Group
  `UserDefaults`; расширение получает его через `providerConfiguration`
  сохранённого VPN-профиля. При удалении токена приложение очищает и Keychain,
  и поле `token` в профиле.
- NetworkExtension: `NEPacketTunnelProvider`, TUN ↔ WebSocket relay,
  установка маршрутов и DNS.
- Метрики трафика: extension считает RX/TX байты и пакеты после split-фильтрации
  и раз в секунду публикует снимок в App Group; Diagnostics показывает суммы,
  пакеты, текущие скорости и живой график RX/TX за последние 60 секунд
  (линии, заливка, сетка, легенда — в цветах активной темы). RU/EN подписи,
  новый `sessionID` на каждое подключение.
- Весь Swift-пакет собирается в **Swift 6 language mode** без предупреждений;
  572 unit-теста проходят на Linux, плюс Xcode UI-тесты рендеринга обеих тем.

## Ограничения

- Локально здесь Linux без macOS/Xcode: ядро собрано и протестировано, а
  iOS-часть собирается и проходит type-check в GitHub Actions на `macos-15`.
  Запуск на реальном устройстве не выполнялся.
- Live-проверка транспорта выполнена через `Tools/LiveProbe`; поведение
  NetworkExtension, маршрутов, On-Demand и метрик трафика на устройстве ещё не
  проверено. График показывает скорости только за время работы приложения на
  переднем плане (история не сохраняется между запусками).
- В токене нет отдельного поля «режим маскировки»; режим выбирается в настройках.
- On-Demand использует правило «connect for any interface». Если выключить
  туннель вручную, но оставить On-Demand включённым, iOS может снова поднять его
  при смене сети; для гарантированно ручного режима отключите On-Demand.
- Встроенный доменный список — снимок `data/split-tunnel-domains.txt` из
  `alex0310/openwrt-fptn` (2158 записей). Пользовательский список хранится в
  App Group и объединяется со встроенным с дедупликацией.
- Доменные исключения работают через обычный DNS (UDP/53) и TLS SNI. DNS over
  HTTPS/TLS внутри туннеля по домену не распознаётся. Обновление host-маршрутов
  делается с debounce; первое подключение после DNS-ответа может успеть уйти в
  туннель до применения маршрута, после RST клиент повторяет его напрямую.
- Keychain-элемент приложения не использует общий `kSecAttrAccessGroup`:
  расширение получает токен через `providerConfiguration`, а не читает Keychain
  напрямую. Если понадобится общий доступ, нужно добавить `keychain-access-groups`
  и `FPTNKeychainAccessGroup` в Info.plist.

## Документация

- [Архитектура](docs/ARCHITECTURE.md)
- [Протокол](docs/PROTOCOL.md)
- [Безопасность](docs/SECURITY.md)
- [Дизайн](docs/DESIGN.md)
- [Сборка](docs/BUILDING.md)
- [Валидация](docs/VALIDATION.md)
- [Живая проверка ядра](Tools/LiveProbe/README.md)
- [План работ](PLAN.md)

## Лицензия

Apache License 2.0, см. [LICENSE](LICENSE).
