# Валидация

## Текущий статус

| Компонент | Среда | Результат |
|---|---|---|
| `FptnCore` + `FptnShared` | Linux x86_64, Swift 6.4.2 | 401 тест (352 + 49), 0 падений |
| `FptnCore` warnings | Linux | 0 |
| iOS app | macOS/Xcode | не проверено в этой среде |
| NetworkExtension | macOS/Xcode | не проверено в этой среде |
| Живой FPTN-сервер | Linux, `Tools/LiveProbe` | login, DNS API, tunnel, DNS-запрос: OK |

Команда:

```bash
/home/vasek/opt/swift-6.4.2/usr/bin/swift test --package-path /home/vasek/FptnClient-iOS
```

Последний прогон: `Executed 352 tests` для `FptnCore` и `Executed 49 tests` для `FptnShared`, с 0 failures. `swift build` также завершается без warnings и errors.

## Живая проверка FPTN

2026-11-12 на Linux через `Tools/LiveProbe` проверен реальный токен сервиса
`FPTN.ONLINE` (19 серверов):

- `Greece-1` — `plain` и `obfuscated`;
- `Russia-Moscow` (censored zone) — `reality`;
- login и `/api/v1/dns` — OK;
- TLS 1.3 + WebSocket upgrade + YAFF `MSG_IP_ASSIGNMENT` — OK;
- DNS-запрос через выданный IPv4-адрес вернул ответ с 2 answer records;
- `FPTNClient` с `dual` pool открыл два туннеля, оба получили IP, DNS через пул — OK.

Токен в репозиторий не записывался. Повторить проверку:

```bash
FPTN_LIVE_TOKEN_FILE=/path/to/fptn-token \
  swift run --package-path Tools/LiveProbe FptnProbe
```

## Что покрыто тестами

- ByteReader/ByteWriter/Hex/SecureRandom.
- YAFF golden-векторы и malformed-кадры.
- FPTN token plain/URL-safe/Brotli/censored servers.
- WebSocket frame encoder/decoder, фрагментация, close, ping/pong.
- SHA-1/SHA-256/SHA-384/MD5, HMAC, constant-time compare.
- TLS 1.3 key schedule, cipher suites, RFC 8448 fixtures.
- TLS ClientHello/ServerHello/Certificate/Finished/KeyUpdate.
- `TlsObfuscator2` encode/decode, padding, timestamp.
- HTTP request/response, chunked, upgrade, browser headers.
- `TLSConnection` plain/obfuscated/reality на scripted transport.
- `FPTNMessage`, IP rewrite, checksums, source port.
- Keepalive, SNTP, NTP fallback.
- `FPTNTunnel` handshake/batch/error/keepalive/lifetime.
- `TunnelPool` dual/triple, stagger, flow pinning, replacement, reconnect.
- `LoginRace` candidates/retry/failure, приоритет закреплённого сервера,
  fallback на остальные серверы и retry budget для единственного сервера.
- `ReconnectPolicy` budget/backoff.
- `SplitTunnel` CIDR/domain/SNI/DNS/TCP RST, обязательные локальные и системные
  CIDR.
- `SplitTunnelRouteStore` дедупликация, порядок, лимит и вытеснение.
- `FPTNClient` start/login/DNS/pool/send/stop.
- `FPTNRelay` forwarding, split actions и изучение DNS/SNI-адресов.
- `SharedSettings` Codable/legacy decode, bundled 2158-domain list, import parsing/merge.
- `OnDemandPolicy` automatic/manual rule descriptors.
- `Localizer`, `AppLanguage` и полнота `en`/`ru` словарей, форматирование и выбор системного языка.
- `TokenStore`: UserDefaults fallback, keychain update/add/delete fallback, trimming,
  malformed UTF-8, mapping ошибок, миграция legacy-токена и удаление токена из
  settings blob.

## Что не покрыто

- `App/` SwiftUI и `Tunnel/` NetworkExtension: требуют macOS/Xcode.
- `Tools/LiveProbe` не входит в unit-тесты и требует реальный токен/сеть.
- Переключение языка в живом UI проверяется только на macOS/iOS; Linux-тесты проверяют словари и `Localizer`.
- Все 19 серверов и длительная работа pool под нагрузкой; live-прогон покрывает по одному серверу на режим.
- iOS route installation и `NEPacketTunnelFlow` на устройстве.
- Динамическое обновление `excludedRoutes` через `setTunnelNetworkSettings` во
  время работы туннеля и гонка «DNS-ответ → первое подключение».
- Доменные правила при DoH/DoT: такие DNS-ответы не видны extension.
- Фактическая установка `NEOnDemandRuleConnect` проверяется только на macOS/iOS.
- App Store signing, entitlements, provisioning.
- Компиляция `Assets.xcassets` и отображение app icon проверяются только в
  macOS/Xcode; PNG и `Contents.json` валидируются локально.
- Реальный Keychain и `providerConfiguration` на iOS: Linux-тесты используют
  fake Keychain и UserDefaults fallback; интеграционный `testSystemKeychainRoundTrip`
  выполняется только на macOS/iOS.

## Как проверять iOS

```bash
xcodegen generate
xcodebuild \
  -project FptnClient.xcodeproj \
  -scheme FptnClient \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

После этого — запуск на устройстве с реальным токеном и сервером. Минимальный
smoke-тест:

1. Импорт токена.
2. Connect → системный VPN-запрос.
3. Проверка assigned IP/DNS в Diagnostics.
4. Открытие HTTP-сайта.
5. Переключение dual/triple.
6. Split tunnel: `10/8`, `172.16/12`, `192.168/16` и системные диапазоны не
   должны уходить в туннель; DNS/SNI-домены должны получать host-маршруты.
7. On-Demand: включить, подключиться, сменить сеть/Wi-Fi → туннель должен
   подняться автоматически.
8. Ручной режим: выключить On-Demand, disconnect → туннель не должен
   переподключаться сам.
9. Disconnect → системный индикатор выключается.
10. Settings → Appearance → язык: переключить RU/EN/System и проверить все экраны.
11. Удалить токен → Keychain очищен, VPN-профиль больше не содержит `token`,
    On-Demand выключен; после перезапуска токен не восстанавливается.
12. Импортировать токен, перезапустить приложение → токен загружается из Keychain,
    старый App Group `UserDefaults` больше не содержит credential.
