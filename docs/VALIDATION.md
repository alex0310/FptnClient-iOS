# Валидация

## Текущий статус

| Компонент | Среда | Результат |
|---|---|---|
| `FptnCore` + `FptnShared` | Linux x86_64, Swift 6.4.2, **Swift 6 language mode** | 445 тестов (358 + 87), 0 падений |
| `FptnCore` warnings | Linux, `-Xswiftc -warnings-as-errors` | 0 |
| `swift build` / `swiftc -parse App/ Tunnel/` | Linux | 0 warnings, 0 errors |
| `Tools/LiveProbe` | Linux, Swift 6 mode ядра | сборка без ошибок |
| CI `core` | GitHub Actions, `ubuntu-24.04`, Swift 6.2 | success |
| CI `ios-build` | GitHub Actions, `macos-15`, Xcode 16.4 | success, сборка без подписи |
| iOS app | macOS/Xcode | type-check и сборка в CI, на устройстве не проверялось |
| NetworkExtension | macOS/Xcode | type-check и сборка в CI, на устройстве не проверялось |
| Живой FPTN-сервер | Linux, `Tools/LiveProbe` | login, DNS API, tunnel, DNS-запрос: OK |

Команда:

```bash
/home/vasek/opt/swift-6.4.2/usr/bin/swift test --package-path /home/vasek/FptnClient-iOS
```

Последний прогон: `Executed 358 tests` для `FptnCore` и `Executed 87 tests` для `FptnShared`, с 0 failures. `swift build` также завершается без warnings и errors, в том числе с `-Xswiftc -warnings-as-errors`.

## Swift 6 language mode

`Package.swift` задаёт `swiftLanguageModes: [.v6]`; зависимости сохраняют свой
собственный язык (по tools-version), поэтому `swift-crypto` не попадает под
чужие проверки. Перевод выявил две проблемы:

- `LoginRace`: `@Sendable`-замыкание `DispatchQueue.async` захватывало обычный
  `(FPTNServer) throws -> String`. Решение — документированный
  `LoginOperation: @unchecked Sendable`: гонка логинов по замыслу вызывается
  параллельно, и каждый вызов владеет своим соединением. Публичный API остался
  без требования `@Sendable`.
- `POSIXSocketTests`: `Thread` захватывал `self` (`EchoServer`). Цикл сервера
  вынесен в свободную функцию `echoServerLoop(descriptor:echo:)`, замыкание
  теперь захватывает только `Int32` и `Bool`.
- `FPTNRelay` стал `@unchecked Sendable`: он разделяется между control queue и
  очередями читателей пула, все его поля неизменяемы, а `SplitTunnel` и
  `SplitTunnelRouteStore` уже потокобезопасны. Это убрало 2 warning из
  macOS-сборки (`capture of 'relay' with non-sendable type`). Compile-time
  проверка — `testRelayIsSendableForCrossQueueUse`.

Проверка: `swift test` в `.v6` — 0 errors, 0 warnings. `PackageManifestTests`
не даёт случайно откатить режим на `.v5`. CI собирает оба таргета с
`-Xswiftc -warnings-as-errors`.

Отдельно CI (`ubuntu-24.04`, Swift 6.2) поймал то, чего не видно на локальном
Swift 6.4.2: локальная константа `descriptor` в `POSIXSocketTests` перекрывала
одноимённое свойство в более ранних замыканиях `bind`/`getsockname`
(`closure captures 'descriptor' before it is declared`). Константа
переименована в `listenDescriptor`.

## Метрики трафика

- `FPTNRelay` сообщает `(bytes, packets)` через `onInboundTraffic` /
  `onOutboundTraffic` **после** split-фильтрации и успешной отправки/записи,
  поэтому исключённый трафик и handshake/keepalive в счёт не входят.
- `TrafficCounter` (`FptnShared`) — потокобезопасный аккумулятор с новым
  `sessionID` на каждое подключение; снимок `TrafficSnapshot` пишется в
  App Group `group.com.example.fptnclient` раз в секунду из уже существующего
  таймера `TunnelRuntime` и дополнительно при остановке.
- `AppModel` раз в секунду читает снимок, вычисляет `TrafficSpeed` по двум
  соседним точкам и публикует `@Published`-поля. Новая секция Diagnostics
  показывает RX/TX байты, пакеты и скорости; подписи локализованы RU/EN.
- График: `TrafficHistory` — кольцевой буфер на 60 сэмплов в процессе app;
  `TrafficChartScale` округляет потолок оси Y до 1/2/5×10ⁿ (минимум 1 KiB/s,
  чтобы график не дёргался на простое); `TrafficChartGeometry` переводит
  сэмплы в нормализованные координаты 0…1. `TrafficChartView` — тонкий
  SwiftUI-слой: сетка, две линии RX/TX, градиентная заливка под RX, легенда,
  заголовок с потолком шкалы, всё в цветах `ThemePalette`. При менее чем двух
  точках показывается заглушка «Собираем данные…».
- История живёт только в app и сбрасывается при отключении/перезапуске;
  в App Group она не пишется.
- На устройстве метрики и график ещё не проверялись.

## CI на GitHub Actions

Репозиторий: `https://github.com/alex0310/FptnClient-iOS`. Workflow
`.github/workflows/ci.yml` запускается на `push`/`pull_request` в `main` и через
`workflow_dispatch`:

- `core` (`ubuntu-24.04`, Swift 6.2): `swift build -Xswiftc -warnings-as-errors`,
  `swift test`, `swiftc -parse App/*.swift App/*/*.swift Tunnel/*.swift`;
- `ios-build` (`macos-15`): `xcodegen generate` и `xcodebuild ... build`
  с `CODE_SIGNING_ALLOWED=NO` для app и extension.

`ubuntu-latest` в 2026 указывает на Ubuntu 26.04, которую
`swift-actions/setup-swift@v2` не поддерживает, поэтому job закреплён за
`ubuntu-24.04`. Swift закреплён за 6.2, так как `swift-asn1` в
`Package.resolved` использует `swift-tools-version:6.1`.

macOS-CI нашёл две ошибки, которые невозможно увидеть на Linux (`swiftc -parse`
не делает type-check):

1. `'IPAddress' is ambiguous for type lookup` в `Tunnel/TunnelRuntime.swift`
   (`NetworkExtension` тянет системный модуль с одноимённым типом). Все обращения
   к `IPAddress` в `App/` и `Tunnel/` теперь пишутся как `FptnCore.IPAddress`;
   регрессию проверяет `TunnelSourceQualificationTests`.
2. `incorrect argument label in call` в `Tunnel/PacketTunnelProvider.swift`:
   `TunnelRuntime.start` принимает `completion:`, а не `completionHandler:`.
   Регрессию проверяет `TunnelCallSiteTests`.

Итоговый прогон (commit `776b68a`): оба job — `success`, **0 Swift-warning и
0 Swift-error** в обоих логах. Остаются только сторонние предупреждения
инструментов: `gpg` при установке Swift, `appintentsmetadataprocessor` Xcode
(нет зависимости от `AppIntents.framework`) и уведомление runner о Node.js 20.
Прогон: https://github.com/alex0310/FptnClient-iOS/actions/runs/43432475597

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
- `FPTNRelay` forwarding, split actions, изучение DNS/SNI-адресов, учёт
  трафика (байты/пакеты после split-фильтрации, пустые батчи, ошибка sender)
  и compile-time проверка `Sendable`.
- `TrafficCounter` (параллельные инкременты, reset/session, переполнение),
  `TrafficSnapshot.speed` (смена сессии, обратное время, сброс счётчиков),
  `TrafficFormatter` (бинарные единицы, некорректные значения),
  `TrafficSnapshotStore` (round-trip, битые данные, clear).
- `TrafficChartTests`: кольцевой буфер (порядок, вытеснение, минимальный лимит,
  reset), `niceCeiling`/`peak`/`scale` (включая NaN/inf/отрицательные),
  геометрия (пусто, x 0…1, масштабирование y, clamp, некорректный scale).
- `TrafficIntegrationTests`: исходники `App/`/`Tunnel/` обязаны содержать
  хуки записи, чтения, истории и отображения метрик/графика.
- `PackageManifestTests`: `swiftLanguageModes: [.v6]` не откатывается.
- `SharedSettings` Codable/legacy decode, bundled 2158-domain list, import parsing/merge.
- `OnDemandPolicy` automatic/manual rule descriptors.
- `Localizer`, `AppLanguage` и полнота `en`/`ru` словарей, форматирование и выбор системного языка.
- `TokenStore`: UserDefaults fallback, keychain update/add/delete fallback, trimming,
  malformed UTF-8, mapping ошибок, миграция legacy-токена и удаление токена из
  settings blob.
- `TunnelSourceQualificationTests`: все обращения к `IPAddress` в `App/` и
  `Tunnel/` обязаны быть записаны как `FptnCore.IPAddress`.
- `TunnelCallSiteTests`: `PacketTunnelProvider` вызывает
  `TunnelRuntime.start(completion:)` с корректным ярлыком аргумента.

## Что не покрыто

- Type-check `App/` и `Tunnel/` теперь выполняет macOS-CI; на Linux по-прежнему
  доступен только `swiftc -parse`. Запуск на устройстве не проверялся.
- `Tools/LiveProbe` не входит в unit-тесты и требует реальный токен/сеть.
- Переключение языка в живом UI проверяется только на macOS/iOS; Linux-тесты проверяют словари и `Localizer`.
- Все 19 серверов и длительная работа pool под нагрузкой; live-прогон покрывает по одному серверу на режим.
- iOS route installation и `NEPacketTunnelFlow` на устройстве.
- Метрики трафика и график в живом туннеле: запись снимков из extension,
  чтение в app, корректность скоростей при смене сети и реконнекте,
  отрисовка `Path` на устройстве/симуляторе.
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
