# Валидация

## Текущий статус

| Компонент | Среда | Результат |
|---|---|---|
| `FptnCore` + `FptnShared` | Linux x86_64, Swift 6.4.2, **Swift 6 language mode** | 572 теста (471 + 101), 0 падений |
| SPKI / OCSP / CRL / SCT | Linux, подписанные DER-фикстуры | парсеры, подписи, сроки, статусы |
| Системные корни | Linux, OS PEM bundle / iOS `SecTrust` | загрузка, разбор, CA, самоподписи |
| Строгая цепочка X.509 | Linux, RFC 8448 + сгенерированные DER-фикстуры | DER/X.509/подписи/hostname/цепочка: 0 падений |
| Токены тем | Linux, golden files | 2 эталона, 0 расхождений |
| UI-рендеринг тем | `macos-15`, iPhone 16 / iOS 26.2, `xcodebuild test` | 4 теста, 0 падений |
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

Последний прогон: `Executed 471 tests` для `FptnCore` и `Executed 101 tests` для `FptnShared`, с 0 failures. `swift build` также завершается без warnings и errors, в том числе с `-Xswiftc -warnings-as-errors`.

## Проверка цепочки сертификатов

- `DER.swift` — строгий DER-декодер (definite length, минимальная длина, OID,
  UTCTime/GeneralizedTime, BIT STRING, BOOLEAN, запрет хвостов).
- `X509Certificate.swift` — разбор `TBSCertificate`: issuer/subject, сроки,
  SPKI, SAN/dNSName, BasicConstraints, KeyUsage, EKU, CN, точные `tbsDER`.
- `CertificateSignature.swift` — верификация подписей RSA (PKCS#1 v1.5 и PSS),
  ECDSA P-256/P-384 и Ed25519; `CertificateVerifyContext` строит подписываемое
  содержимое RFC 8446 §4.4.3.
- `CertificateChainPolicy.swift` — `X509TrustAnchors`,
  `CertificateValidationPolicy` (`.pinnedMD5` / `.strictChain`), построение
  цепочки до якоря, проверка подписей, сроков, CA/`keyCertSign`, EKU
  `serverAuth` и hostname (точное совпадение и левый `*`).
- `CertificatePinner` больше не пропускает проверку при `nil`:
  `TLSError.missingServerAuthentication`.
- `TLSClientSession` в `.strictChain` верифицирует `CertificateVerify`
  публичным ключом листа; в `.pinnedMD5` сохраняется поведение upstream.
- Фикстуры: реальный сертификат из RFC 8448, сгенерированные RSA/ECDSA
  цепочки, лист с чужим SAN, чужой корень, испорченная подпись, тестовый
  приватный ключ (только для тестов).
- Интеграционные тесты `StrictChainHandshakeTests`: успешный handshake с
  настоящей цепочкой и подписью, отказ при фейковом `CertificateVerify`,
  чужом корне и неверном hostname.
- `CertificatePolicyWiringTests` сторожит проброс политики через
  `FPTNClientConfiguration` → `FPTNTunnelFactory` / `FPTNAPITransport` →
  `TLSConnectionConfiguration` → `TLSClientConfiguration`.

## SPKI, отзыв и Certificate Transparency

Дополнительные проверки оркестрируются `CertificateSecurityOptions` и
применяются после основной политики (пинн, цепочка, системное доверие).
Все они отключены по умолчанию и включаются конфигурацией.

- **SPKI-pinning:** SHA-256 DER `SubjectPublicKeyInfo` листа, hex или base64,
  constant-time сравнение. Пин можно задать в `FPTNClientConfiguration` или в
  токене (`spki_sha256` у сервера); `addingSPKIPin` не дублирует значения.
- **OCSP:** RFC 6960 `BasicOCSPResponse` — статус good/revoked/unknown,
  `thisUpdate`/`nextUpdate`, серийный номер, подпись ответа (responder-сертификат
  или издатель). Поддерживается stapling через TLS `status_request` (type 5)
  и-response из конфигурации.
- **CRL:** RFC 5280 `CertificateList` — издатель, окно действия, список
  отозванных серийных номеров, подпись издателя. Из сертификата также
  извлекаются `crlDistributionPoints` и OCSP-URI из AIA.
- **SCT / CT:** RFC 6962 v1 — парсер TLS `SignedCertificateTimestampList`
  (extension 18) и X.509 SCT extension, проверка подписи доверенным CT-логом,
  времени выпуска и минимального числа валидных SCT.
- Сетевых запросов во время handshake нет: сеть в этот момент уже туннелируется.
  Данные об отзыве и список CT-логов предоставляет вызывающий код
  (`RevocationPolicy`, `CTPolicy`), при `requireStatus` / `minimumValidSCTs`
  отсутствие данных — fail-closed.

Тесты: `CertificateSPKITests`, `CertificateRevocationTests`,
`CertificateTransparencyTests`, `CertificateSecurityIntegrationTests` (SPKI-пин,
stapled good/revoked OCSP и TLS SCT прямо в handshake), `X509CertificateTests`
(серийный номер, CRL DP, AIA, встроенный SCT). Фикстуры CRL/OCSP/SCT
подписываются одноразовым тестовым CA-ключом из `Tests/FptnCoreTests/Fixtures`.

## Системные корни

Вендоринга CA bundle нет: статическая копия быстро устаревает и тянет
стороннюю лицензию. Вместо этого `CertificateValidationPolicy.systemTrust`
использует доверие операционной системы:

- **Apple (`#if canImport(Security)`)** — `SecTrustCreateWithCertificates` +
  `SecPolicyCreateSSL` + `SecTrustEvaluateWithError`; iOS не даёт перечислить
  системные якоря, поэтому решение о доверии принимает сам `SecTrust`.
- **Linux/прочие** — `X509PEM` разбирает системный PEM-бандл
  (`/etc/ssl/certs/ca-certificates.crt` и альтернативные пути), якоря
  кэшируются один раз на процесс; дальше работает тот же чистый Swift
  валидатор цепочки.
- Явный набор якорей (`systemAnchors:`) всегда имеет приоритет — это делает
  путь детерминированным для тестов и позволяет встроить собственные корни.
- Если системный бандл недоступен, `.systemTrust` падает с
  `CertificateChainError.noTrustAnchor` (fail-closed).
- Политика по умолчанию: при наличии `md5_fingerprint` — `.pinnedMD5`, при
  его отсутствии — `.systemTrust` (раньше это был молчаливый пропуск, позже
  жёсткий отказ).

Тесты: `X509PEMTests` (LF/CRLF, комментарии, несколько сертификатов, битые
маркеры/base64), `SystemTrustTests` (загрузка из внедрённого PEM, OS-бандл,
`.systemTrust` с якорями/без якорей, дефолты политики), guard-тест на
наличие `SecTrust`-кода и проброс `.systemTrust`.

## Тесты тем

Дизайн-токены вынесены в `FptnShared` (`ThemeTokens`, `ThemeColor`, `AppTheme`),
а `ThemePalette` в app-таргете стал тонким адаптером `ThemeColor → SwiftUI.Color`
без единого цветового литерала. Это позволяет тестировать темы на Linux.

- **Golden snapshots:** `Tests/FptnSharedTests/Snapshots/aurora.theme` и
  `ember.theme` — стабильный дамп всех 11 цветов с точностью до 3 знаков.
  `ThemeSnapshotTests` сравнивает сгенерированный дамп с эталоном; эталоны
  тестами не перезаписываются, поэтому любое изменение палитры падает в CI.
- **Доступность:** `ThemeContrast` считает WCAG-контраст; тесты требуют ≥ 4.5
  для основного текста и ≥ 3.0 для второстепенного на обоих фонах темы.
- **Прочее:** уникальность тем, диапазон 0…1 у всех компонентов, fallback
  `AppTheme(stored:)`, локализация названий/подписей в `en` и `ru`,
  детерминированность дампа.
- **Guard-тесты:** `App/` не содержит `Color(red:...)`, палитра строится из
  `ThemeTokens`, `project.yml`/CI содержат UI-тестовый таргет и `xcodebuild test`.
- **Xcode UI-тесты:** `Tests/FptnClientTests/ThemeRenderingTests.swift` через
  `ImageRenderer` рендерит `ThemeSwatch` и `TrafficChartView` для обеих тем,
  проверяет непустой PNG и то, что Aurora и Ember дают разные изображения.
  Пиксельные эталоны PNG пока не хранятся — шрифты и SF Symbols зависят от
  рантайма симулятора, поэтому сравнивается факт и различие рендеринга.
  Прогон на `iPhone 16` / iOS 26.2: `Executed 4 tests, with 0 failures`,
  `** TEST SUCCEEDED **`.

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
- `ios-build` (`macos-15`): `xcodegen generate`, `xcodebuild ... build`
  с `CODE_SIGNING_ALLOWED=NO` для app и extension, затем `xcodebuild ... test`
  на iOS Simulator для таргета `FptnClientTests`.

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

Итоговый прогон (commit `1406acd`): оба job — `success`, **0 Swift-warning и
0 Swift-error** в обоих логах; Linux — 572 теста (471 + 101), macOS-job
собрал app/extension c `_CryptoExtras`, скомпилировал `SystemTrust.swift`
(`SecTrust`-путь для iOS), подтвердил type-check `TrafficChartView` и выполнил
4 UI-теста рендеринга тем (`** TEST SUCCEEDED **`). Остаются только сторонние
предупреждения инструментов: `gpg` при установке Swift,
`appintentsmetadataprocessor` Xcode (нет зависимости от `AppIntents.framework`)
и уведомление runner о Node.js 20.
Прогон: https://github.com/alex0310/FptnClient-iOS/actions/runs/43581023113

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
- `DERTests`, `X509CertificateTests`, `CertificateChainTests`,
  `CertificateVerifyTests`, `StrictChainHandshakeTests`,
  `CertificatePolicyWiringTests`, `X509PEMTests`, `SystemTrustTests`,
  `CertificateSPKITests`, `CertificateRevocationTests`,
  `CertificateTransparencyTests`, `CertificateSecurityIntegrationTests`: DER,
  X.509 (RFC 8448 + RSA/ECDSA фикстуры), PEM, подписи, сроки, SAN/wildcard,
  цепочка до якоря, системные корни, SPKI-пины, OCSP/CRL, SCT, негативные
  сценарии, `CertificateVerify` и проброс политик в продакшн-конфигурацию.
- `ThemeSnapshotTests`: golden-файлы обеих тем, полнота дампа, уникальность,
  диапазон компонентов, fallback, RU/EN названия, WCAG-контраст.
- `ThemeIntegrationTests`: палитра-адаптер без цветовых литералов, отсутствие
  хардкодных цветов во views, наличие UI-таргета и CI-шага.
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
- Переключение языка и тем в живом UI проверяется только на macOS/iOS; Linux-тесты проверяют словари, `Localizer` и токены, а Xcode-тесты — факт рендеринга.
- Пиксельное совпадение UI с эталонными PNG **осознанно не реализовано**:
  эталоны зависят от версии iOS, шрифтов и SF Symbols конкретного симулятора.
  Вместо этого golden-файлы фиксируют точные значения токенов, а Xcode-тесты —
  непустой рендер и различие тем. Тема UI/snapshot-тестов считается закрытой.
- Все 19 серверов и длительная работа pool под нагрузкой; live-прогон покрывает по одному серверу на режим.
- `.systemTrust` на реальном iOS-устройстве с публичным сертификатом:
  симуляторный CI проверяет только сборку `SecTrust`-кода.
- Сетевая загрузка OCSP/CRL и встроенный список доверенных CT-логов:
  данные и логи передаёт вызывающий код, handshake сеть не использует.
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
