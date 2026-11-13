# Безопасность

## Модель доверия

Клиент повторяет компромиссы upstream FPTN:

1. **Pinned MD5 leaf.** Если токен содержит `md5_fingerprint`, клиент сравнивает
   MD5 листового сертификата с этим значением.
2. **TLS Finished.** Проверяется, что сервер знает handshake secrets.
3. **CertificateVerify не проверяется.** Подпись сертификата не валидируется.
   Это нужно для самоподписанных серверов FPTN и повторяет поведение C++/Rust
   клиентов.

Следствие: при утере MD5 из токена или компрометации сервера клиент не сможет
отличить его от поддельного сервера с тем же MD5. Перед публикацией в App Store
нужно решить, включать ли строгую проверку цепочки для не-FPTN серверов.

## Токен

Токен — bearer-credential: он содержит username/password и список серверов.

Приложение хранит его в Keychain как generic password:

- service `com.example.fptnclient`, account `fptn-access-token`;
- accessibility `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`;
- item не синхронизируется через iCloud и не попадает в App Group;
- расширение получает токен в `NETunnelProviderProtocol.providerConfiguration`
  при запуске туннеля и не читает Keychain напрямую;
- при удалении токена приложение очищает Keychain, убирает `token` из
  сохранённого VPN-профиля и отключает On-Demand.

Старые сборки хранили токен в App Group `UserDefaults`. При запуске приложение
читает legacy-поле, переносит его в Keychain и перезаписывает settings blob уже
без credential. Если Keychain-элемент повреждён, используется legacy-токен, пока
он ещё есть.

Общий Keychain access group для приложения и расширения не настроен: это
потребовало бы `keychain-access-groups` и provisioning-profile-specific
`kSecAttrAccessGroup`. Если расширение когда-нибудь будет читать Keychain
напрямую, нужно добавить `keychain-access-groups` и `FPTNKeychainAccessGroup`.

## JWT

JWT живёт только в памяти extension и используется для `Authorization: Bearer`.
Он не сохраняется в настройках. При перезапуске extension login race выполняется
заново.

## Сетевые заголовки

`FPTNAPIClient` отправляет браузероподобные заголовки и `Client-Agent`, но не
отправляет `Accept-Encoding`. Это сделано, чтобы сервер не сжал JSON, который
клиент разбирает вручную.

## Reality

Decoy ClientHello содержит случайный session ID с decoy-ключом. После decoy
ServerHello клиент отправляет CCS и делает паузу. Реальный handshake идёт через
`TlsObfuscator2`; после Finished обфускатор отбрасывается.

## Split tunnel

CIDR-правила устанавливаются как `excludedRoutes`. Обязательные локальные и
системные диапазоны (`10/8`, `172.16/12`, `192.168/16`, loopback, link-local,
multicast, IPv6 ULA/link-local/multicast) добавляются всегда и не могут быть
удалены через пользовательский список.

Доменные правила:

- SNI-совпадение → TCP RST в TUN и запоминание destination;
- DNS A/AAAA → адреса попадают в `SplitTunnelRouteStore`;
- extension с debounce пересобирает `excludedRoutes` с host-маршрутами `/32` и
  `/128`, чтобы повторное подключение шло мимо VPN.

Если split tunnel включён, приложение обязано явно показать пользователю, какие
сети и домены идут мимо VPN. DNS-исключения работают только для обычного DNS
(UDP/53); DoH/DoT внутри туннеля по домену не распознаются.

## Что не реализовано

- Проверка `CertificateVerify` и цепочки сертификатов.
- Certificate pinning по SPKI.
- Защита от downgrade режима маскировки.
- Общий Keychain access group для приложения и расширения.
- Аудит сторонних зависимостей (`swift-crypto`, `SwiftBrotli`).
