# Безопасность

## Модель доверия

Доступны три политики аутентификации сервера (`CertificateValidationPolicy`).
Выбор делается конфигурацией; по умолчанию при наличии `md5_fingerprint`
сохраняется поведение upstream, при его отсутствии включается системное доверие.

### Pinned MD5 (FPTN-серверы)

1. **Pinned MD5 leaf.** Если токен содержит `md5_fingerprint`, клиент сравнивает
   MD5 листового DER с этим значением (constant-time).
2. **TLS Finished.** Проверяется, что сервер знает handshake secrets.
3. `CertificateVerify` в этом режиме не верифицируется — самоподписанные
   серверы FPTN повторяют поведение C++/Rust клиентов.

**Если `md5_fingerprint` отсутствует**, конфигурация по умолчанию переключается
на `.systemTrust` (раньше это был молчаливый пропуск аутентификации). Явный
вызов `.pinnedMD5(nil)` по-прежнему завершается
`TLSError.missingServerAuthentication`.

### Strict X.509 chain (не-FPTN серверы)

Политика `.strictChain(X509TrustAnchors)` включает полную проверку:

- DER/ASN.1-парсер и разбор сертификата: issuer/subject, сроки, SPKI,
  SAN/dNSName, BasicConstraints, KeyUsage, EKU;
- верификацию подписей RSA (PKCS#1 v1.5 / PSS) и ECDSA P-256/P-384 через
  `swift-crypto` и `_CryptoExtras`, Ed25519 — через CryptoKit;
- построение цепочки до явно заданного доверенного корня, проверку того, что
  промежуточные сертификаты являются CA и имеют `keyCertSign`;
- проверку имени хоста по SAN (с левым `*`), при отсутствии SAN — по CN;
- проверку срока действия и EKU `serverAuth` у листа;
- верификацию TLS 1.3 `CertificateVerify` публичным ключом листа, что связывает
  сертификат с владельцем TLS-ключа;
- проверку TLS Finished.

Корни задаются **явно** (`X509TrustAnchors(derRoots:)`); публичный CA bundle в
репозиторий не входит. Пустой набор якорей — fail-closed
(`CertificateChainError.noTrustAnchor`). Это позволяет использовать строгий
режим и для самоподписанных FPTN-серверов, если их сертификат добавлен в якоря.

### System trust (корни операционной системы)

Политика `.systemTrust` — значение по умолчанию для серверов без пинна.
CA bundle в репозиторий **намеренно не вендорится**: статическая копия устаревает
и требует распространения сторонней лицензии.

- **iOS/macOS:** `SecTrustCreateWithCertificates` + `SecPolicyCreateSSL` +
  `SecTrustEvaluateWithError` — решение принимает системный trust store
  (iOS не позволяет перечислить якоря как массив сертификатов).
- **Linux/прочие:** `X509PEM` читает системный PEM-бандл
  (`/etc/ssl/certs/ca-certificates.crt` и альтернативные пути), якоря
  кэшируются на процесс, затем работает тот же чистый Swift валидатор.
- Явно переданный `systemAnchors` имеет приоритет (детерминированные тесты и
  встроенные корни). Отсутствие системного бандла — fail-closed
  (`noTrustAnchor`).

Тестовые цепочки лежат в `Tests/FptnCoreTests/Fixtures/`.
`rsa-leaf-key.pem` — одноразовый тестовый ключ, в приложение не попадает.

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

- Проверка `.systemTrust` на реальном iOS-устройстве с публичным сертификатом
  (CI проверяет только сборку `SecTrust`-кода на симуляторе).
- Certificate pinning по SPKI.
- Проверка статуса отзыва (OCSP/CRL) и SCT.
- Защита от downgrade режима маскировки.
- Общий Keychain access group для приложения и расширения.
- Аудит сторонних зависимостей (`swift-crypto`, `SwiftBrotli`).
