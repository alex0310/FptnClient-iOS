# Протокол FPTN

Документ фиксирует формат, который реализует `FptnCore`. Он собран из
`fptn-upstream`, Android-клиента и Rust-порта `fptn-client-rs`.

## 1. Access token

Поддерживаются три префикса:

| Префикс | Кодирование |
|---|---|
| `fptn:` | Base64 JSON |
| `fptn://` | Base64 JSON |
| `fptnb:` | Brotli-сжатый JSON, затем Base64 |

Пробелы и переводы строк удаляются до разбора: токены часто ломаются при
копировании через мессенджеры.

Поля JSON:

```json
{
  "version": 1,
  "service_name": "Example",
  "username": "user",
  "password": "secret",
  "servers": [
    {
      "name": "Finland",
      "host": "vpn.example.com",
      "port": 443,
      "md5_fingerprint": "…",
      "country_code": "FI"
    }
  ],
  "censored_zone_servers": []
}
```

`censored_zone_servers` добавляются к общему списку с флагом
`isCensoredZone`. В Swift-клиенте reality-режим выбирается настройкой, а не
автоматически по флагу; флаг отображается в UI.

## 2. Control plane

База: `https://<host>:<port>`.

### Login

```http
POST /api/v1/login HTTP/1.1
Content-Type: application/json
Client-Agent: FptnClient(iOS/1.0.0)
Connection: close

{"username":"user","password":"secret"}
```

Ответ: `{"access_token":"<jwt>"}`.

### DNS

```http
GET /api/v1/dns HTTP/1.1
Authorization: Bearer <jwt>
Client-Agent: FptnClient(iOS/1.0.0)
Connection: close
```

Ответ: `{"dns":"10.0.0.53","dns_ipv6":"fd00::53"}`.

`FPTNAPITransport` открывает отдельное TLS-соединение на каждый запрос. В
заголовках намеренно нет `Accept-Encoding`: сервер не должен сжимать ответы,
которые разбирает клиент.

## 3. Login race

Из списка серверов выбирается случайная половина, но не меньше одного:

```text
count = max(1, servers.count / 2)
```

Для каждого кандидата выполняется до 3 попыток login с паузой 500 мс. Первый
успешный ответ фиксирует сервер и JWT. Остальные попытки отменяются флагом.

## 4. WebSocket

```http
GET /api/v1/fptn HTTP/1.1
Host: <host>:<port>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64>
Sec-WebSocket-Version: 13
Authorization: Bearer <jwt>
X-Serializer: yaff
Client-Agent: FptnClient(iOS/1.0.0)
SessionID: <64 alphanumeric>
X-Send-Duration: <ms>       (опционально)
X-Ttl: <ms>                 (опционально)
```

Ожидаемый ответ — `101 Switching Protocols` с корректным
`Sec-WebSocket-Accept`. Клиентские фреймы маскируются, серверные — нет.

## 5. YAFF

Кадр:

```text
u32 root_offset_le | size_mask | payload
```

Внутри payload:

```text
u8 message_type | поля
```

Типы:

| Значение | Тип | Поля |
|---:|---|---|
| 0 | `MSG_ERROR` | `u8 error_type`, `string error_msg` |
| 1 | `MSG_IP_PACKET` | `bytes packet` |
| 2 | `MSG_IP_ASSIGNMENT` | `bytes ipv4`, `bytes ipv6` |
| 3 | `MSG_BATCH_IP_PACKET` | `u32 count`, затем count пакетов |

`error_type`: `0` default, `1` wrong version, `2` session expired.

`MSG_IP_ASSIGNMENT` в эталонных Rust-векторах содержит сырые 4/16 байт, а
реальный C++-сервер иногда присылает текстовые адреса. Swift-декодер принимает
оба варианта; текстовая строка валидируется уже в `FPTNTunnel`.

После upgrade сервер первым присылает `MSG_IP_ASSIGNMENT`. До него клиент не
имеет права отправлять IP-пакеты.

## 6. Батчинг

`FPTNTunnel` группирует пакеты до `maxBatchSize` (по умолчанию 64) и отправляет
`MSG_BATCH_IP_PACKET`. Пустые пакеты отбрасываются. Одиночный пакет может быть
отправлен как batch из одного элемента — сервер принимает оба варианта.

## 7. TLS 1.3

- TLS 1.3, cipher suites `0x1301`, `0x1302`, `0x1303`.
- X25519 key share, HKDF-SHA-256/384, Finished, KeyUpdate.
- Клиент проверяет pinned MD5 leaf-сертификата, если в токене есть
  `md5_fingerprint`.
- `CertificateVerify` не проверяется: подпись сертификата не валидируется,
  доверие строится на pinned MD5 + TLS Finished. Это осознанное повторение
  поведения upstream C++ и задокументировано в `SECURITY.md`.

### FPTN session key

В TLS 1.3 session ID (32 байта) всегда штампуется FPTN-ключом:

- реальный ключ — в конец session ID (offset 28);
- decoy — offset 14;
- устаревший decoy — offset 10.

Окно timestamp ±120 с.

## 8. Режимы маскировки

### Plain

Обычный TLS ClientHello с SNI. Используется, когда DPI не мешает.

### TLS obfuscation (`TlsObfuscator2`)

Весь TLS handshake заворачивается в обфусцированные записи:

```text
17 03 03 | content_length | 8 random | timestamp | xor_key |
payload_length | padding_length | payload | padding
```

- заголовок 22 байта;
- padding 4095–8192 байт;
- content length ≤ 16384;
- timestamp ±120 с;
- XOR с ключом;
- после Finished обфускатор отбрасывается;
- перед первой application-записью — пауза ~150 мс.

### Reality

1. Отправить decoy ClientHello сырым.
2. Прочитать decoy ServerHello, игнорируя содержимое.
3. Отправить `14 03 03 00 01 01` (CCS).
4. Пауза ~150 мс.
5. Выполнить реальный TLS handshake через `TlsObfuscator2`.

Тайминги: quiet period 300 мс, decoy timeout 6 с, задержка реального
handshake 150 мс, до 3 попыток.

## 9. Keepalive

- ping при простое 15 с;
- мёртвый peer — 90 с без входящих фреймов;
- pong обновляет watchdog;
- WebSocket ping payload — 8 байт sequence.

## 10. IP rewrite

Исходящий пакет: source IP заменяется на выданный сервером адрес.
Входящий: destination заменяется на TUN-адрес, если он сконфигурирован.
Пересчитываются checksums IPv4, TCP, UDP, ICMP и ICMPv6.

## 11. Rolling lifetime

- базовый lifetime 600 с;
- замена за 60 с до закрытия;
- dual: 300/600 с;
- triple: 200/400/600 с;
- новый слот ставится в самый широкий интервал между оставшимися lifetime.
