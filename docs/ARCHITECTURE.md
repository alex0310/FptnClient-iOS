# Архитектура

## Слои

```
┌─────────────────────────────────────────────────────────────┐
│ iOS app (SwiftUI)                                           │
│  AppModel → VPNController → NETunnelProviderManager         │
└───────────────────────────────┬─────────────────────────────┘
                                │ providerConfiguration
┌───────────────────────────────▼─────────────────────────────┐
│ NetworkExtension (PacketTunnelProvider)                     │
│  TunnelRuntime: TUN ↔ FPTNRelay ↔ FPTNClient               │
│  PacketFlowDevice: NEPacketTunnelFlow adapter               │
└───────────────────────────────┬─────────────────────────────┘
                                │ FptnCore
┌───────────────────────────────▼─────────────────────────────┐
│ FptnCore                                                    │
│  FPTNClient → TunnelPool → FPTNTunnel → WebSocketConnection │
│                                      → TLSConnection        │
│  FPTNAPIClient / LoginRace / ReconnectPolicy / SplitTunnel  │
└─────────────────────────────────────────────────────────────┘
```

`FptnCore` не импортирует `NetworkExtension` и не знает про TUN. Это позволяет
запускать 401 unit-тест на Linux (352 в `FptnCore` и 49 в `FptnShared`).
iOS-слой знает только про `PacketSender` и `PacketSink` из `FPTNRelay`.

`FptnShared` также содержит `Localizer` и словари `en.lproj`/`ru.lproj`. UI берёт
готовые строки из `Localizer`, поэтому язык можно менять без перезапуска
приложения; `.system` разрешается через `Locale.preferredLanguages`.

## Хранение токена

`TokenStore` — небольшой протокол с `load`/`save`/`delete`. На Apple-платформах
`TokenStorage.make()` возвращает `KeychainTokenStore` с accessibility
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. На Linux и в тестах
используется `UserDefaultsTokenStore` с той же семантикой (trim, запрет пустого
значения, `nil` для отсутствующего элемента).

Keychain-клиент отделён протоколом `KeychainAccess`, поэтому fallback-логика
`update → add → update` проверяется fake-клиентом без реального Keychain.

`AppModel` загружает токен из Keychain и передаёт его в `VPNController.start`;
`VPNController` кладёт его в `providerConfiguration` VPN-профиля. Расширение
читает `providerConfiguration` и использует legacy-токен только как fallback.
При очистке токена `AppModel` удаляет Keychain-элемент и просит
`VPNController.clearStoredToken()` убрать `token` из профиля.

## Поток данных

### Исходящий пакет

1. `NEPacketTunnelFlow.readPackets` отдаёт IP-пакеты.
2. `FPTNRelay.forwardOutgoing` проверяет split tunnel:
   - CIDR-совпадение → пакет отбрасывается, потому что маршрут уже исключён;
   - SNI-совпадение → destination запоминается для host-маршрута, в TUN
     отправляется TCP RST, пакет не уходит в туннель.
3. `FPTNClient.send` передаёт пакеты в `TunnelPool`.
4. Пул выбирает слот по source port (или round-robin), `FPTNTunnel.send`
   переписывает source IP на выданный сервером адрес и батчит до 64 пакетов.
5. YAFF-сообщение уходит в WebSocket binary frame, затем в TLS-запись.

### Входящий пакет

1. Отдельный reader-поток на каждый слот вызывает
   `FPTNTunnel.receivePackets`.
2. Ping/pong обрабатываются внутри, ошибки сервера превращаются в исключение.
3. `FPTNTunnel` переписывает destination IP на TUN-адрес, если он известен.
4. `FPTNRelay.forwardIncoming` запоминает A/AAAA-адреса для доменных правил и
   отдаёт пакеты в `NEPacketTunnelFlow.writePackets`.

## Rolling pool

`TunnelPool` хранит слоты с `id`, `closeAt` и ссылкой на `PoolTunnel`.

- dual: первый слот живёт 300 с, второй — 600 с;
- triple: 200 / 400 / 600 с;
- замена начинается за 60 с до `closeAt`;
- между заменами выдерживается stagger 15 с;
- поток прибит к слоту по source port: `port % activeCount`;
- без transport-порта используется round-robin;
- один `SessionID` (64 alphanumeric) передаётся во все WebSocket upgrade;
- `nextLifetime` повторяет upstream-логику: новый слот ставится в самый широкий
  интервал между оставшимися lifetime.

Пул синхронный: connector блокируется на TLS/reality handshake. В расширении
`maintain` вызывается из control-очереди, а не из UI.

## Выбор сервера

`LoginRace` сначала делает одну попытку логина на закреплённом сервере
(`preferredServerID` из настроек). Если она успешна, остальные серверы не
опрашиваются. Если нет — закреплённый сервер исключается, а для остальных
запускается обычная гонка по случайной половине. Токен с единственным сервером
сохраняет полный retry budget. После логина пул открывает соединения только к
выбранному серверу.

## Переподключение

`ReconnectPolicy` — скользящее окно: не более 5 попыток за 120 с, затем
экспоненциальная задержка 1/2/4/…/30 с. Исчерпание бюджета переводит клиент в
`.failed`, а не в бесконечный hot loop.

## Split tunnel

`SplitTunnel` умеет:

- CIDR: `IPPrefix.contains`;
- домены: suffix по границе метки (`vk.com` матчит `m.vk.com`, но не `notvk.com`);
- policy `exclude`/`include`;
- разбор TLS ClientHello и SNI;
- разбор DNS-ответов и A/AAAA;
- генерацию TCP RST с корректными checksums.

`TunnelRuntime` всегда объединяет пользовательские CIDR с
`SharedSettings.mandatorySplitCIDRs`: `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`,
`224.0.0.0/4`, `255.255.255.255/32`, `::1/128`, `fc00::/7`, `fe80::/10`,
`ff00::/8`. Поэтому локальные сети и системный трафик не попадают в туннель,
даже если пользователь очистил редактируемый список CIDR.

Доменные правила работают через L7/DNS: `SplitTunnelRouteStore` хранит адреса,
изученные из SNI и DNS A/AAAA. `TunnelRuntime` с debounce 350 мс пересобирает
`excludedRoutes`, добавляя host-маршруты `/32` и `/128`. Это позволяет клиенту
после TCP RST повторить подключение уже напрямую, вне VPN.

## Ошибки и состояния

`FPTNClientState`: `idle → loggingIn → connecting → connected → reconnecting →
stopped | failed(String)`.

`FPTNTunnelStatus`: `active`, `rotate`, `dead`.

`TunnelRuntimeError`: отсутствующий токен, отсутствие выданного адреса, ошибка
установки network settings.
