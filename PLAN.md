# План

## Сделано

- [x] Изучить Android/iOS upstream, Rust-порт и C++ FPTN.
- [x] Платформонезависимый `FptnCore`.
- [x] YAFF, FPTN token, HTTP API, WebSocket.
- [x] TLS 1.3, `TlsObfuscator2`, reality.
- [x] IP rewrite/checksums, keepalive, NTP.
- [x] `FPTNTunnel`, `TunnelPool`, login race, reconnect budget.
- [x] Split tunnel CIDR + domain/SNI/DNS.
- [x] Обязательные CIDR для локальных сетей и системного трафика.
- [x] Динамические host-маршруты `/32`/`/128` из DNS/SNI на iOS.
- [x] Полный список доменов OpenWRT (2158) в `FptnShared`.
- [x] Импорт пользовательского `.txt`-списка доменов в UI.
- [x] On-Demand по умолчанию + переключатель ручного режима.
- [x] Локализация RU/EN с выбором системного языка в настройках.
- [x] Keychain для токена + миграция из App Group `UserDefaults`.
- [x] `Assets.xcassets` с оригинальной app icon (генератор в `Tools/AppIcon`).
- [x] Закреплённый сервер влияет на login race, с fallback на остальные.
- [x] `FPTNClient`, `FPTNRelay`.
- [x] iOS SwiftUI app с темами Aurora/Ember.
- [x] NetworkExtension skeleton.
- [x] Linux tests: 401 (352 core + 49 shared), 0 падений, 0 warnings.
- [x] Linux live probe: login/DNS/tunnel/DNS через туннель, plain/obfuscated/reality.
- [x] Проверить на реальном FPTN-сервере все три режима маскировки (`Tools/LiveProbe`).
- [x] CI macOS job для сборки без подписи.

## Следующие шаги

- [ ] Собрать iOS app и extension на macOS.
- [ ] Метрики трафика из extension в app.
- [ ] UI-тесты и snapshot-тесты тем.
- [ ] Проверить, что `swift build` не даёт предупреждений на Swift 6 language mode.

## Открытые вопросы

1. Нужна ли строгая проверка цепочки сертификатов для не-FPTN серверов?
2. Нужен ли Always On / принудительный on-demand без ручного отключения?
3. Как показывать трафик: байты, скорость, график?
4. Нужна ли третья светлая тема?
