# Сборка

## Ядро (Linux/macOS)

```bash
swift test
```

Пакет не содержит iOS-кода, поэтому работает без Xcode. На текущей машине:

```bash
/home/vasek/opt/swift-6.4.2/usr/bin/swift test --package-path /home/vasek/FptnClient-iOS
```

## Живая проверка ядра (Linux/macOS)

```bash
FPTN_LIVE_TOKEN_FILE=/path/to/fptn-token \
  swift run --package-path Tools/LiveProbe FptnProbe
```

Инструмент проверяет login, DNS API, TLS/WebSocket/YAFF, выдачу IP и DNS-запрос
через туннель. Параметры `FPTN_LIVE_MODE`, `FPTN_LIVE_SERVER` и
`FPTN_LIVE_CLIENT` описаны в [Tools/LiveProbe/README.md](../Tools/LiveProbe/README.md).

## iOS (macOS + Xcode)

### 1. Инструменты

```bash
brew install xcodegen
xcodebuild -version
```

Требуется Xcode 16+ и iOS 17 SDK.

### 2. Генерация проекта

```bash
xcodegen generate
open FptnClient.xcodeproj
```

`FptnClient.xcodeproj` генерируется из `project.yml` и не коммитится.

### 3. Идентификаторы

В `project.yml` и `Shared/SharedSettings.swift` замените:

| Что | Значение |
|---|---|
| App bundle id | `com.example.fptnclient` |
| Extension bundle id | `com.example.fptnclient.tunnel` |
| App Group | `group.com.example.fptnclient` |
| Development team | `DEVELOPMENT_TEAM` |

Одинаковые App Group должны быть у app и extension. Bundle id расширения
должен совпадать с `VPNController.providerBundleIdentifier`.

### 4. Подпись

- Включите capability **Network Extensions** для обоих targets.
- Включите **App Groups** для обоих targets.
- Для симулятора можно собрать без подписи:

```bash
xcodebuild \
  -project FptnClient.xcodeproj \
  -scheme FptnClient \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Для устройства нужен provisioning profile с entitlement
`com.apple.developer.networking.networkextension` и значением
`packet-tunnel-provider`.

### 5. Запуск

1. Установите приложение на устройство.
2. Импортируйте токен.
3. Нажмите Connect.
4. iOS покажет системный запрос на добавление VPN-конфигурации.
5. После подключения проверьте Diagnostics и системный индикатор VPN.
6. В Settings → Appearance переключите язык и убедитесь, что интерфейс
   обновился без перезапуска.

## CI

`.github/workflows/ci.yml`:

- `core` — Ubuntu, `swift test`;
- `ios-build` — macOS, XcodeGen + `xcodebuild` без подписи.

macOS job не запускает extension и не проверяет живой сервер; это только
компиляция и линковка.

## Известные ограничения сборки

- Иконка приложения генерируется скриптом `Tools/AppIcon/generate.py`; для
  App Store перед публикацией проверьте её на устройстве и при необходимости
  замените финальным дизайном.
- Нет launch screen storyboard; используется пустой `UILaunchScreen`.
- `DEVELOPMENT_TEAM` пустой; для устройства его нужно заполнить.
- iOS 17 — минимальная версия; более старые iOS не поддерживаются.
