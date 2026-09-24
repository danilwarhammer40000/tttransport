# android/

Скелет Android-клиента. **Не собирается «под ключ»** без Android
SDK/NDK и `gomobile`, которых нет в среде, где это генерировалось —
здесь только код и точные команды.

## 1. Собрать .aar из Go-моста

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

cd /path/to/turboflare-transport
gomobile bind -target=android -androidapi 26 -o gomobilebridge.aar ./android/gomobilebridge
```

`android/gomobilebridge` зависит только от `client/`, `transport/`,
`proto/` — все три собираются офлайн (без внешних зависимостей), так
что этот шаг НЕ требует сети сам по себе, если у вас уже есть Go
toolchain и Android NDK локально.

## 2. Подключить .aar к Android-проекту

Положите `gomobilebridge.aar` в `android/app/libs/` и добавьте в
`android/app/build.gradle`:

```gradle
dependencies {
    implementation files('libs/gomobilebridge.aar')
    implementation 'androidx.security:security-crypto:1.1.0-alpha06' // EncryptedSharedPreferences
    implementation 'androidx.core:core-ktx:1.13.1'
    implementation 'androidx.appcompat:appcompat:1.7.0'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1'
}
```

## 3. Заполнить конфиг

В `MainActivity.kt` замените:
- `serverStaticPubHex` — публичный X25519-ключ вашего сервера (см.
  `server/` — сгенерируйте статическую пару один раз, захардкодьте
  публичный ключ сюда, приватный держите только на сервере).
- `provisionToken` — токен, выданный через ваш provisioning-флоу
  (Telegram-бот и т.д., см. `server/binding.go`).

## 4. Что ещё не реализовано в этом скелете

- **Test Mode кнопка** — заглушка (`onTestModeClicked`). Реальное
  подключение `observability.TestMode` требует расширения
  `android/gomobilebridge/bridge.go` методами, возвращающими
  bind-совместимые результаты пробников (сейчас `observability/`
  ориентирован на использование из Go-кода напрямую, не через
  gomobile).
- **uTLS-fingerprint** — `gomobilebridge` сейчас использует стандартный
  TLS-стек Go (через `client.Client`), не `fingerprint/utlsclient`.
  Чтобы подключить — замените `client.New(...)` в `bridge.go` на
  вариант с `HTTPClient`, собранным через
  `utlsclient.NewHTTPClient(profile)` (см.
  `fingerprint/utlsclient/README.md`), не забыв сначала `go mod tidy`
  в том подмодуле.

## 5. VPN-режим (Stage 7)

Полноценный VPN-клиент со split tunneling поверх того же протокола —
см. `android/vpntun/README.md` для Go-стороны (там же — как дособрать
gVisor-зависимость, нужна сеть).

Новые файлы на Kotlin-стороне (уже включены в этот скелет):
- `AppSelectionStore.kt` / `AppSelectionActivity.kt` — выбор
  приложений для тоннелирования (split tunnel: только выбранные
  приложения идут через VPN, остальные — напрямую в интернет, через
  стандартный механизм Android `VpnService.Builder.addAllowedApplication`)
- `TurboflareVpnService.kt` — сам VPN-сервис (TUN-интерфейс,
  foreground-уведомление, передача TUN fd в Go)
- `MainActivity.kt` — добавлены кнопки Select Apps / Start VPN / Stop
  VPN, обработка системного разрешения `VpnService.prepare()`

`AndroidManifest.xml` обновлён — добавлены разрешения
(`FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`), объявление VPN-сервиса,
экрана выбора приложений, и `<queries>` для получения списка
установленных приложений (Android 11+ package visibility).

**Порядок сборки не меняется** — `gomobile bind` для `gomobilebridge`
теперь захватывает и VPN-функциональность, раз `android/vpntun/`
импортируется из `bridge.go`. Просто сначала дособерите зависимость
gVisor (см. `android/vpntun/README.md`), потом обычный `gomobile bind`.
