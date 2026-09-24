# fingerprint/utlsclient

Отдельный Go-модуль (не часть основного `turboflare-transport` модуля),
потому что зависит от `github.com/refraction-networking/utls`, которую
я не смог скачать в среде без сети.

## Сборка у себя

```bash
cd fingerprint/utlsclient
go mod tidy    # подтянет github.com/refraction-networking/utls
go build ./...
```

## Что нужно проверить/поправить после первой сборки

1. **`clientHelloIDByName`** в `utlsclient.go` — сверьте с реально
   экспортируемыми константами `utls.HelloChrome_*` в скачанной версии
   библиотеки (`go doc github.com/refraction-networking/utls`), там
   могут не быть отдельного профиля под каждую версию Chrome из
   `fingerprint/profiles.go` — временный fallback на ближайший
   доступный профиль пока приемлем, но стоит пересмотреть.
2. **HTTP2Settings** — на момент написания API для явного оверрайда
   SETTINGS-фрейма через uTLS зависит от конкретной версии пакета;
   проверьте его h2-подпакет и подключите `rt.Profile.HTTP2Settings`
   там, где это возможно (сейчас они хранятся в `Profile`, но не
   применяются напрямую — TODO, отмечен в коде).
3. Как только модуль собирается — прогоните `observability` test-mode
   (Stage 5) на реальном домене, чтобы получить вердикт
   `tls_fingerprint` / `http2_settings` PASS/WARN/FAIL и свериться
   с ожиданиями.

## Подключение к основному клиенту

`client.Client.HTTPClient` — обычный `*http.Client`. Чтобы включить
uTLS-fingerprint вместо стандартного TLS-стека Go:

```go
httpClient, err := utlsclient.NewHTTPClient(fingerprint.Pool[0])
if err != nil { /* ... */ }

c := client.New(baseURL, serverStaticPub, deviceID, token)
c.HTTPClient = httpClient
```

Не забудьте также проставлять `User-Agent` из `profile.UserAgent` на
каждый исходящий запрос — `RoundTripper` этим не занимается сам
(намеренно, см. комментарий в коде), это ответственность вызывающего
слоя (`client.Client`), чтобы не создавать скрытую магию.
