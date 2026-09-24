# turboflare-transport

Личный исследовательский протокол транспорта через CDN. Полная
спецификация и журнал решений — в [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
Полная история находок и исправлений по этапам — в
[`CHANGELOG.md`](CHANGELOG.md) (там же — два дизайн-бага, найденные и
исправленные по ходу реализации, важно прочитать перед тем, как
разбираться в коде).

## Статус: все 6 этапов реализованы (код написан, но НЕ скомпилирован)

**Важно:** среда, в которой это писалось, не имела ни Go toolchain, ни
сети — код вычитан вручную, но `go build`/`go test` ни разу не
прогонялись. Это первое, что нужно сделать у себя.

```
[x] Stage 1: proto/           — формат фрейма + крипто
[x] Stage 2: transport/       — сессии, congestion control, reconnect
[x] Stage 3: client/, server/ — echo поверх HTTP (handshake/push/pull)
[x] Stage 4: fingerprint/     — профили + uTLS-обвязка (отдельный модуль)
[x] Stage 5: observability/   — логирование + test mode
[x] Stage 6: android/         — gomobile-мост + Kotlin UI (скелет)
```

## Сборка и тесты

### Основной модуль (офлайн-собираемый, без внешних зависимостей)

```bash
cd turboflare-transport
go build ./...
go test ./... -v
```

Покрывает: `proto/`, `transport/`, `client/`, `server/`, `integration/`,
`observability/`, `android/gomobilebridge/`.

Ключевые тесты, на которые стоит посмотреть в первую очередь:
- `proto`: `TestHandshakeRoundTrip_Reconnect`,
  `TestDataFrameOutOfOrderStillDecodes` — регрессионные тесты на два
  бага, найденных и исправленных в Stage 2 (см. CHANGELOG).
- `transport`: `TestCongestionController_BurstJumpsAndReturnsToBaseline`,
  `TestReconnectState_GraceClosesEarlyOnConfirmation`.
- `integration`: `TestEndToEnd_HandshakePushPullEcho` — полный цикл
  через реальный `net/http/httptest` сервер.

### Модули с внешними зависимостями (нужна сеть на вашей стороне)

```bash
cd fingerprint/utlsclient && go mod tidy && go build ./...
cd observability/sqlitewriter && go mod tidy && go build ./...
```

См. README в каждой директории — там же список того, что нужно
сверить/поправить после первой сборки (например, соответствие
`HelloChrome_*` констант установленной версии uTLS).

### Android

Нужен `gomobile` + Android SDK/NDK — см. `android/README.md` для
точных команд. Ничего не скомпилировано, только исходники.

## Если что-то не соберётся

Пришлите вывод ошибки — поправлю точечно, без необходимости
пересобирать всё заново.
