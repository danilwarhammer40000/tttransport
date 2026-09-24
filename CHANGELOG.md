# CHANGELOG

## Stage 1 — proto/ (формат фрейма + крипто)

- Добавлены `proto/crypto.go` (X25519 ECDH, HKDF-SHA256, AES-256-GCM —
  только стандартная библиотека Go) и `proto/frame.go` (handshake- и
  data-фреймы).
- Handshake-фрейм: 69 байт (32 eph_pub + 8 nonce + 29 sealed ciphertext).
- Data-фрейм (первая версия): overhead 33 байта, nonce **не передавался**,
  подразумевался как синхронный счётчик на обеих сторонах.

## Stage 2 — transport/ (сессии, congestion control, reconnect)

### 🔧 Найден и исправлен дизайн-баг: неявный nonce-счётчик

При проектировании session state machine выяснилось, что **implicit
nonce counter из Stage 1 несовместим с уже принятым решением** о том,
что CDN может завершать параллельные HTTP-транзакции не по порядку
(это прямо описано в исходном исследовании, §14/§19, и было учтено в
дизайне sequence-based reassembly). Если nonce не передаётся явно,
получатель не может знать, с каким counter пытаться расшифровать
конкретный пришедший фрейм при переупорядочивании.

**Исправление**: `nonce_counter` стал явным 4-байтным полем в начале
wire-формата data-фрейма (по аналогии с тем, как уже сделано в
handshake-фрейме). Это делает каждый фрейм независимо расшифровываемым
вне зависимости от порядка прихода HTTP-ответов.

- **Overhead data-фрейма пересчитан: 33 → 37 байт** (4 nonce_counter +
  17 header + 16 tag). Всё ещё в пределах "не больше VLESS" по порядку
  величины.
- Добавлена **anti-replay защита** (`transport/replay.go`) — отдельный
  уровень от sequence-based дедупликации: sliding-window по
  nonce_counter (64 позиции), сбрасывается при смене session_key.
- Добавлен **reorder buffer** (`transport/reorder.go`) — сборка
  логического byte-stream из фреймов, приходящих не по порядку,
  идемпотентная обработка дублей по sequence (per §29/§33 исходного
  исследования).

### 🔧 Найден и исправлен дизайн-баг: nonce для handshake при reconnect

При написании `server/server.go` обнаружилось, что `EncodeHandshake`
строил AEAD-nonce с использованием **реального** `connection_id`
(нужного при reconnect), а `DecodeHandshake` пытался открыть шифр с
`connection_id=0` **всегда** — то есть encode/decode расходились на
любом reconnect (non-zero connection_id). Это работало бы только для
совсем новой сессии, что не было замечено, пока не дошло до реализации
сервера.

**Исправление**: handshake AEAD-nonce всегда строится с
placeholder-значением `connection_id=0`, независимо от того, какой
реальный `connection_id` запрашивается внутри зашифрованного payload.
Реальный `connection_id` определяется только после успешной
расшифровки. Добавлен регрессионный тест
`TestHandshakeRoundTrip_Reconnect`.

### Реализовано (без изменений от зафиксированного дизайна)

- `transport/congestion.go` — импульсная burst/baseline модель окна
  (W_baseline=2, W_burst_target=8, W_burst_abs_max=10), консервативный
  block size (target 16KiB, soft max 24KiB, hard max 64KiB), RTT EWMA
  по формуле Джекобсона, штраф на потолок burst после ошибки с
  постепенным восстановлением.
- `transport/reconnect.go` — grace period (5с таймер ИЛИ раннее
  закрытие по подтверждению нового ключа), бюджет на 3 redundant-
  отправки первых фреймов после reconnect.
- `transport/session.go` — связывает всё вместе: device_id,
  connection_id, session_key, атомарные счётчики, encode/decode
  высокого уровня.

## Stage 3 — client/ + server/ (echo поверх HTTP)

- `server/binding.go` — token→device_id биндинг (atomic compare-and-
  set), revoke (ручной + по неактивности, TTL по умолчанию 30 дней).
- `server/server.go` — три эндпоинта: `POST /api/v1/open` (handshake),
  `POST /api/v1/push` (upload), `GET /api/v1/pull` (polling download,
  per §23 исходного исследования — не infinite stream).
- `client/client.go` — симметричная клиентская обвязка: `Open()`,
  `Reconnect()`, `Push()`, `Pull()`.
- `integration/integration_test.go` — end-to-end тесты через
  `httptest.Server`: полный цикл handshake→push→pull, отказ второго
  устройства при активном биндинге, revoke освобождает токен, reconnect
  подтверждает ключ и закрывает grace period.

**Известное упрощение**: provisioning-токен передаётся HTTP-заголовком
(`X-Provision-Token`), а не внутри зашифрованного handshake-payload.
Это защищено внешним TLS-слоем, но не внутренним AEAD-слоем протокола.
Отмечено как то, что стоит пересмотреть, если понадобится, чтобы токен
был защищён от CDN-оператора так же, как остальной payload.

## Stage 3.1 — server/: echo → реальный TCP-forwarding в интернет

- `server.go` переработан: сервер больше не отражает пришедшие payload
  обратно клиенту. Теперь первый payload новой сессии — это **CONNECT
  команда** (`"host:port"` в открытом виде, внутри уже
  AEAD-зашифрованного фрейма — сам протокол это не меняет, меняется
  только то, что сервер делает с расшифрованным payload).
- Сервер открывает реальное TCP-соединение (`net.DialTimeout`) к
  указанному адресу, дальше все последующие payload с клиента пишутся
  в этот сокет как есть, а всё, что приходит от сокета в ответ —
  ставится в очередь на `/pull` через тот же `EncodeOutgoing`/
  sequence/ACK механизм, что и раньше.
- Подтверждение подключения — служебный payload `"OK CONNECTED"`;
  ошибка — `"ERROR: ..."`. Клиент должен дождаться одного из них через
  `/pull`, прежде чем начинать слать реальные данные (см. ограничение
  ниже).
- Добавлен `Server.AllowedTargets` — опциональный allowlist адресов
  (по умолчанию пуст = разрешено всё; open relay на произвольные
  интернет-адреса — сознательный выбор для personal research
  прототипа, но оставлено как явная точка для ограничения позже).
- **Известное ограничение**: если клиент шлёт данные в том же
  HTTP-батче сразу после CONNECT, не дождавшись подтверждения — они
  молча теряются (dial асинхронный). Не влияет на `client.Client`,
  который и так ждёт подтверждения по дизайну.
- `integration/integration_test.go` переписан: вместо проверки echo
  теперь поднимает локальный TCP echo-listener и проверяет полный цикл
  CONNECT → OK CONNECTED → push данных → форвардинг → получение ответа
  обратно через `/pull`. Плюс отдельный тест на `ERROR` при
  недоступном таргете (`127.0.0.1:1`).

## Stage 4 — fingerprint/ (uTLS-интеграция)

- `fingerprint/profiles.go` — данные (без внешних зависимостей): пул из
  3 Android/Chrome-Mobile профилей (TLS ClientHello ID + согласованный
  User-Agent + HTTP2 SETTINGS), функция поиска по ID.
- `fingerprint/utlsclient/` — **отдельный Go-модуль** (требует
  `github.com/refraction-networking/utls`, недоступно без сети в этой
  среде). Реализует `http.RoundTripper` на базе uTLS с профилем.
  Требует `go mod tidy` у вас перед сборкой — см.
  `fingerprint/utlsclient/README.md` с конкретными шагами проверки
  (сверка `HelloChrome_*` констант с реальной версией библиотеки,
  подключение HTTP2 SETTINGS).

## Stage 5 — observability/ (логирование + test mode)

- `observability/logger.go` — категорийные переключатели (per §4),
  `JSONLWriter` (stdlib-only, работает офлайн из коробки), `ShortHash`
  для непубличного сопоставления device_id/session_key в логах без их
  раскрытия.
- `observability/testmode.go` — оркестрация диагностических пробников
  (`Probe`), структурированный summary-отчёт (PASS/WARN/FAIL/INFO),
  готовые reference-реализации для CDN body-limit, RTT baseline,
  reconnect, fingerprint-check пробников (принимают функции, не жёстко
  привязаны к конкретным пакетам — подключаются на месте использования).
- `observability/sqlitewriter/` — **отдельный Go-модуль** (требует
  `modernc.org/sqlite`, чистый Go без cgo — нормально кросс-
  компилируется под Android). Опциональный backend поверх того же
  `EventWriter` интерфейса, что и `JSONLWriter`.

## Stage 6 — android/ (gomobile + Kotlin UI)

- `android/gomobilebridge/` — упрощённый API поверх `client/`,
  совместимый с ограничениями `gomobile bind` (только простые типы:
  string, []byte, error). Зависит только от stdlib-only основного
  модуля — сам мост НЕ требует внешних зависимостей для сборки .aar.
- `android/app/` — Kotlin-скелет: `MainActivity.kt` (Connect / Push
  test / Test Mode кнопки, `NetworkCallback` триггерит `Reconnect()`
  при смене сети), `DeviceIdentity.kt` (постоянный `device_id`,
  генерируется один раз, хранится в `EncryptedSharedPreferences`).
- **Test Mode кнопка на Android — пока заглушка**: реальная проводка
  `observability.TestMode` через `gomobilebridge` не реализована в этом
  скелете (нужно расширить bridge.go bind-совместимыми методами,
  возвращающими результаты пробников).
- **uTLS ещё не подключён в bridge.go** — сейчас `gomobilebridge`
  использует обычный `client.Client` со стандартным TLS Go. Инструкция
  по подключению `utlsclient` — в `android/README.md`.
- gomobile/Android SDK/NDK отсутствуют в среде сборки — `.aar` не
  скомпилирован, только исходники + точные команды сборки.

---

## Что НЕ проверено локально (честно)

В среде, где это собиралось, **нет Go toolchain и нет сети** (не смог
поставить ни `go`, ни системный пакет через apt — тоже упёрлось в
отсутствие сети). Поэтому:

- `proto/`, `transport/`, `client/`, `server/`, `integration/`,
  `observability/` (без sqlitewriter) — код написан и вычитан вручную,
  но **не скомпилирован и не прогнан** через `go build`/`go test`.
  Это первое, что нужно сделать у себя: `go build ./... && go test ./... -v`
  из корня репозитория (модуль `turboflare-transport`, все эти пакеты
  в него входят, `go.mod` уже есть).
- `fingerprint/utlsclient/`, `observability/sqlitewriter/` — отдельные
  модули, нужен `go mod tidy` с доступом к сети перед сборкой.
- `android/` — нужен gomobile + Android SDK/NDK, ничего не собрано.

Если при первом прогоне тестов что-то не сойдётся — присылайте вывод
ошибки, поправлю точечно.

## Stage 7 — android/vpntun/: полноценный VPN-клиент со split tunneling

- `android/vpntun/tunnel.go` — userspace TCP/IP стек на TUN
  file descriptor через gVisor netstack (`gvisor.dev/gvisor/pkg/tcpip`).
  Каждый перехваченный TCP-flow становится отдельной сессией
  существующего `client.Client` (handshake + CONNECT + relay) — сам
  протокол не менялся ни на байт, только появился новый "адаптер" между
  Android TUN-интерфейсом и уже работающим CONNECT-механизмом.
- **Известные ограничения** (см. `android/vpntun/README.md` подробно):
  один handshake на каждый TCP-flow (нет мультиплексирования через
  `stream_id`, хотя поле уже есть в wire-формате); UDP не
  обрабатывается вообще (только TCP relay).
- `android/gomobilebridge/bridge.go` — добавлены `StartVpnTunnel` и
  `VpnTunnelHandle` (gomobile-bind-совместимая обёртка).
- Kotlin: `AppSelectionStore.kt` + `AppSelectionActivity.kt` — выбор
  приложений для split tunnel (хранится в `SharedPreferences`, читается
  сервисом при построении VPN). `TurboflareVpnService.kt` — сам
  VPN-сервис: строит TUN через `VpnService.Builder`, применяет
  `addAllowedApplication` для выбранных пакетов (Android-нативный
  split tunnel — только выбранные приложения идут в тоннель, остальные
  бай-пасят напрямую), передаёт TUN fd в Go.
- `MainActivity.kt` — кнопки Select Apps / Start VPN / Stop VPN,
  обработка `VpnService.prepare()` через `ActivityResultContracts`.
- `AndroidManifest.xml` — добавлены `FOREGROUND_SERVICE`,
  `POST_NOTIFICATIONS`, объявление VPN-сервиса с
  `BIND_VPN_SERVICE`/`android.net.VpnService` intent-filter, `<queries>`
  для перечисления установленных приложений (package visibility,
  Android 11+).
- **Важный компромисс**: зависимость `gvisor.dev/gvisor` добавлена в
  ОСНОВНОЙ `go.mod` (не изолированный модуль, как было с uTLS/SQLite) —
  потому что VPN-функциональность должна собираться в один `.aar`
  вместе с `gomobilebridge`. Следствие: `go build ./...`/`go test
  ./...` для всего проекта **больше не гарантированно офлайн** — нужна
  сеть хотя бы раз для `go mod tidy`.

## Stage 7.1 — DNS-relay: фикс "интернет не работает" на реальном устройстве

При первом реальном тесте VPN на телефоне обнаружилось: выбранные в
split tunnel приложения не могли зайти ни на один сайт
(`DNS_PROBE_FINISHED_NO_INTERNET` в Chrome, `ERR_NAME_NOT_RESOLVED` в
Яндекс.Браузере). Причина — `vpntun` изначально обрабатывал только TCP
(задокументировано как known limitation), а DNS-запросы идут по UDP;
Android заставляет туннелируемые приложения резолвить DNS через
VPN-интерфейс, и эти UDP-пакеты просто отбрасывались стеком.

**Фикс**: `android/vpntun/tunnel.go` — добавлен UDP-forwarder
(регистрация `udp.NewProtocol` в стеке), перехватывающий только порт
53 (DNS). Каждый перехваченный DNS-запрос конвертируется в
DNS-over-TCP (RFC 1035 §4.2.2, поддерживается всеми публичными
резолверами) и прогоняется через **одну** постоянную CONNECT-сессию к
`1.1.1.1:53`, открытую один раз на весь срок жизни туннеля (не по
сессии на запрос — иначе overhead handshake на каждый DNS-запрос был
бы неприемлем). Запросы сериализуются через mutex — простое и
корректное решение для персонального использования, но не
масштабируется на много параллельных запросов (см.
`android/vpntun/README.md`).

Протокол (`proto/`, `client/`, `server/`) не менялся вообще — DNS-relay
использует ровно тот же CONNECT-механизм, что и обычный TCP-relay,
просто с одной постоянной сессией вместо одной на flow.

**Весь остальной UDP** (кроме DNS) по-прежнему не обрабатывается —
известное ограничение, актуально для QUIC/HTTP3 и других
UDP-протоколов.
