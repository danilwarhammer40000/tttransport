# TurboFlare Transport — Protocol Specification

Личный исследовательский протокол: транспорт произвольных данных через
TurboFlare CDN как последовательность коротких независимых HTTP-транзакций
(а не один долгоживущий stream), с отдельным слоем шифрования поверх TLS.

Этот документ фиксирует все решения, принятые в ходе проектирования,
и служит источником правды для реализации в `proto/`, `transport/`,
`fingerprint/`, `observability/`.

Статус: **Stage 1 завершён** (proto/ — формат фрейма + крипто).

---

## §0. Идентификация и формат фрейма

### Иерархия идентификаторов

```
device_id     — постоянный, генерируется локально на устройстве один раз,
                8 байт (HKDF от локального random seed)
connection_id — логическая сессия, 4 байта, выдаётся сервером,
                живёт часами/днями, переживает смену сети
session_key   — эфемерный, новый X25519 handshake на каждое
                (пере)подключение, даёт forward secrecy
```

### Device binding (не hardware, а account/token)

- Провижининг-ссылка/токен привязана к аккаунту (например, Telegram),
  не к железу.
- `device_id` генерируется на устройстве, но становится "активным" только
  после первого успешного handshake с данным токеном.
- Сервер хранит биндинг `(token → device_id)` атомарно (compare-and-set):
  один активный `device_id` на токен одновременно.
- Второе устройство с тем же токеном, пока первое активно → REJECT.
- Revoke: вручную (команда пользователю) или авто по неактивности —
  освобождает токен для нового `device_id` без переиздания ссылки.

### Handshake frame (первый фрейм сессии и каждый reconnect)

```
eph_pub      32B   X25519 ephemeral public key, cleartext
nonce        8B    explicit monotonic counter, cleartext, старт = 0
                    для ЭТОГО session_key (никогда не переиспользуется
                    между разными ключами)
ciphertext   29B   AES-256-GCM seal(13-байтного plaintext), tag включён
  device_id       8B
  connection_id   4B   (0x00000000 = запрос новой сессии)
  flags           1B
```

**Итого: 69 байт.** Закреплено тестом `TestHandshakeWireSizeConstant`.

### Data frame (все фреймы после handshake)

```
nonce_counter 4B   cleartext, уникален для (connection_id, session_key)
ciphertext   var   AES-256-GCM seal(plaintext), tag включён
  connection_id   4B
  stream_id       2B   (0, если мультиплексирование не используется)
  sequence        4B
  ack             4B
  flags           1B
  payload_length  2B
  payload         var
```

**Пересмотрено в Stage 2 (см. CHANGELOG.md):** изначально nonce_counter
не передавался (подразумевался синхронный счётчик), но это несовместимо
с переупорядочиванием HTTP-транзакций, задокументированным в исходном
исследовании (§14/§19) — сервер не мог бы знать, каким counter
расшифровывать пришедший не по порядку фрейм. Теперь nonce_counter —
явное 4-байтное поле, что делает каждый фрейм независимо
расшифровываемым вне зависимости от порядка доставки. Replay-защита
(sliding window по nonce_counter) вынесена в отдельный уровень
(`transport/replay.go`), отдельно от sequence-based reassembly.

**Overhead: 37 байт** (4 nonce_counter + 17 header + 16 tag), без
payload. Сопоставимо по порядку величины с VLESS.

### Flags (битовая маска, комбинируются)

```
OPEN  = 0x01   DATA = 0x02   ACK  = 0x04   FIN = 0x08
RESET = 0x10   PING = 0x20   PONG = 0x40
KEY_CONFIRMED = 0x80   — сервер подтвердил переход на новый session_key
                          при reconnect (закрывает grace period досрочно)
```

### Reconnect (смена сети wifi↔LTE)

- Grace period: **3–5 сек таймер ИЛИ** явное подтверждение нового ключа
  (`KEY_CONFIRMED` в ACK) — что раньше.
- Первые data-фреймы после нового handshake шлются **×3 дублированно**
  (одинаковый `sequence`) до подтверждения нового ключа; дедупликация
  на сервере — по `(connection_id, sequence)`.
- Если grace period истёк без подтверждения — сессия считается потерянной,
  локальный state обнуляется, стартует новая сессия с новым `connection_id`.

### Размер блока данных (block_size)

```
B_min = 4 KiB    B_max = 64 KiB (технический потолок CDN, по тестам)
target_block ≈ 16 KiB, рабочий диапазон 8–24 KiB (сознательно ниже потолка)
```

---

## §1–2. Congestion control + traffic shaping (объединены)

**Принцип: не максимальный throughput, а минимальная аномальность.**
Транспорт намеренно работает заметно ниже технического предела CDN.

### Импульсная (burst) модель роста окна

```
W_baseline = 1–2     (простой/idle — почти незаметный фон)
W_burst    = 6–10     (всплеск при накоплении очереди данных на отправку,
                        скачком, не постепенно — как реальный браузер
                        при загрузке страницы)
```

- Burst стартует при непустой очереди данных, держится пока очередь не
  опустеет либо до burst_timeout (~1–2 сек).
- После burst — скачок обратно до `W_baseline` (тоже резко, не плавно).
- **Любая ошибка внутри burst** — немедленный обрыв burst, откат до
  baseline, временное (~20%) снижение потолка следующего burst
  (восстанавливается после нескольких чистых циклов).
- `W_burst` всегда ниже уровня, где в экспериментах начинались
  incomplete response.

### Реакция на события (раздельно window vs block_size)

| Событие | Реакция |
|---|---|
| Timeout / 5xx | `W -= 1` (линейно, не /2), retransmit с backoff |
| Incomplete response | `B -= 4KiB` (режем **block_size**, не окно) |
| Успех (после длительного чистого периода) | редкий, малый рост |

### RTT

EWMA как в TCP: `RTT_avg = RTT_avg*0.875 + sample*0.125`,
`timeout = RTT_avg + 4*RTT_var` (формула Джекобсона), границы 500мс–10сек.

Congestion state — **общий на connection_id** (не раздельно по stream_id),
для простоты на этапе прототипа.

---

## §3. TLS/HTTP fingerprint

- База — **uTLS**, но не "голый": используется через обёртку, которая
  синхронно задаёт согласованный TLS ClientHello **и** HTTP/2 SETTINGS/
  порядок заголовков под один и тот же профиль браузера (в духе
  tls-client / curl-impersonate), чтобы не было рассинхрона между
  уровнями.
- Native (naiveproxy/Cronet, полный Chromium-стек) — **отложено**
  (build-сложность, медленная итерация при активном дизайне протокола).
  System WebView — возможный промежуточный шаг, если uTLS+HTTP2-связка
  всё ещё детектируется на тестах.
- Платформа разработки — **только Android**.
- Пул из нескольких (3–5) правдоподобных Android/Chrome-Mobile профилей,
  **рандомизация один раз** при активации `device_id` через token,
  дальше профиль фиксирован на весь срок жизни устройства (клиент не
  меняет "браузер" сам по себе).
- Архитектурно профиль хранится отдельным конфигом (не хардкод), чтобы
  позже можно было добавить in-app обновление профиля без переделки кода.
- `Accept-Language`/локаль — берётся из реальных системных настроек
  устройства, без отдельной гео-подмены.

---

## §4. Observability

- Dev-сборка: **максимальное логирование** по умолчанию, с
  per-категорийными переключателями (tx_send/ack/error, congestion
  window/block/burst, handshake, connection lifecycle, network iface
  change, token binding, tls profile, http2 settings, raw HTTP headers)
  + глобальный уровень verbosity (DEBUG/INFO/SILENT_EXCEPT_ERRORS).
- `raw.http_headers` — отдельный флаг (самый "тяжёлый"), нужен для
  сверки fingerprint.
- **Никогда не логируются**: session_key, eph_priv/eph_pub, device_id
  в открытом виде (только короткий хэш-префикс для сопоставления),
  содержимое payload, токен провижининга целиком.
- Хранение: SQLite, таблица `events(ts, event_type, conn_id_prefix,
  payload_json)`, rotation по размеру/возрасту.
- **Test mode** (отдельный от боевого трафика режим): активные проверки
  — TLS fingerprint match, HTTP/2 SETTINGS match, CDN body-size limits /
  incomplete response, streaming/long-response поведение, reconnect /
  device-binding, RTT baseline — со структурированным summary-отчётом
  (PASS/WARN/FAIL по каждому пункту) в конце прогона.

---

## Roadmap

```
[x] Stage 1: proto/     — формат фрейма + крипто (X25519, HKDF, AES-256-GCM)
[x] Stage 2: transport/ — сессии, congestion control, reconnect
[x] Stage 3: client/server — echo поверх proto/ (localhost)
[x] Stage 4: fingerprint/ — uTLS-интеграция
[x] Stage 5: observability/ — логирование + test mode
[x] Stage 6: android/ — gomobile-сборка + Kotlin UI
```

Подробности реализации, найденные по ходу дизайн-баги и их исправления
— см. [`CHANGELOG.md`](../CHANGELOG.md).
