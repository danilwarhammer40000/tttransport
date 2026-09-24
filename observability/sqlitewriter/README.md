# observability/sqlitewriter

Опциональный backend для `observability.EventWriter` на SQLite
(`modernc.org/sqlite` — чистый Go, без cgo, поэтому нормально
кросс-компилируется под Android через gomobile). Вынесен в отдельный
модуль, потому что зависимость не удалось скачать без сети.

## Сборка у себя

```bash
cd observability/sqlitewriter
go mod tidy
go build ./...
```

## Использование

```go
w, err := sqlitewriter.New("/path/to/turboflare-logs.db")
if err != nil { /* ... */ }
logger := observability.NewLogger(observability.DefaultDevConfig(), w)
```

По умолчанию (Stage 5, основной модуль) используется `JSONLWriter` —
он всегда работает офлайн и ничего дополнительно собирать не нужно.
Подключайте `sqlitewriter`, когда понадобятся SQL-выборки для анализа
(например, "все `incomplete_response` за последний час" — см. §4
PROTOCOL.md).

## Rotation

`Writer.Rotate(maxAge)` удаляет события старше `maxAge` — вызывайте
периодически (например, раз при старте приложения), не на каждую
запись.
