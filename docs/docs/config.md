## Конфигурация Equality

### Режимы работы

- **Client (SOCKS → EQ/Direct)**: принимает SOCKS5, отправляет через EQ или напрямую
- **Server (EQ → Target)**: принимает EQ, отправляет на целевой сервер

### Структура

```xml
<config ver="1" shutdown_timeout="10" verbose="true">
    <in type="..." port="..." ... />
    <out type="..." ... />
</config>
```

#### Атрибуты `<config>`

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `ver` | - | Версия конфигурации (всегда `1`) |
| `shutdown_timeout` | 10 | Таймаут при выключении (секунды) |
| `verbose` | false | Подробное логирование |

---

### Блок `<in>` — Входящие соединения

#### `type="socks"` — SOCKS5 прокси

Простейшая конфигурация:

```xml
<in type="socks" port="1080" />
```

Только параметр `port` имеет значение, остальные игнорируются.

---

#### `type="eq"` — EQ сервер

```xml
<in type="eq" port="443" clock="20" frame="700">
    <sid>
        <item>secret-key-min-16-chars-abc123</item>
    </sid>
</in>
```

| Параметр | Обязательный | Описание |
|----------|--------------|----------|
| `port` | ✓ | Порт для прослушивания |
| `clock` | ✓ | Интервал отправки кадров (мс) |
| `frame` | ✓ | Размер кадра (100-65535 байт) |

##### `<sid>` — Ключи аутентификации

```xml
<sid>
    <item>key-1-production-v1</item>
    <item>key-2-production-v2</item>
</sid>
```

- Минимум 16 символов
- Можно несколько для ротации
- Генерация: `openssl rand -hex 32`

##### `<ssl>` — TLS (опционально)

```xml
<ssl
 key="/path/to/private.key"
 crt="/path/to/certificate.crt"
/>
```

##### `<reverse>` — Обратный прокси (опционально)

Все соединения → один адрес:

```xml
<reverse host="127.0.0.1" port="8080" />
```

---

### Блок `<out>` — Исходящие соединения

Используется только в client mode (`in.type="socks"`).

#### `type="freedom"` — Прямое подключение

```xml
<out type="freedom" />
```

Простой SOCKS5 прокси без шифрования/обфускации. Параметры не требуются.

---

#### `type="eq"` — Через EQ протокол

```xml
<out
 type="eq"
 server="your-server.com"
 port="443"
 sid="same-key-as-server"
 clock="20"
 frame="700"
/>
```

| Параметр | Описание |
|----------|----------|
| `server` | IP или домен EQ сервера |
| `port` | Порт EQ сервера |
| `sid` | Ключ (должен быть в `<sid>` сервера) |
| `clock` | Интервал (мс), **должен совпадать с сервером** |
| `frame` | Размер кадра (байты), **должен совпадать с сервером** |

---

### Параметры производительности

#### `clock` — Интервал отправки (миллисекунды)

| Значение | Латентность | Применение |
|----------|-------------|------------|
| 10 | Низкая | SSH, gaming |
| 20 | Средняя | **Универсальный** |
| 50-100 | Высокая | Загрузка файлов |

#### `frame` — Размер кадра (байты)

| Значение | Эффективность | MTU |
|----------|---------------|-----|
| 300-500 | Низкая | Мобильные сети |
| 700-900 | Средняя | **Рекомендуется** |
| 1400-1500 | Высокая | Стандартный MTU |

**Пропускная способность:**
```
max_throughput ≈ (frame - 3) × (1000 / clock) байт/сек
```

Пример: frame=700, clock=20 → ~34.85 MB/s теоретически

---

### Примеры конфигураций

#### 1. Простой SOCKS5 прокси

```xml
<config ver="1">
    <in type="socks" port="1080" />
    <out type="freedom" />
</config>
```

#### 2. SOCKS → EQ клиент

```xml
<config ver="1">
    <in type="socks" port="1080" />
    <out
     type="eq"
     server="eq.example.com"
     port="443"
     sid="production-key-2024-abc123"
     clock="20"
     frame="700"
    />
</config>
```

#### 3. EQ сервер (любой target)

```xml
<config ver="1">
    <in type="eq" port="443" clock="20" frame="700">
        <sid>
            <item>production-key-2024-abc123</item>
        </sid>
        <ssl
         key="/etc/letsencrypt/live/example.com/privkey.pem"
         crt="/etc/letsencrypt/live/example.com/fullchain.pem"
        />
    </in>
    <out type="eq" />
</config>
```

Target берётся из AUTH фрейма клиента.

#### 4. EQ сервер (обратный прокси)

```xml
<config ver="1">
    <in type="eq" port="443" clock="20" frame="700">
        <sid>
            <item>webserver-key-2024</item>
        </sid>
        <ssl
         key="/etc/ssl/private/server.key"
         crt="/etc/ssl/certs/server.crt"
        />
        <reverse host="127.0.0.1" port="8080" />
    </in>
    <out type="eq" />
</config>
```

Все соединения → localhost:8080 (например, nginx).

---

### Безопасность

#### Ротация ключей

1. Добавить новый SID:
```xml
<sid>
    <item>old-key</item>
    <item>new-key-2024</item>
</sid>
```

2. Перезапустить сервер
3. Обновить клиентов
4. Удалить старый ключ

#### Рекомендации

- ✅ TLS обязателен в production
- ✅ SID ≥32 символа
- ✅ Регулярная ротация ключей
- ✅ Firewall: только нужные порты
- ❌ Не использовать `verbose=true` в production
