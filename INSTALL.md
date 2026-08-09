# Установка RiseVPN

Эта инструкция разворачивает один центральный сервер RiseVPN Control и одну или
несколько локаций RiseVPN Node. Команды рассчитаны на release `v0.2.5`.

> Коммерческий запуск нельзя считать завершённым без юридического заключения,
> реквизитов оператора, политики обработки персональных данных, российского
> размещения основной БД/backup и acceptance-теста с актуальным v2RayTun.

## 1. Что понадобится

### Центральный сервер

- VPS в РФ с публичным статическим IP, минимум 4 vCPU, 8 ГБ RAM и 80 ГБ SSD;
- Ubuntu 24.04 или 26.04 `amd64`/`arm64`;
- два домена, например `risevpn.example` и `control.risevpn.example`;
- Docker Engine с Compose plugin, Git и OpenSSL;
- Telegram-бот с OIDC Client ID и Client Secret;
- S3-совместимое хранилище в РФ для зашифрованных backup.

Официальная установка Docker для Ubuntu описана в
[Docker Docs](https://docs.docker.com/engine/install/ubuntu/). Не используйте
`get.docker.com` для production: Docker рекомендует официальный APT-репозиторий.

### Каждая локация

- отдельный VPS с чистой Ubuntu 26.04;
- `amd64` или `arm64`, публичный статический IP;
- отдельный домен, например `msk-1.example`;
- HTTPS-сайт-маскировка, принадлежащий оператору.

### DNS и порты

До установки создайте A/AAAA-записи:

| Имя | Куда направить |
| --- | --- |
| `risevpn.example` | IP центрального сервера |
| `control.risevpn.example` | IP центрального сервера |
| `msk-1.example` | IP сервера локации |

На центральном сервере разрешите входящие TCP 80, TCP 443 и UDP 443. На узле —
TCP 80, TCP/UDP 443 и временно TCP 8443. После enrollment агент сам перестанет
слушать 8443. Панель управления облачного провайдера должна разрешать эти порты
даже при наличии локального firewall.

## 2. Подготовка RiseVPN Control

Подключитесь к центральному VPS и клонируйте репозиторий:

```bash
sudo apt update
sudo apt install -y git openssl ca-certificates
cd "$HOME"
git clone https://github.com/mirrage11gpt/rmvpn.git risevpn
cd "$HOME/risevpn"
git checkout main
git pull --ff-only origin main
docker --version
docker compose version
```

Домашний каталог выбран намеренно: на некоторых VPS `/opt` доступен Docker
daemon только для чтения. Если репозиторий уже находится в `/opt/risevpn`,
скопируйте его без удаления исходной копии:

```bash
mkdir -p "$HOME/risevpn"
cp -a /opt/risevpn/. "$HOME/risevpn/"
cd "$HOME/risevpn"
```

Проверьте, что Docker daemon локальный и видит bind mounts из текущего каталога:

```bash
docker context show
findmnt -T "$PWD" -no TARGET,OPTIONS
docker run --rm -v "$PWD:/src:ro" alpine:3.23 \
  test -f /src/docker-compose.yml
```

Первая команда обычно должна показать `default`, а последняя — завершиться без
ошибки. Если Docker сообщает `read-only file system` или не видит файл:

- при remote context bind path ищется на машине Docker daemon, а не на VPS с CLI;
- для LXC/OpenVZ хостер должен разрешить nesting и bind mounts;
- если эти возможности недоступны, используйте KVM-VPS.

Не продолжайте установку до успешной проверки: Compose использует bind mounts
для Caddyfile, backup-скрипта и Docker secrets.

### Telegram OIDC

Создайте бота через `@BotFather`, откройте для него **Login Widget** и добавьте:

- Allowed origin: `https://risevpn.example`;
- Redirect URI: `https://risevpn.example/auth/telegram/callback`.

BotFather покажет Client ID и Client Secret. Telegram требует заранее
зарегистрировать redirect URI; актуальное описание находится в
[Telegram Login](https://core.telegram.org/bots/telegram-login).

### Переменные окружения

Создайте рабочий файл:

```bash
cp .env.example .env
```

Сгенерируйте криптографические значения. Эта команда не использует bind mount,
поэтому работает даже до исправления доступа Docker к каталогу проекта, и
не создаёт файлов с секретами — значения выводятся только в терминал:

```bash
docker run --rm golang:1.26-alpine sh -ceu '
  wget -qO /tmp/keygen.go \
    https://raw.githubusercontent.com/mirrage11gpt/rmvpn/main/cmd/risevpn-keygen/main.go
  go run /tmp/keygen.go
'
```

Перенесите шесть напечатанных строк в `.env`, затем заполните остальные поля:

```dotenv
PUBLIC_DOMAIN=risevpn.example
CONTROL_DOMAIN=control.risevpn.example
ACME_EMAIL=admin@example.com
POSTGRES_PASSWORD=<сгенерированное значение>
TELEGRAM_CLIENT_ID=<Client ID из BotFather>
TELEGRAM_CLIENT_SECRET=<Client Secret из BotFather>
TELEGRAM_BOT_TOKEN=<токен бота>
SESSION_SECRET=<сгенерированное значение>
ENCRYPTION_KEY=<сгенерированное значение>
HWID_HMAC_KEY=<сгенерированное значение>
QUOTA_ED25519_PRIVATE_KEY=<сгенерированное значение>
COMPLIANCE_ED25519_PRIVATE_KEY=<сгенерированное значение>
RESTIC_REPOSITORY=s3:https://storage.example/risevpn-backups
BACKUP_ACCESS_KEY=<S3 access key>
BACKUP_SECRET_KEY=<S3 secret key>
BACKUP_REGION=ru-central1
```

Не добавляйте `.env` или каталог `secrets/` в Git.

## 3. PKI и backup secret

Создайте offline root CA и зашифрованный online intermediate:

```bash
./scripts/pki-init.sh
```

OpenSSL попросит пароль для intermediate key. Сохраните его в менеджере
секретов — он понадобится при каждом старте контейнера Control. Затем:

```bash
mkdir -p secrets
chmod 700 secrets
cp pki/certs/intermediate-ca.pem secrets/node-ca.pem
cp pki/online/intermediate-ca.key.enc secrets/node-ca-key.pem.enc
openssl rand -base64 32 > secrets/restic-password
chmod 600 .env secrets/*
```

Запишите пароль intermediate key без перевода строки:

```bash
read -rsp 'Intermediate CA password: ' RISEVPN_CA_PASSWORD
printf '%s' "$RISEVPN_CA_PASSWORD" > secrets/node-ca-key-password
unset RISEVPN_CA_PASSWORD
chmod 600 secrets/node-ca-key-password
```

Скопируйте `pki/offline/` и `pki/certs/root-ca.pem` на отдельный зашифрованный
носитель. После проверки копии offline root не должен оставаться на VPS.

## 4. Первый запуск Control

Проверьте конфигурацию и запустите систему:

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

Проверка:

```bash
curl --fail --show-error https://risevpn.example/healthz
docker compose logs --tail=100 control caddy postgres redis
```

В `docker compose ps` сервисы `control`, `postgres` и `redis` должны стать
healthy. Caddy автоматически выпустит TLS-сертификаты после корректного DNS.

Если backup-хранилище ещё не подготовлено, сервис `backup` будет
перезапускаться. Не оставляйте это состояние перед production-запуском:

```bash
docker compose logs --tail=100 backup
```

## 5. Назначение первого владельца

1. Откройте `https://risevpn.example` и один раз войдите через Telegram.
2. На сервере найдите созданную запись:

```bash
docker compose exec postgres psql -U risevpn -d risevpn -c \
  "SELECT id, display_name, username, telegram_subject FROM users;"
```

3. Назначьте роль по своему Telegram username без `@`:

```bash
docker compose exec postgres psql -U risevpn -d risevpn -c \
  "INSERT INTO user_roles(user_id, role) SELECT id, 'owner' FROM users WHERE username = 'YOUR_USERNAME' ON CONFLICT DO NOTHING;"
```

Если username отсутствует, используйте UUID из предыдущего запроса:

```bash
docker compose exec postgres psql -U risevpn -d risevpn -c \
  "INSERT INTO user_roles(user_id, role) VALUES ('USER_UUID', 'owner') ON CONFLICT DO NOTHING;"
```

Выйдите из сайта и войдите снова, чтобы новая роль попала в cookie-сессию.
Откройте `/admin`, создайте TOTP и добавьте показанный секрет в приложение-
аутентификатор. Секрет показывается только при первичной настройке.

## 6. Установка первой локации

На отдельном сервере Ubuntu 26.04 убедитесь, что DNS уже указывает на него и
порты 80, 443 и 8443 свободны. Скачайте и проверьте release:

```bash
sudo apt update
sudo apt install -y curl minisign
mkdir -p risevpn-node-install
cd risevpn-node-install
curl --fail --location --remote-name https://github.com/mirrage11gpt/rmvpn/releases/download/v0.2.5/install.sh
curl --fail --location --remote-name https://github.com/mirrage11gpt/rmvpn/releases/download/v0.2.5/checksums.txt
curl --fail --location --remote-name https://github.com/mirrage11gpt/rmvpn/releases/download/v0.2.5/checksums.txt.minisig
minisign -Vm checksums.txt -x checksums.txt.minisig \
  -P 'RWSn29kV+Wd2mrITWv/1AJZZLBImC/vVNjWInBYFLBletXZvdN+aLyCc'
grep ' install.sh$' checksums.txt | sha256sum --check
chmod 700 install.sh
```

Запустите установку, заменив три значения своими:

```bash
sudo RISEVPN_RELEASE_PUBLIC_KEY='RWSn29kV+Wd2mrITWv/1AJZZLBImC/vVNjWInBYFLBletXZvdN+aLyCc' ./install.sh \
  --domain msk-1.example \
  --acme-email admin@example.com \
  --masquerade-url https://cover.example.com \
  --version 0.2.5
```

`masquerade-url` должен принадлежать оператору, открываться по HTTPS и иметь
валидный сертификат. Установщик проверит Ubuntu, DNS, origin, порты, подпись и
SHA-256, после чего выведет единственный ключ `rvpn1_…`. Он действует 24 часа.

Если терминал был закрыт, ключ можно снова показать:

```bash
sudo risevpn-node enrollment show
```

## 7. Подключение локации к Control

1. Откройте `https://risevpn.example/admin`.
2. Подтвердите TOTP.
3. Нажмите **Добавить rvpn1_…**.
4. Вставьте ключ целиком и подтвердите.

Control вызовет временный endpoint узла, выдаст ему 30-дневный mTLS-сертификат
и сохранит одноразовый claim. Затем узел закроет 8443 и установит исходящее
соединение с `control.risevpn.example`.

Проверьте узел:

```bash
sudo risevpn-node status
sudo risevpn-node doctor
sudo risevpn-node logs -f
sudo ss -lntp | grep ':8443'
```

Последняя команда после успешного claim не должна ничего вывести. В админке
локация должна перейти в `healthy`. Если ключ истёк:

```bash
sudo risevpn-node reenroll
```

Затем вставьте новый ключ в админке.

## 8. Обновления и диагностика

Обновление Control:

```bash
cd "$HOME/risevpn"
git fetch --tags origin
git checkout <новый-тег>
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

Обновление узла выполняется атомарно с health-check и rollback:

```bash
sudo risevpn-node update --version <новая-версия>
sudo risevpn-node doctor
```

Полезные команды центрального сервера:

```bash
docker compose ps
docker compose logs -f control caddy
docker compose logs --tail=100 postgres redis backup
docker compose restart control
```

Не используйте `docker compose down -v`: флаг `-v` удалит PostgreSQL и другие
именованные volumes. Перед любым переносом сначала проверьте restic backup и
успешный restore-test в логах сервиса `backup`.

## 9. Контрольный список

- оба домена Control открываются только по HTTPS;
- Telegram login возвращает пользователя в `/app`;
- владелец включил TOTP и видит `/admin`;
- `docker compose ps` не показывает unhealthy-контейнеров;
- backup успешно записывается и проходит автоматический restore-test;
- локация `healthy`, TCP 8443 закрыт после claim;
- обычный HTTPS/HTTP3-запрос к домену локации показывает masquerade origin;
- subscription импортирован реальным актуальным v2RayTun;
- юридические и персональные данные оформлены до публичного запуска.
