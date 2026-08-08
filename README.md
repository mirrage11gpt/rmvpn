# RiseVPN Node

Серверный агент локации RiseVPN и минимальный patch-set для Hysteria 2. Узел
устанавливается на Ubuntu 26.04, работает на одном публичном IP и выдаёт
одноразовый ключ `rvpn1_...` для будущего управляющего сервера.

## Что реализовано

- статический Go-агент для `amd64` и `arm64`, SQLite WAL и systemd hardening;
- Ed25519-идентичность узла и одноразовый enrollment со сроком 24 часа;
- временный HTTPS claim endpoint на TCP 8443 и исходящий mTLS WebSocket после claim;
- локальные auth/authorize API для Hysteria, недоступные извне;
- тарифы Trial, Lite, Plus и Ultra, серверные speed limits и throttling;
- отдельные device credentials, revoke и quota leases;
- сбор статистики Hysteria каждые 15 секунд и отключение исчерпанных Trial/leases;
- подписанный compliance feed, доменные/CIDR/port правила и постоянный stale-alert;
- P2P-фильтр по tracker-адресам, портам и распознаваемым BitTorrent/µTP payload;
- HTTP/HTTPS/HTTP3 reverse-proxy masquerade на принадлежащий оператору origin;
- signed GitHub Releases, безопасное обновление с health-check и rollback бинарников;
- mock control-server для разработки второй части.

Hysteria остаётся совместимой со стандартными клиентами: wire protocol, QUIC,
TLS и криптография не изменены. Полная неотличимость от VPN не гарантируется, а
нестандартный или дополнительно зашифрованный P2P может не распознаться.

## Подготовка релизов

Upstream Hysteria закреплён в `hysteria-patches/UPSTREAM_VERSION`. Патчи хранятся
отдельно и последовательно применяются к чистому upstream.

```bash
go test -race ./...
./scripts/build-hysteria.sh
```

Перед первым production release владелец репозитория должен создать minisign
ключ вне репозитория:

```bash
minisign -G -W -p risevpn-release.pub -s risevpn-release.key
```

Содержимое private key добавляется в GitHub Actions secret
`MINISIGN_PRIVATE_KEY`. Строка `RW...` из public key публикуется через доверенный
канал и передаётся установщику. Private key нельзя коммитить.

Текущий production public key:

```text
RWSn29kV+Wd2mrITWv/1AJZZLBImC/vVNjWInBYFLBletXZvdN+aLyCc
```

Release workflow собирает оба агента, patched Hysteria, packaging archive,
`checksums.txt` и `checksums.txt.minisig`.

## Установка узла

Предварительные условия:

- чистая Ubuntu 26.04 `amd64` или `arm64` с публичным IP;
- A/AAAA-запись домена уже направлена на узел;
- TCP 80, TCP/UDP 443 и временно TCP 8443 доступны;
- HTTPS origin принадлежит оператору и отвечает валидным сертификатом.

Рекомендуется сначала скачать установщик по TLS и просмотреть его, затем:

```bash
sudo RISEVPN_RELEASE_PUBLIC_KEY='RWSn29kV+Wd2mrITWv/1AJZZLBImC/vVNjWInBYFLBletXZvdN+aLyCc' ./install.sh \
  --domain node-msk-1.example.com \
  --acme-email admin@example.com \
  --masquerade-url https://cover.example.com \
  --version 0.1.0
```

Установщик проверяет ОС, архитектуру, DNS, origin, занятые порты, minisign и
SHA-256. Затем создаёт системных пользователей, получает сертификат Let's
Encrypt, устанавливает systemd units и выводит enrollment key. Повторный запуск
с теми же параметрами идемпотентен; для обновления используется `--upgrade`.

Администрирование:

```bash
risevpn-node status
risevpn-node doctor
risevpn-node logs -f
risevpn-node enrollment show
risevpn-node reenroll
risevpn-node update --version 0.1.1
risevpn-node uninstall
risevpn-node uninstall --purge-data
```

Без `--purge-data` identity, база и конфигурация сохраняются. С этим флагом они
удаляются необратимо.

## Локальная разработка

Требуется Go 1.26. Сборка агента:

```bash
go test ./...
go build -o target/risevpn-node ./cmd/risevpn-node
go build -o target/risevpn-mock-controller ./cmd/risevpn-mock-controller
```

Для тестовой регистрации запустите агент с тестовым сертификатом и конфигом,
скопируйте `rvpn1_...`, затем запустите контроллер:

```bash
risevpn-mock-controller \
  --bundle 'rvpn1_...' \
  --listen :9443 \
  --public-url wss://127.0.0.1:9443/v1/nodes/connect \
  --claim-url https://node.example.com:8443/v1/enrollment/claim \
  --plan PLUS
```

Контроллер выпускает node mTLS certificate, выполняет claim, отправляет тестовое
устройство и подписанный пустой compliance feed. Credential выводится только в
его консоль.

## Данные и безопасность

База и private identity находятся в `/var/lib/risevpn/node.db` с режимом `0600`.
Сохраняются агрегированные байты, устройства, security-события и alerts. Адреса
посещённых ресурсов и payload не записываются; initial payload используется в
памяти только для решения allow/deny.

Compliance работает fail-open по выбранной политике: при просроченном feed
последние правила продолжают применяться, а узел отправляет постоянный critical
alert. Это техническое поведение не является подтверждением соответствия
законодательству. Перед коммерческим запуском обязательны юридическая проверка,
реальный источник реестра и процесс взаимодействия с Роскомнадзором.

Форматы enrollment и control-channel описаны в
[`docs/control-protocol.md`](docs/control-protocol.md).
