# RiseVPN Node control protocol v1/v2

## Protocol v2 (Node v0.2)

Каждое WebSocket-сообщение использует envelope с `version`, `messageId`, `replyTo`, `type`, `sentAt` и `data`. Узел объявляет версии и capabilities в `hello`. Контроллер хранит команды в PostgreSQL, повторяет их с bounded backoff и считает применёнными только после `ack`; `nack` сохраняет причину. Узел запоминает `messageId`, поэтому повтор команды идемпотентен.

v2 добавляет подписанные `quota.lease`, `device.upsert`, `device.revoke`, `session.kick`, `policy.override`, `certificate.rotate`, `drain` и атомарный `update`. Usage учитывается один раз по `(nodeId,eventId)`. Envelope v1 без новых полей продолжает читаться во время rollout.

## Enrollment bundle

Формат: `rvpn1_` плюс base64url JSON без padding.

```json
{
  "version": 1,
  "nodeId": "uuid-v4",
  "domain": "node.example.com",
  "claimEndpoint": "https://node.example.com:8443/v1/enrollment/claim",
  "nodePublicKey": "base64url-ed25519-public-key",
  "claimToken": "base64url-256-bit-secret",
  "expiresAt": "2026-08-09T10:00:00Z",
  "agentVersion": "0.2.0"
}
```

Bundle является секретом до claim. Изменение public key приводит к выпуску
несовместимого сертификата, который узел отклонит.

## Claim

`POST /v1/enrollment/claim`, максимум 1 MiB:

```json
{
  "claimToken": "...",
  "controllerUrl": "wss://control.example.com/v2/nodes/connect",
  "controllerPublicKey": "base64url-ed25519-public-key",
  "quotaPublicKey": "base64url-ed25519-public-key",
  "compliancePublicKey": "base64url-ed25519-public-key",
  "nodeCertificatePem": "-----BEGIN CERTIFICATE-----...",
  "controllerCaPem": "-----BEGIN CERTIFICATE-----..."
}
```

Node certificate должен быть подписан переданным CA, содержать исходный Ed25519
public key и `clientAuth` EKU. После успешной атомарной записи повторный claim
возвращает 401, HTTPS listener закрывается, а узел подключается к controller по
mTLS 1.3.

## Control channel

Каждое WebSocket text message имеет форму:

```json
{"version":2,"messageId":"uuid","replyTo":"optional-command-uuid","type":"message.type","sentAt":"2026-08-08T19:00:00Z","data":{}}
```

Node → controller:

- `hello`: protocol version, node ID и agent version;
- `heartbeat`: UTC time, health и активные persistent alerts;
- `usage.batch`: идемпотентные usage events с устойчивыми event ID; без
  подтверждения пакет будет отправлен повторно;
- `error`: отклонённый тип команды и безопасное описание ошибки.

Controller → node:

- `device.upsert` и `quota.lease`: device ID, SHA-256 credential hash, plan,
  active, subscription/period end, quota и lease;
- `device.revoke`: немедленно запрещает новые подключения устройства;
- `compliance.feed`: подписанная версия правил;
- `usage.ack`: список сохранённых `eventIds`, после которого узел помечает
  события отправленными;
- `drain` и `update`: зарезервированы для privileged updater helper; агент
  возвращает явную ошибку, пока helper не подключён к control-channel.

При смене `periodEnds` локальный usage сбрасывается атомарно. Credential в
открытом виде на узел не передаётся.

## Local Hysteria API

Все endpoints слушают только `127.0.0.1:9080`.

`POST /v1/auth` принимает стандартные `addr`, `auth`, `tx` и возвращает:

```json
{
  "ok": true,
  "id": "device-id",
  "policy": {
    "upBps": 50000000,
    "downBps": 50000000,
    "priority": 1,
    "p2pAllowed": false,
    "deviceId": "device-id",
    "throttled": false,
    "complianceRequired": true
  }
}
```

`POST /v1/authorize` принимает ID, protocol, destination и необязательный
base64 initial payload. Ответ `ok=false` блокирует запрос до открытия outbound.

## Compliance feed

Подписывается точный JSON с `version`, UTC `updatedAt`, UTC `expiresAt` и
`rules`. Поддерживаемые правила:

```json
{
  "blockedDomains": ["blocked.example"],
  "blockedCidrs": ["203.0.113.0/24"],
  "blockedPorts": [25]
}
```

Подпись Ed25519 передаётся как base64url в поле `signature`. Неверная подпись,
CIDR или временной диапазон отклоняются без замены последнего рабочего feed.
