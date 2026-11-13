# Notifications

Citadel can tell people when something needs their attention: an AI agent
asking for approval, an agent being suspended, unusual agent behaviour, or
the kill switch being used. Notifications go to **channels** that an account
admin sets up in **Administration → Notifications**.

Channels are per account. Each one subscribes to a set of events and has a
delivery log.

## Channel types

| Type | Destination | Notes |
|---|---|---|
| Webhook | Any `https://` URL | Citadel POSTs a JSON event signed with the channel's secret (see [Verifying webhook signatures](#verifying-webhook-signatures)). |
| Slack | A Slack [incoming webhook](https://api.slack.com/messaging/webhooks) on `hooks.slack.com` | The URL is a credential: Citadel stores it encrypted and only ever shows its non-secret prefix. Other hosts are refused. |
| Email | Up to 20 addresses | Sent through the deployment's SMTP server (`KMS_SMTP_*`, see [configuration](configuration.md#email-notifications-smtp)). Unavailable until it is configured. |

## Events

| Event | When |
|---|---|
| `agent.approval_requested` | An agent asked for access that needs a human's approval. The payload links to the request in the console (`url`) and names the agent, credential, actions, reason and task ID. |
| `agent.access_decided` | Someone approved or denied an agent's access request (with the scope and lease expiry, or the denial reason). |
| `agent.suspended` | An agent was suspended, by a person or automatically. |
| `agent.anomaly` | An agent behaved unusually: a new host, off-hours use, a rate spike or repeated denials. |
| `security.kill_switch` | Every agent in the account was suspended with the kill switch. |
| `test` | You pressed **Send test**. Every channel receives test events, even a disabled one. |

The console and `GET /v1/notifications/channels` list the events this server
knows, with a title and a severity, so new event types appear without a
console change.

Event payloads describe what happened (names, IDs, hosts, the actor). They
never contain secret values.

## Delivery

Notifications are written to a durable outbox and sent by a background
worker that runs on every replica (replicas never take the same delivery).
A delivery that fails (a non-2xx response, a timeout, an SMTP error) is
retried with exponential backoff: 30 seconds, then 1, 2, 4... minutes, at
most an hour apart. After 10 failed attempts it is **dead-lettered**: shown
as *Failed* in the delivery log, where an admin can **Retry** it.

Delivery is at least once. A receiver can see the same event twice (for
example after a timeout on a request that did arrive); use the event `id`
(or `X-Citadel-Event-Id`) to deduplicate.

Delivered and failed entries stay in the delivery log for 30 days. Deleting a
channel deletes its log.

Webhook and Slack requests follow the same outbound rules as SIEM streaming
and rotation webhooks: https only, no redirects followed, a 15-second
timeout, and the resolved address is checked when connecting, so a URL can't
reach loopback, link-local (cloud metadata) or other internal-only ranges.
Private (RFC 1918) addresses are allowed.

## Webhook requests

```http
POST /your/endpoint HTTP/1.1
Content-Type: application/json
User-Agent: Citadel-notifications/1
X-Citadel-Event: agent.suspended
X-Citadel-Event-Id: evt_5b1e0c9a7f3d2e4a6c8b0d1f
X-Citadel-Delivery: 1842
X-Citadel-Signature: t=1794580000,v1=5d41402abc4b2a76b9719d911017c592...

{"id":"evt_5b1e0c9a7f3d2e4a6c8b0d1f","type":"agent.suspended","accountId":"123456789012",
 "createdAt":"2026-11-13T10:00:00Z","data":{"agentId":"agt_...","name":"builder","actor":"alice"}}
```

Reply with any 2xx status to acknowledge. The body of your reply is ignored.

## Verifying webhook signatures

Each webhook channel has a signing secret (`whsec_...`), shown once when the
channel is created and when it is rotated. Every request carries

```
X-Citadel-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>
```

where the HMAC key is the signing secret and the message is the timestamp, a
dot, and the raw request body: `"<t>.<body>"`. To verify a request:

1. Read the raw body **before** parsing it as JSON.
2. Split the header on `,` and take `t` and `v1`.
3. Compute `HMAC-SHA256(secret, t + "." + body)` as lowercase hex and compare
   it with `v1` in constant time.
4. Reject timestamps more than 5 minutes from now, so a captured request
   can't be replayed later.

### Node.js

```js
import crypto from 'node:crypto';
import express from 'express';

const secret = process.env.CITADEL_SIGNING_SECRET;

function verify(header, rawBody, toleranceSeconds = 300) {
  const parts = Object.fromEntries(header.split(',').map((p) => p.split('=', 2)));
  const t = Number(parts.t);
  if (!Number.isInteger(t) || Math.abs(Date.now() / 1000 - t) > toleranceSeconds) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${parts.t}.`).update(rawBody).digest('hex');
  const given = Buffer.from(parts.v1 ?? '', 'utf8');
  const want = Buffer.from(expected, 'utf8');
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

const app = express();
app.post('/citadel', express.raw({ type: 'application/json' }), (req, res) => {
  if (!verify(req.get('X-Citadel-Signature') ?? '', req.body)) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString('utf8'));
  console.log(event.type, event.data);
  res.sendStatus(204);
});
app.listen(8080);
```

### Go

The Go SDK has `citadel.VerifyNotificationSignature`:

```go
import "github.com/worlddrknss/citadel/sdk/citadel"

http.HandleFunc("/citadel", func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := citadel.VerifyNotificationSignature(secret, r.Header.Get("X-Citadel-Signature"), body, 0); err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var ev citadel.NotificationEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Printf("%s %s", ev.Type, ev.Data)
	w.WriteHeader(http.StatusNoContent)
})
```

Without the SDK, the check is a few lines of the standard library:

```go
func verify(secret, header string, body []byte) bool {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(n, 0)).Abs() > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
}
```

### Rotating the secret

**Rotate signing secret** (or `POST /v1/notifications/channels/signing-secret`)
replaces the secret at once: deliveries from then on are signed with the new
one. To rotate without dropping events, have your receiver accept either the
old or the new secret while you switch, then remove the old one. A delivery
that fails verification and gets a non-2xx reply is retried, so a short gap
doesn't lose events.

## Slack and email messages

Slack messages and emails are rendered from the event: its title, a summary
line, and the payload's fields. Emails come from `KMS_SMTP_FROM` with the
subject `[Citadel] <event title>`.

## API

Every operation needs the **admin** role in the account and is recorded in
the audit log (`citadel.CreateNotificationChannel`,
`citadel.UpdateNotificationChannel`, `citadel.DeleteNotificationChannel`,
`citadel.TestNotificationChannel`, `citadel.RotateNotificationSigningSecret`,
`citadel.RetryNotificationDelivery`). See the API reference in the console
or [openapi.yaml](openapi.yaml) for the request and response shapes.

| Operation | Endpoint |
|---|---|
| List channels and the event catalog | `GET /v1/notifications/channels` |
| Create a channel | `POST /v1/notifications/channels` |
| Update a channel | `POST /v1/notifications/channels/update` |
| Delete a channel | `DELETE /v1/notifications/channels?id=` |
| Send a test | `POST /v1/notifications/channels/test` |
| Rotate a webhook's signing secret | `POST /v1/notifications/channels/signing-secret` |
| Delivery log | `GET /v1/notifications/deliveries?channelId=&limit=` |
| Retry a dead-lettered delivery | `POST /v1/notifications/deliveries/retry` |

The Go SDK wraps them (`ListNotificationChannels`,
`CreateNotificationChannel`, `UpdateNotificationChannel`,
`DeleteNotificationChannel`, `TestNotificationChannel`,
`RotateNotificationSigningSecret`, `ListNotificationDeliveries`,
`RetryNotificationDelivery`).

## For Citadel developers

Features raise events with

```go
if err := s.notify(ctx, accountID, EventAgentSuspended, map[string]any{
	"agentId": a.ID, "name": a.Name, "actor": actor, "summary": a.Name + " was suspended",
}); err != nil {
	log.Printf("notify failed: %v", err) // never fail the operation over a notification
}
```

The payload is any value that marshals to a JSON object (at most 64 KiB);
`summary` (or `message`) becomes the headline in Slack and email. Never put
secret values in it. To add an event type, add a constant and an entry to
`notificationEvents` in `internal/server/notifications.go`, and a row to the
table above.
