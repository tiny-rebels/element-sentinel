
# Throttling in Element/Sentinel

This document explains how login throttling works in **Element/Sentinel**, how to create the required database table, and how to integrate it into your authentication flow. The implementation is based on two core components:

- `ThrottlePolicy` — an immutable value object describing the rolling window and suspension strategy. citeturn2search2
- `EloquentThrottleRepository` — a repository that persists attempt counters and suspensions in a database table and exposes a small API (`hit`, `isSuspended`, `availableIn`, `clear`). citeturn2search1

---

## 1) Database schema

Create a table (default name used in the examples: `throttle`) with the following columns:

- `scope` (`VARCHAR(32)`): logical bucket (e.g., `global`, `ip`, `user`). citeturn2search1
- `key_hash` (`VARCHAR(191)`): identifier within the scope (IP address, user id, or normalized email hash/string). The repository treats this as an opaque string. citeturn2search1
- `attempts` (`INT UNSIGNED`): number of attempts observed within the current rolling window. citeturn2search1
- `last_attempt_at` (`DATETIME`): timestamp of the last attempt; used to reset the counter when the window elapses. citeturn2search1
- `suspended_until` (`DATETIME`): when set to a future time the key is blocked and further attempts are rejected. citeturn2search1

Example DDL for MySQL/MariaDB:

```sql
CREATE TABLE IF NOT EXISTS `throttle` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `scope` VARCHAR(32) NOT NULL,
  `key_hash` VARCHAR(191) NOT NULL,
  `attempts` INT UNSIGNED NOT NULL DEFAULT 0,
  `last_attempt_at` DATETIME NULL,
  `suspended_until` DATETIME NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_scope_key` (`scope`, `key_hash`),
  KEY `idx_suspended_until` (`suspended_until`),
  KEY `idx_last_attempt_at` (`last_attempt_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

> If you choose a different table name, pass that same name to `EloquentThrottleRepository` when you construct it. citeturn2search1

---

## 2) Policy model

`ThrottlePolicy` defines **how** throttling behaves for a scope. It contains: citeturn2search2

- `intervalSeconds()` — the rolling time window in seconds.
- `thresholds()` — either
    - an **integer** (max attempts in the window) → *fixed* suspension using `suspensionSecondsDefault()`, or
    - a **map** `attempts => minutes` for *escalating* backoff (largest key ≤ attempts wins).
- `suspensionSecondsDefault()` — default suspension length used with integer thresholds.
- `resolveSuspensionSecondsForAttempts(int $attempts)` — returns how many seconds to suspend for the given attempt count.

**Resolution rules**: If thresholds is an integer and `attempts > max`, the default suspension applies; if thresholds is a map, the highest configured key ≤ `attempts` determines the suspension in minutes (converted to seconds). citeturn2search2

---

## 3) Repository behavior

`EloquentThrottleRepository` persists and evaluates throttling state. Key methods: citeturn2search1

- `hit(string $scope, string $key): int` — registers a failed attempt. If currently suspended, returns remaining seconds without incrementing. Otherwise it (a) resets the counter if the window elapsed, (b) increments attempts, (c) calculates and applies suspension according to the policy, and returns the suspension seconds (0 if not suspended). citeturn2search1
- `isSuspended(string $scope, string $key): bool` — true if `suspended_until` is in the future. citeturn2search1
- `availableIn(string $scope, string $key): int` — seconds until suspension lifts (0 if not suspended). citeturn2search1
- `clear(string $scope, string $key): void` — resets attempts and lifts any suspension; typically called after a successful login. citeturn2search1

Policies are bound **per scope**. The repository chooses the correct `ThrottlePolicy` for `global`, `ip`, or `user`. citeturn2search1

---

## 4) Wiring (example)

```php
use Element\Sentinel\Infrastructure\Policies\ThrottlePolicy;
use Element\Sentinel\Infrastructure\Eloquent\EloquentThrottleRepository;

$global = new ThrottlePolicy(
    intervalSeconds: 60,              // 1-minute window
    thresholds: 10,                   // >10 attempts => default suspension
    suspensionSecondsDefault: 60      // 60s suspension
);

$ip = new ThrottlePolicy(
    intervalSeconds: 300,             // 5-minute window
    thresholds: [5 => 1, 10 => 5]     // >=5 => 1 min, >=10 => 5 min
);

$user = new ThrottlePolicy(
    intervalSeconds: 300,
    thresholds: [3 => 1, 5 => 10]     // >=3 => 1 min, >=5 => 10 min
);

$repo = new EloquentThrottleRepository(
    throttleTableName: 'throttle',
    globalPolicy: $global,
    ipPolicy: $ip,
    userPolicy: $user
);
```

> The constructor requires the table name plus three policies (global, ip, user). citeturn2search1

---

## 5) Using the throttle in an authentication flow

**Pre-check (optional):** Prevent work if an IP or user is already blocked.

```php
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if ($repo->isSuspended('ip', $ip)) {
    $remaining = $repo->availableIn('ip', $ip);
    // Show: "Too many attempts. Try again in {$remaining} seconds."
    return;
}
```

**On failed login:** Register hits for the scopes you track (at least IP; add user if identity is known).

```php
$suspForIp = $repo->hit('ip', $ip);
if (isset($userIdOrEmailKey)) {
    $suspForUser = $repo->hit('user', (string)$userIdOrEmailKey);
}
```

**On successful login:** Clear the counters for the same scopes to avoid sticky suspensions.

```php
$repo->clear('ip', $ip);
$repo->clear('user', (string)$userId);
```

---

## 6) Choosing keys

- For `ip` scope use the remote address string (or a normalized representation if you’re behind proxies). citeturn2search1
- For `user` scope, prefer a stable identifier (numeric user id). If you don’t want to store raw identifiers, hash them (e.g., SHA-256) before passing to the repository; it treats the key as opaque. citeturn2search1

---

## 7) Operational tips

- The unique index on (`scope`, `key_hash`) prevents duplicates for a tracked entity. citeturn2search1
- Consider a periodic cleanup of very old rows (e.g., where `last_attempt_at` is older than 90 days). The repository logic does not require this, it’s purely housekeeping. citeturn2search1
- For cross-service installations, ensure app servers share the same database (or use a shared cache + persistence) so suspensions are enforced consistently. (General integration note.)

---

## 8) UI messaging

- **Warning (not yet suspended):** "Too many attempts. Next failure may result in a temporary lock."
- **Suspended:** "Too many attempts. Please try again in **{availableIn}** seconds."

The `availableIn(scope, key)` helper returns the exact number of seconds remaining. citeturn2search1

---

## 9) End-to-end recap

1. Optionally **pre-check** with `isSuspended(...)` to short-circuit work. citeturn2search1
2. On **failed attempt**, call `hit(...)` for relevant scopes; repository will reset window when needed, increment, and possibly set `suspended_until`. citeturn2search1turn2search2
3. On **success**, call `clear(...)` for those scopes. citeturn2search1

---

## 10) Variants

Need a schema for PostgreSQL or SQLite? The structure is identical; change column types and index syntax accordingly. If you want to avoid storing raw IPs or user identifiers, hash the values before passing them to the repository; the API remains unchanged. citeturn2search1

