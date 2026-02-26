-- create_throttle.sql
-- Table for tracking authentication throttling across scopes (global, ip, user)

-- MySQL / MariaDB
CREATE TABLE IF NOT EXISTS `throttle` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `scope` VARCHAR(32) NOT NULL,               -- e.g. 'global', 'ip', 'user'
    `key_hash` VARCHAR(191) NOT NULL,           -- stored key (already treated as an identifier in repo)
    `attempts` INT UNSIGNED NOT NULL DEFAULT 0, -- rolling count within current window
    `last_attempt_at` DATETIME NULL,            -- timestamp of last attempt
    `suspended_until` DATETIME NULL,            -- if not null and in the future => blocked

    -- Eloquent timestamps
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_scope_key` (`scope`, `key_hash`),
    KEY `idx_suspended_until` (`suspended_until`),
    KEY `idx_last_attempt_at` (`last_attempt_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Helpful comment:
-- The repository resets attempts when the time since last_attempt_at exceeds
-- the policy's intervalSeconds(). It also sets suspended_until when thresholds
-- imply a backoff. See ThrottlePolicy for details.  (Derived from code)
