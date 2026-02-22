CREATE TABLE `activations` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `code` CHAR(64) NOT NULL,

    `completed_at` DATETIME NULL DEFAULT NULL,
    `created_at` DATETIME NOT NULL,

    PRIMARY KEY (`id`),
    UNIQUE KEY `activations_code_unique` (`code`),
    KEY `activations_user_id_index` (`user_id`),

    CONSTRAINT `activations_user_id_fk`
       FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
           ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;