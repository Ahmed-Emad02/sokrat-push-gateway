-- Sokrat VOICE Push Gateway device registry
-- One row per (extension, device). A user may have many devices.
CREATE TABLE IF NOT EXISTS `mobile_devices` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `extension` VARCHAR(20) NOT NULL,
  `platform` ENUM('ios','android') NOT NULL,
  `token` VARCHAR(1024) NOT NULL COMMENT 'APNs device token (non-voip) or FCM registration token',
  `voip_token` VARCHAR(1024) DEFAULT NULL COMMENT 'APNs PushKit VoIP token (iOS only)',
  `device_uuid` VARCHAR(128) DEFAULT NULL,
  `app_version` VARCHAR(40) DEFAULT NULL,
  `last_push_error` DATETIME DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `idx_token` (`token`(255)),
  KEY `idx_extension` (`extension`),
  KEY `idx_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
