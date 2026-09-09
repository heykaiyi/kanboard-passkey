<?php

namespace Kanboard\Plugin\Passkey\Schema;

use PDO;

const VERSION = 1;

function version_1(PDO $pdo)
{
    // credential_id is a TEXT column because the spec allows up to 1023 raw
    // bytes; the sha256 of it is what carries the unique index, so the key
    // stays inside InnoDB's limit whatever the authenticator sends.
    $pdo->exec("
        CREATE TABLE passkey_credentials (
            id INT NOT NULL AUTO_INCREMENT,
            user_id INT NOT NULL,
            credential_id TEXT NOT NULL,
            credential_hash VARCHAR(64) NOT NULL,
            public_key TEXT NOT NULL,
            algorithm INT NOT NULL DEFAULT -7,
            sign_count BIGINT NOT NULL DEFAULT 0,
            aaguid VARCHAR(32) DEFAULT '',
            transports VARCHAR(64) DEFAULT '',
            name VARCHAR(100) DEFAULT '',
            is_backup_eligible TINYINT(1) DEFAULT 0,
            created_at INT DEFAULT 0,
            last_used_at INT DEFAULT 0,
            PRIMARY KEY(id),
            UNIQUE KEY passkey_credentials_hash_idx (credential_hash),
            KEY passkey_credentials_user_idx (user_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB CHARSET=utf8
    ");
}
