<?php

namespace Kanboard\Plugin\Passkey\Schema;

use PDO;

const VERSION = 1;

function version_1(PDO $pdo)
{
    $pdo->exec('
        CREATE TABLE passkey_credentials (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL,
            credential_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            algorithm INTEGER NOT NULL DEFAULT -7,
            sign_count INTEGER NOT NULL DEFAULT 0,
            aaguid TEXT DEFAULT "",
            transports TEXT DEFAULT "",
            name TEXT DEFAULT "",
            is_backup_eligible INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT 0,
            last_used_at INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ');

    $pdo->exec('CREATE UNIQUE INDEX passkey_credentials_hash_idx ON passkey_credentials(credential_hash)');
    $pdo->exec('CREATE INDEX passkey_credentials_user_idx ON passkey_credentials(user_id)');
}
