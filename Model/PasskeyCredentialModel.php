<?php

namespace Kanboard\Plugin\Passkey\Model;

use Kanboard\Core\Base;

/**
 * Stored passkeys.
 *
 * Nothing here is a secret: a credential row holds a public key and a counter.
 * Losing the table means users have to enrol again, not that anyone can sign
 * in as them.
 */
class PasskeyCredentialModel extends Base
{
    const TABLE = 'passkey_credentials';

    /**
     * @param  int $userId
     * @return array
     */
    public function getAllByUser($userId)
    {
        return $this->db->table(self::TABLE)
            ->eq('user_id', $userId)
            ->desc('created_at')
            ->findAll();
    }

    /**
     * @param  int $userId
     * @return string[]  base64url credential ids
     */
    public function getCredentialIdsByUser($userId)
    {
        return $this->db->table(self::TABLE)
            ->eq('user_id', $userId)
            ->findAllByColumn('credential_id');
    }

    /**
     * Look up the credential the browser just used.
     *
     * @param  string $credentialId  base64url
     * @return array|null
     */
    public function getByCredentialId($credentialId)
    {
        $credential = $this->db->table(self::TABLE)
            ->eq('credential_hash', $this->hash($credentialId))
            ->findOne();

        // The hash is what carries the index; compare the id itself before
        // trusting the row.
        if (empty($credential) || ! hash_equals($credential['credential_id'], $credentialId)) {
            return null;
        }

        return $credential;
    }

    /**
     * @param  int   $id
     * @param  int   $userId
     * @return array|null
     */
    public function getById($id, $userId)
    {
        $credential = $this->db->table(self::TABLE)->eq('id', $id)->eq('user_id', $userId)->findOne();

        return empty($credential) ? null : $credential;
    }

    /**
     * @param  int    $userId
     * @param  array  $credential  As returned by Server::verifyCreation()
     * @param  string $name        What the user calls this passkey
     * @return bool
     */
    public function create($userId, array $credential, $name)
    {
        return $this->db->table(self::TABLE)->insert(array(
            'user_id' => $userId,
            'credential_id' => $credential['credential_id'],
            'credential_hash' => $this->hash($credential['credential_id']),
            'public_key' => $credential['public_key'],
            'algorithm' => $credential['algorithm'],
            'sign_count' => $credential['sign_count'],
            'aaguid' => $credential['aaguid'],
            'transports' => $credential['transports'],
            'name' => $name,
            'is_backup_eligible' => $credential['is_backup_eligible'],
            'created_at' => time(),
            'last_used_at' => 0,
        ));
    }

    /**
     * @param  int $id
     * @param  int $signCount
     * @return bool
     */
    public function markAsUsed($id, $signCount)
    {
        return $this->db->table(self::TABLE)->eq('id', $id)->update(array(
            'sign_count' => $signCount,
            'last_used_at' => time(),
        ));
    }

    /**
     * @param  int    $id
     * @param  int    $userId
     * @param  string $name
     * @return bool
     */
    public function rename($id, $userId, $name)
    {
        return $this->db->table(self::TABLE)->eq('id', $id)->eq('user_id', $userId)->update(array('name' => $name));
    }

    /**
     * @param  int $id
     * @param  int $userId
     * @return bool
     */
    public function remove($id, $userId)
    {
        return $this->db->table(self::TABLE)->eq('id', $id)->eq('user_id', $userId)->remove();
    }

    /**
     * @param  int $userId
     * @return int
     */
    public function countByUser($userId)
    {
        return $this->db->table(self::TABLE)->eq('user_id', $userId)->count();
    }

    /**
     * Whether the sign-in button is worth showing at all.
     *
     * @return bool
     */
    public function hasAny()
    {
        return $this->db->table(self::TABLE)->count() > 0;
    }

    private function hash($credentialId)
    {
        return hash('sha256', $credentialId);
    }
}
