<?php
namespace Element\Sentinel\Support;

use Element\Sentinel\Contracts\PasswordHasherInterface;

class NativePasswordHasher implements PasswordHasherInterface {

    /**
     * Hash et password med password_hash()
     *
     * @param string $password
     *
     * @return string
     */
    public function hash(string $password): string {

        // PASSWORD_DEFAULT er bcrypt i PHP 7.x (60 chars)
        // PHP-manualen anbefaler at bruge DEFAULT for fremtidssikring.
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Verificér et password mod et givent hash
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function verify(string $password, string $hash): bool {

        return password_verify($password, $hash);
    }

    /**
     * Afgør om hash’et skal regenereres (nyere cost/algoritme)
     *
     * @param string $hash
     * @return bool
     */
    public function needsRehash(string $hash): bool {

        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

    /**
     * Resolve a PasswordHasherInterface from a mixed input.
     *
     * Rules:
     *  - If $hasher is already an instance of PasswordHasherInterface, return it.
     *  - Otherwise, return a new NativePasswordHasher().
     *
     * @param mixed $hasher
     *
     * @return PasswordHasherInterface
     */
    public static function resolveHasher($hasher): PasswordHasherInterface {

        if ($hasher instanceof PasswordHasherInterface) {

            return $hasher;
        }

        return new self();
    }

}
