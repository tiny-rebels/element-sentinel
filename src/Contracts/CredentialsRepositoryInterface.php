<?php

namespace Element\Sentinel\Contracts;

interface CredentialsRepositoryInterface {

    /**
     * Find a user by email.
     *
     * @param string $email
     *
     * @return UserInterface|null
     */
    public function find(string $email): ?UserInterface;

    /**
     * Read the stored password hash for the given user.
     *
     * @param UserInterface $user
     *
     * @return string
     */
    public function getPasswordHash(UserInterface $user): string;

    /**
     * Update (rehash) the stored password for the given user.
     *
     * @param UserInterface $user
     * @param string $newHash
     *
     * @return void
     */
    public function updatePassword(UserInterface $user, string $newHash);

    /**
     * Verify a plaintext password against the user's stored hash.
     *
     * @param UserInterface $user
     * @param string $plainPassword
     * @param PasswordHasherInterface $hasher
     * @return bool
     */
    public function verify(UserInterface $user, string $plainPassword, PasswordHasherInterface $hasher): bool;

}
