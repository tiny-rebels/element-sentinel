<?php

namespace Element\Sentinel\Contracts;

interface CredentialsRepositoryInterface {

    /**
     * Find a user (email/username/etc.) by a single login value.
     *
     * @param string $login
     *
     * @return UserInterface|null
     */
    public function findByLogin(string $login): ?UserInterface;

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
}
