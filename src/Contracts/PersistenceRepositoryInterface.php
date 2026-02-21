<?php

namespace Element\Sentinel\Contracts;

/**
 * PersistenceRepositoryInterface
 *
 * Responsible for remember-me (persistent "login") storage and cookie handling
 * in a framework-agnostic way.
 */
interface PersistenceRepositoryInterface {

    /**
     * Create a persistent login token for the user and set the remember cookie.
     *
     * @param int|string $userId
     *
     * @return void
     */
    public function remember($userId): void;

    /**
     * Try to resolve a user id from the remember cookie, if present and valid.
     *
     * @return int|string|null
     */
    public function userIdFromRememberCookie();

    /**
     * Revoke the current remember cookie and its DB record, if present.
     *
     * @return void
     */
    public function forgetCurrent(): void;

    /**
     * Revoke all remember tokens for a given user.
     *
     * @param int|string $userId
     *
     * @return void
     */
    public function forgetUser($userId): void;
}
