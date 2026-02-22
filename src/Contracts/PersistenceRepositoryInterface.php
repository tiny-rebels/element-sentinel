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
     * Create and persist a remember-me token for the given user id (server-side),
     * and write a signed/opaque cookie on the client.
     *
     * @param int|string $userId
     *
     * @return void
     */
    public function remember($userId): void;

    /**
     * Restore a user id from the remember-me cookie if present and valid.
     *
     * @return int|string|null
     */
    public function userIdFromRememberCookie();

    /**
     * Forget all server-side tokens and client cookie for a specific user id.
     *
     * @param int|string $userId
     *
     * @return void
     */
    public function forgetUser($userId): void;

    /**
     * Forget the remember-me token for the current client context if present
     * (e.g., remove server-side token referenced by the cookie, then clear cookie).
     *
     * @return void
     */
    public function forgetCurrent(): void;

    /**
     * Always clear the remember-me cookie on the client (idempotent).
     * This does not require a known user id and may be used as a final safeguard
     * after forgetUser()/forgetCurrent().
     *
     * @return void
     */
    public function forgetCookie(): void;

}
