<?php

namespace Element\Sentinel\Contracts;

/**
 * UserRepositoryInterface
 *
 * Generic user repository contract. Framework-agnostic by design.
 */
interface UserRepositoryInterface {

    /**
     * Find a user by ID.
     *
     * @param int $id
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findById(int $id, array $withRelations = []): ?UserInterface;

    /**
     * Find a user by UUID.
     *
     * @param string $uuid
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findByUuid(string $uuid, array $withRelations = []): ?UserInterface;

    /**
     * Find a user by email.
     *
     * @param string $email
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findByEmail(string $email, array $withRelations = []): ?UserInterface;

    /**
     * Register a new user from a flat attributes array.
     *
     * Expected keys (adjust to your schema):
     * - uuid (optional)
     * - first_name
     * - last_name
     * - email (required)
     * - password (required, plaintext)
     * - activation_token (optional; auto-created when $activate === false if missing)
     *
     * Behavior:
     * - Hashes the plaintext password before persistence.
     * - If $activate === true: sets user as activated (and clears activation_token if present).
     * - If $activate === false: ensures activation_token exists and sets activated = false.
     *
     * @param array $attributes  Associative array of user fields.
     * @param bool $activate    Whether to mark the user as activated immediately. Default false.
     *
     * @return UserInterface
     *
     * @throws \InvalidArgumentException When required fields are missing (e.g., email/password).
     * @throws \RuntimeException         When the user cannot be persisted.
     */
    public function register(array $attributes, bool $activate = false): UserInterface;

    /**
     * Check the current authentication state and return the authenticated user if available.
     *
     * Behavior:
     * - Returns a UserInterface instance if the session contains a valid user id.
     * - Returns null if there is no active session or no authenticated user.
     *
     * Notes:
     * - This is framework-agnostic. Your application must set
     *   $_SESSION['sentinel_user_id'] after a successful login.
     *
     * @param string[] $withRelations Optional list of relation method names to eager-load
     *
     * @return UserInterface|null
     */
    public function check(array $withRelations = []): ?UserInterface;
}
