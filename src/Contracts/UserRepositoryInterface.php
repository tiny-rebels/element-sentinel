<?php

namespace Element\Sentinel\Contracts;

/**
 * UserRepositoryInterface
 *
 * Generic user repository contract. Framework-agnostic by design.
 */
interface UserRepositoryInterface {

    /**
     * Find a user by primary key.
     *
     * @param int|string $id
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findById($id, array $withRelations = []): ?UserInterface;

    /**
     * Persist a user entity.
     *
     * @param UserInterface $user
     *
     * @return void
     */
    public function save(UserInterface $user);

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
