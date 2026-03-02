<?php

namespace Element\Sentinel\Contracts;

/**
 * RoleRepositoryInterface
 *
 * Abstraction for role storage & user-role assignments.
 */
interface RoleRepositoryInterface {

    public function findById($id): ?RoleInterface;

    public function findBySlug(string $slug): ?RoleInterface;

    /**
     * Create a role if it does not exist (idempotent).
     */
    public function createIfMissing(string $slug, ?string $name = null): RoleInterface;

    /**
     * Return role slugs assigned to a user.
     *
     * @param int|string $userId
     * @return string[]
     */
    public function userRoleSlugs($userId): array;

    /**
     * Assign (attach) roles by slug (role must exist).
     *
     * @param int|string $userId
     * @param string[]   $slugs
     */
    public function assignToUser($userId, array $slugs): void;

    /**
     * Sync user roles exactly to the given set (creates/detaches as needed when autoCreate is enabled).
     *
     * @param int|string $userId
     * @param string[]   $slugs
     * @param bool       $autoCreate
     */
    public function syncForUser($userId, array $slugs, bool $autoCreate = true): void;

    /**
     * Revoke (detach) selected roles by slug.
     *
     * @param int|string $userId
     * @param string[]   $slugs
     */
    public function revokeFromUser($userId, array $slugs): void;

    /**
     * Check if user has a given role slug.
     *
     * @param int|string $userId
     * @param string     $slug
     */
    public function userHasRole($userId, string $slug): bool;
}
