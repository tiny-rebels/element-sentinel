<?php

namespace Element\Sentinel\Contracts;

/**
 * PermissionRepositoryInterface
 *
 * Abstraction for permission storage and assignments to users and roles.
 */
interface PermissionRepositoryInterface {

    /**
     * Find a permission by slug.
     *
     * @param string $slug
     *
     * @return PermissionInterface|null
     */
    public function findBySlug(string $slug): ?PermissionInterface;

    /**
     * Create a permission if missing (idempotent).
     *
     * @param string      $slug
     * @param string|null $name
     *
     * @return PermissionInterface
     */
    public function createIfMissing(string $slug, ?string $name = null): PermissionInterface;

    /**
     * Return user-based permission slugs for a user.
     *
     * @param int|string $userId
     *
     * @return string[]
     */
    public function userPermissionSlugs($userId): array;

    /**
     * Return role-based permission slugs for a role.
     *
     * @param int|string $roleId
     *
     * @return string[]
     */
    public function rolePermissionSlugs($roleId): array;

    /**
     * Grant permissions directly to a user (attach).
     *
     * @param int|string $userId
     * @param string[]   $permissionSlugs
     *
     * @return void
     */
    public function grantToUser($userId, array $permissionSlugs): void;

    /**
     * Revoke permissions from a user (detach).
     *
     * @param int|string $userId
     * @param string[]   $permissionSlugs
     *
     * @return void
     */
    public function revokeFromUser($userId, array $permissionSlugs): void;

    /**
     * Synchronize the exact set of permissions for a user.
     *
     * @param int|string $userId
     * @param string[]   $permissionSlugs
     * @param bool       $automaticallyCreateMissing
     *
     * @return void
     */
    public function syncForUser($userId, array $permissionSlugs, bool $automaticallyCreateMissing = true): void;

    /**
     * Grant permissions to a role (attach).
     *
     * @param int|string $roleId
     * @param string[]   $permissionSlugs
     *
     * @return void
     */
    public function grantToRole($roleId, array $permissionSlugs): void;

    /**
     * Revoke permissions from a role (detach).
     *
     * @param int|string $roleId
     * @param string[]   $permissionSlugs
     *
     * @return void
     */
    public function revokeFromRole($roleId, array $permissionSlugs): void;

    /**
     * Synchronize the exact set of permissions for a role.
     *
     * @param int|string $roleId
     * @param string[]   $permissionSlugs
     * @param bool       $automaticallyCreateMissing
     *
     * @return void
     */
    public function syncForRole($roleId, array $permissionSlugs, bool $automaticallyCreateMissing = true): void;

    /**
     * Combined-evaluation helpers: underlying checks for user-based and role-based.
     *
     * @param int|string $userId
     * @param string     $permissionSlug
     *
     * @return bool
     */
    public function userHasPermissionUserBased($userId, string $permissionSlug): bool;

    /**
     * @param int|string $userId
     * @param string     $permissionSlug
     *
     * @return bool
     */
    public function userHasPermissionRoleBased($userId, string $permissionSlug): bool;
}
