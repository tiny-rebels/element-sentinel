<?php

namespace Element\Sentinel\Services;

use Element\Sentinel\Contracts\{
    PermissionRepositoryInterface,
    RoleRepositoryInterface
};

use Psr\Log\LoggerInterface;

/**
 * PermissionManager
 *
 * Decision rule (ALWAYS "combined"):
 *  1) If the permission exists directly on the user (user-based) => ALLOW
 *  2) Else, if the permission exists via any of the user's roles (role-based) => ALLOW
 *  3) Else => DENY
 *
 * User-based permissions ALWAYS have higher priority than role-based permissions.
 */
final class PermissionManager {

    /** @var PermissionRepositoryInterface */
    private $permissions;

    /** @var RoleRepositoryInterface */
    private $roles;

    /** @var LoggerInterface|null */
    private $logger;

    /** @var bool */
    private $autoCreate;

    /** @var array<int|string, string[]> */
    private $userPermCache = [];

    /** @var array<int|string, array<string,bool>> */
    private $roleCheckCache = [];

    /**
     * @param PermissionRepositoryInterface $permissions
     * @param RoleRepositoryInterface       $roles
     * @param LoggerInterface|null          $logger
     * @param bool                          $autoCreate  Auto-create missing permissions on sync* methods.
     */
    public function __construct(
        PermissionRepositoryInterface $permissions,
        RoleRepositoryInterface $roles,
        ?LoggerInterface $logger = null,
        bool $autoCreate = true
    ) {
        $this->permissions = $permissions;
        $this->roles       = $roles;
        $this->logger      = $logger;
        $this->autoCreate  = $autoCreate;
    }

    /**
     * Evaluate permission for a given user id using the combined rule.
     *
     * @param int|string $userId
     * @param string     $permissionSlug
     *
     * @return bool
     */
    public function userCan($userId, string $permissionSlug): bool {

        // 1) User-based (highest priority)
        if ($this->userHasUserBasedCached($userId, $permissionSlug)) {

            return true;
        }

        // 2) Role-based fallback
        return $this->userHasRoleBasedCached($userId, $permissionSlug);
    }

    // ----------------------------
    // User-based assignment API
    // ----------------------------

    public function grantToUser($userId, array $slugs): void {

        $this->permissions->grantToUser($userId, $slugs);

        // Invalidate per-request cache
        unset($this->userPermCache[$userId]);

        if ($this->logger) {

            $this->logger->info('Permissions: granted to user', [

                'user_id'       => $userId,
                'permissions'   => $slugs,
            ]);
        }
    }

    public function revokeFromUser($userId, array $slugs): void {

        $this->permissions->revokeFromUser($userId, $slugs);

        unset($this->userPermCache[$userId]);

        if ($this->logger) {

            $this->logger->info('Permissions: revoked from user', [

                'user_id'       => $userId,
                'permissions'   => $slugs,
            ]);
        }
    }

    public function syncUser($userId, array $slugs): void {

        $this->permissions->syncForUser($userId, $slugs, $this->autoCreate);

        unset($this->userPermCache[$userId]);

        if ($this->logger) {

            $this->logger->info('Permissions: synced for user', [

                'user_id'       => $userId,
                'permissions'   => $slugs,
                'autoCreate'    => $this->autoCreate,
            ]);
        }
    }

    // ----------------------------
    // Role-based assignment API
    // ----------------------------

    /**
     * @param int|string $roleId  Numeric role id (caller-resolved).
     * @param string[]   $slugs
     */
    public function grantToRole($roleId, array $slugs): void {

        $this->permissions->grantToRole($roleId, $slugs);

        // Conservative: clear all role-based checks cache
        $this->roleCheckCache = [];

        if ($this->logger) {

            $this->logger->info('Permissions: granted to role', [

                'role_id'       => $roleId,
                'permissions'   => $slugs,
            ]);
        }
    }

    public function revokeFromRole($roleId, array $slugs): void {

        $this->permissions->revokeFromRole($roleId, $slugs);

        $this->roleCheckCache = [];

        if ($this->logger) {

            $this->logger->info('Permissions: revoked from role', [

                'role_id'       => $roleId,
                'permissions'   => $slugs,
            ]);
        }
    }

    public function syncRole($roleId, array $slugs): void {

        $this->permissions->syncForRole($roleId, $slugs, $this->autoCreate);

        $this->roleCheckCache = [];

        if ($this->logger) {

            $this->logger->info('Permissions: synced for role', [

                'role_id'       => $roleId,
                'permissions'   => $slugs,
                'autoCreate'    => $this->autoCreate,
            ]);
        }
    }

    // ----------------------------
    // Internal helpers (per-request cache)
    // ----------------------------

    /**
     * @param int|string $userId
     * @param string     $slug
     *
     * @return bool
     */
    private function userHasUserBasedCached($userId, string $slug): bool {

        if (!array_key_exists($userId, $this->userPermCache)) {

            $this->userPermCache[$userId] = $this->permissions->userPermissionSlugs($userId);
        }

        return in_array($slug, $this->userPermCache[$userId], true);
    }

    /**
     * @param int|string $userId
     * @param string     $slug
     *
     * @return bool
     */
    private function userHasRoleBasedCached($userId, string $slug): bool {

        if (!isset($this->roleCheckCache[$userId])) {

            $this->roleCheckCache[$userId] = [];
        }

        if (array_key_exists($slug, $this->roleCheckCache[$userId])) {

            return $this->roleCheckCache[$userId][$slug];
        }

        $result = $this->permissions->userHasPermissionRoleBased($userId, $slug);

        $this->roleCheckCache[$userId][$slug] = $result;

        return $result;
    }
}
