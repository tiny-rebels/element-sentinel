<?php

namespace Element\Sentinel\Services;

use Element\Sentinel\Contracts\RoleRepositoryInterface;

use Psr\Log\LoggerInterface;

/**
 * RoleManager
 *
 * Facade-like manager to query and manage user roles.
 */
final class RoleManager {

    /** @var RoleRepositoryInterface */
    private $roles;

    /** @var LoggerInterface|null */
    private $logger;

    /** @var bool */
    private $autoCreate;

    /**
     * @param RoleRepositoryInterface $roles
     * @param LoggerInterface|null    $logger
     * @param bool                    $autoCreate  If true, missing roles are created on sync()
     */
    public function __construct(RoleRepositoryInterface $roles, ?LoggerInterface $logger = null, bool $autoCreate = true) {

        $this->roles      = $roles;
        $this->logger     = $logger;
        $this->autoCreate = $autoCreate;
    }

    /**
     * Get role slugs for a user.
     *
     * @param int|string $userId
     *
     * @return string[]
     */
    public function userRoles($userId): array {

        return $this->roles->userRoleSlugs($userId);
    }

    /**
     * Check if user has a given role slug.
     *
     * @param int|string $userId
     * @param string     $slug
     *
     * @return bool
     */
    public function userHasRole($userId, string $slug): bool {

        return $this->roles->userHasRole($userId, $slug);
    }

    /**
     * Assign roles to user (attach).
     *
     * @param int|string $userId
     * @param string[]   $slugs
     *
     * @return void
     */
    public function assign($userId, array $slugs): void {

        $this->roles->assignToUser($userId, $slugs);

        if ($this->logger) {

            $this->logger->info('Roles: assigned to user', [

                'user_id' => $userId,
                'roles'   => $slugs,
            ]);
        }
    }

    /**
     * Sync user's roles exactly to the given set.
     *
     * @param int|string $userId
     * @param string[]   $slugs
     *
     * @return void
     */
    public function sync($userId, array $slugs): void {

        $this->roles->syncForUser($userId, $slugs, $this->autoCreate);

        if ($this->logger) {

            $this->logger->info('Roles: synced for user', [

                'user_id'    => $userId,
                'roles'      => $slugs,
                'autoCreate' => $this->autoCreate,
            ]);
        }
    }

    /**
     * Revoke roles from user (detach).
     *
     * @param int|string $userId
     * @param string[]   $slugs
     *
     * @return void
     */
    public function revoke($userId, array $slugs): void {

        $this->roles->revokeFromUser($userId, $slugs);

        if ($this->logger) {

            $this->logger->info('Roles: revoked from user', [

                'user_id' => $userId,
                'roles'   => $slugs,
            ]);
        }
    }
}
