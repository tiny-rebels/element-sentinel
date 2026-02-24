<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    PermissionInterface,
    PermissionRepositoryInterface
};

use Illuminate\Database\{
    Capsule\Manager as DB,
    Eloquent\Model
};

/**
 * EloquentPermissionRepository
 *
 * Pluggable permission model, with user- and role-based pivots.
 * Works with or without defined Eloquent relations on your models.
 */
class EloquentPermissionRepository implements PermissionRepositoryInterface {

    /** @var class-string<Model&PermissionInterface> */
    private $permissionModelClass;

    /** @var class-string<Model> */
    private $userModelClass;

    /** @var string */
    private $permissionUserPivotTable;

    /** @var string */
    private $permissionRolePivotTable;

    /** @var string */
    private $roleUserPivotTable;

    /** @var string */
    private $userForeignKey;

    /** @var string */
    private $roleForeignKey;

    /** @var string */
    private $permissionForeignKey;

    /**
     * @param string $permissionModelClass       FQCN of the permission model (implements PermissionInterface)
     * @param string $userModelClass             FQCN of the user model (extends Eloquent Model)
     * @param string $permissionUserPivotTable   Pivot table name for user-permission
     * @param string $permissionRolePivotTable   Pivot table name for role-permission
     * @param string $roleUserPivotTable         Pivot table name for user-role (used in role-based checks)
     * @param string $userForeignKey             Foreign key name to user id
     * @param string $roleForeignKey             Foreign key name to role id
     * @param string $permissionForeignKey       Foreign key name to permission id
     */
    public function __construct(
        string $permissionModelClass,
        string $userModelClass,
        string $permissionUserPivotTable = 'permission_user',
        string $permissionRolePivotTable = 'permission_role',
        string $roleUserPivotTable = 'role_user',
        string $userForeignKey = 'user_id',
        string $roleForeignKey = 'role_id',
        string $permissionForeignKey = 'permission_id'
    ) {
        $this->permissionModelClass     = $permissionModelClass;
        $this->userModelClass           = $userModelClass;
        $this->permissionUserPivotTable = $permissionUserPivotTable;
        $this->permissionRolePivotTable = $permissionRolePivotTable;
        $this->roleUserPivotTable       = $roleUserPivotTable;
        $this->userForeignKey           = $userForeignKey;
        $this->roleForeignKey           = $roleForeignKey;
        $this->permissionForeignKey     = $permissionForeignKey;
    }

    /**
     * {@inheritdoc}
     */
    public function findBySlug(string $slug): ?PermissionInterface {

        /** @var Model $model */
        $model = new $this->permissionModelClass();

        $found = $model->newQuery()->where('slug', '=', $slug)->first();

        return ($found instanceof PermissionInterface) ? $found : null;
    }

    /**
     * {@inheritdoc}
     */
    public function createIfMissing(string $slug, ?string $name = null): PermissionInterface {

        /** @var Model $model */
        $model = new $this->permissionModelClass();

        /** @var Model|null $existing */
        $existing = $model->newQuery()->where('slug', '=', $slug)->first();

        if ($existing instanceof PermissionInterface) {
            return $existing;
        }

        /** @var Model&PermissionInterface $created */
        $created = $model->newQuery()->create([

                'slug' => $slug,
                'name' => $name !== null ? $name : ucfirst(str_replace('-', ' ', $slug)),
            ]);

        return $created;
    }

    /**
     * {@inheritdoc}
     */
    public function userPermissionSlugs($userId): array {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        return DB::table($this->permissionUserPivotTable)
            ->join(
                $permissionTable,
                $this->permissionUserPivotTable . '.' . $this->permissionForeignKey,
                '=',
                $permissionTable . '.id'
            )
            ->where($this->permissionUserPivotTable . '.' . $this->userForeignKey, $userId)
            ->pluck($permissionTable . '.slug')
            ->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function rolePermissionSlugs($roleId): array {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        return DB::table($this->permissionRolePivotTable)
            ->join(
                $permissionTable,
                $this->permissionRolePivotTable . '.' . $this->permissionForeignKey,
                '=',
                $permissionTable . '.id'
            )
            ->where($this->permissionRolePivotTable . '.' . $this->roleForeignKey, $roleId)
            ->pluck($permissionTable . '.slug')
            ->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function grantToUser($userId, array $permissionSlugs): void{

        $permissionIds = $this->ensurePermissionIds($permissionSlugs, false);

        $existing = DB::table($this->permissionUserPivotTable)->where($this->userForeignKey, '=', $userId)->pluck($this->permissionForeignKey)->toArray();

        $toAttach = array_diff($permissionIds, $existing);

        foreach ($toAttach as $permissionId) {

            DB::table($this->permissionUserPivotTable)->insert([

                $this->userForeignKey       => $userId,
                $this->permissionForeignKey => $permissionId,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokeFromUser($userId, array $permissionSlugs): void {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        $permissionIds = DB::table($permissionTable)
            ->whereIn('slug', $this->cleanSlugs($permissionSlugs))
            ->pluck('id')
            ->toArray();

        if (!empty($permissionIds)) {

            DB::table($this->permissionUserPivotTable)->where($this->userForeignKey, '=', $userId)->whereIn($this->permissionForeignKey, $permissionIds)->delete();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function syncForUser($userId, array $permissionSlugs, bool $automaticallyCreateMissing = true): void {

        $desiredIds = $this->ensurePermissionIds($permissionSlugs, $automaticallyCreateMissing);

        $current = DB::table($this->permissionUserPivotTable)->where($this->userForeignKey, '=', $userId)->pluck($this->permissionForeignKey)->toArray();

        $toAttach = array_diff($desiredIds, $current);
        $toDetach = array_diff($current, $desiredIds);

        if (!empty($toDetach)) {

            DB::table($this->permissionUserPivotTable)->where($this->userForeignKey, '=', $userId)->whereIn($this->permissionForeignKey, $toDetach)->delete();
        }

        foreach ($toAttach as $permissionId) {

            DB::table($this->permissionUserPivotTable)->insert([

                $this->userForeignKey       => $userId,
                $this->permissionForeignKey => $permissionId,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function grantToRole($roleId, array $permissionSlugs): void {

        $permissionIds = $this->ensurePermissionIds($permissionSlugs, false);

        $existing = DB::table($this->permissionRolePivotTable)->where($this->roleForeignKey, '=', $roleId)->pluck($this->permissionForeignKey)->toArray();

        $toAttach = array_diff($permissionIds, $existing);

        foreach ($toAttach as $permissionId) {

            DB::table($this->permissionRolePivotTable)->insert([

                $this->roleForeignKey       => $roleId,
                $this->permissionForeignKey => $permissionId,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function revokeFromRole($roleId, array $permissionSlugs): void {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        $permissionIds = DB::table($permissionTable)->whereIn('slug', $this->cleanSlugs($permissionSlugs))->pluck('id')->toArray();

        if (!empty($permissionIds)) {

            DB::table($this->permissionRolePivotTable)->where($this->roleForeignKey, '=', $roleId)->whereIn($this->permissionForeignKey, $permissionIds)->delete();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function syncForRole($roleId, array $permissionSlugs, bool $automaticallyCreateMissing = true): void {

        $desiredIds = $this->ensurePermissionIds($permissionSlugs, $automaticallyCreateMissing);

        $current = DB::table($this->permissionRolePivotTable)->where($this->roleForeignKey, $roleId)->pluck($this->permissionForeignKey)->toArray();

        $toAttach = array_diff($desiredIds, $current);
        $toDetach = array_diff($current, $desiredIds);

        if (!empty($toDetach)) {

            DB::table($this->permissionRolePivotTable)->where($this->roleForeignKey, '=', $roleId)->whereIn($this->permissionForeignKey, $toDetach)->delete();
        }

        foreach ($toAttach as $permissionId) {

            DB::table($this->permissionRolePivotTable)->insert([

                $this->roleForeignKey       => $roleId,
                $this->permissionForeignKey => $permissionId,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function userHasPermissionUserBased($userId, string $permissionSlug): bool {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        $permissionId = DB::table($permissionTable)->where('slug', 'slug', $permissionSlug)->value('id');

        if (!$permissionId) {

            return false;
        }

        return DB::table($this->permissionUserPivotTable)->where($this->userForeignKey, '=', $userId)->where($this->permissionForeignKey, $permissionId)->exists();
    }

    /**
     * {@inheritdoc}
     */
    public function userHasPermissionRoleBased($userId, string $permissionSlug): bool {

        $permissionTable = (new $this->permissionModelClass())->getTable();

        $permissionId = DB::table($permissionTable)->where('slug', '=', $permissionSlug)->value('id');

        if (!$permissionId) {

            return false;
        }

        // role_user (ru) -> permission_role (pr)
        return DB::table($this->roleUserPivotTable . ' as ru')
            ->join('' . $this->permissionRolePivotTable . ' as pr', 'ru.' . $this->roleForeignKey, '=', 'pr.' . $this->roleForeignKey)
            ->where('ru.' . $this->userForeignKey, $userId)
            ->where('pr.' . $this->permissionForeignKey, $permissionId)
            ->exists();
    }

    /**
     * Ensure permission ids exist for given slugs; optionally create missing.
     *
     * @param string[] $permissionSlugs
     * @param bool     $automaticallyCreateMissing
     *
     * @return array<int>
     */
    private function ensurePermissionIds(array $permissionSlugs, bool $automaticallyCreateMissing): array {

        $permissionSlugs = $this->cleanSlugs($permissionSlugs);

        if (empty($permissionSlugs)) {

            return [];
        }

        /** @var Model $model */
        $model = new $this->permissionModelClass();

        $existing = $model->newQuery()->whereIn('slug', $permissionSlugs)->pluck('id', 'slug')->toArray();

        $ids = array_values($existing);

        if ($automaticallyCreateMissing) {

            $missing = array_diff($permissionSlugs, array_keys($existing));

            foreach ($missing as $slug) {

                /** @var Model&PermissionInterface $created */
                $created = $model->newQuery()->create([

                    'slug' => $slug,
                    'name' => ucfirst(str_replace('-', ' ', $slug)),
                ]);

                $ids[] = $created->getId();
            }
        }

        return $ids;
    }

    /**
     * Normalize and de-duplicate permission slugs.
     *
     * @param string[] $permissionSlugs
     *
     * @return string[]
     */
    private function cleanSlugs(array $permissionSlugs): array {

        $result = [];

        foreach ($permissionSlugs as $slug) {

            if (!is_string($slug)) {

                continue;
            }

            $normalized = strtolower(trim($slug));

            if ($normalized !== '') {

                $result[] = $normalized;
            }
        }

        return array_values(array_unique($result));
    }
}
