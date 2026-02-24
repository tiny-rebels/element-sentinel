<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    RoleInterface,
    RoleRepositoryInterface
};

use Illuminate\Database\{
    Capsule\Manager as DB,
    Eloquent\Model
};

/**
 * EloquentRoleRepository
 *
 * Pluggable role model, pluggable user model, configurable pivot table.
 * Works with or without a roles() relation on the user model.
 */
class EloquentRoleRepository implements RoleRepositoryInterface {

    /** @var class-string<Model&RoleInterface> */
    private $roleModelClass;

    /** @var class-string<Model> */
    private $userModelClass;

    /** @var string */
    private $pivotTable;

    /** @var string */
    private $userKey;

    /** @var string */
    private $roleKey;

    public function __construct(
        string $roleModelClass,
        string $userModelClass,
        string $pivotTable = 'users_roles',
        string $userKey = 'user_id',
        string $roleKey = 'role_id'
    ) {
        $this->roleModelClass = $roleModelClass;
        $this->userModelClass = $userModelClass;
        $this->pivotTable     = $pivotTable;
        $this->userKey        = $userKey;
        $this->roleKey        = $roleKey;
    }

    /**
     * @param $id
     *
     * @return RoleInterface|null
     */
    public function findById($id): ?RoleInterface {

        /** @var Model $role */
        $role = (new $this->roleModelClass())->newQuery()->find($id);

        return ($role instanceof RoleInterface) ? $role : null;
    }

    /**
     * @param string $slug
     *
     * @return RoleInterface|null
     */
    public function findBySlug(string $slug): ?RoleInterface {

        /** @var Model $role */
        $role = (new $this->roleModelClass())->newQuery()->where('slug', $slug)->first();

        return ($role instanceof RoleInterface) ? $role : null;
    }

    /**
     * @param string $slug
     * @param string|null $name
     *
     * @return RoleInterface
     */
    public function createIfMissing(string $slug, ?string $name = null): RoleInterface {

        /** @var Model $model */
        $model = new $this->roleModelClass();

        /** @var Model $found */
        $found = $model->newQuery()->where('slug', $slug)->first();

        if ($found instanceof RoleInterface) {

            return $found;
        }

        /** @var Model&RoleInterface $created */
        $created = $model->newQuery()->create([

            'slug' => $slug,
            'name' => $name ?? ucfirst(str_replace('-', ' ', $slug)),
        ]);

        return $created;
    }

    /**
     * @param $userId
     *
     * @return array|string[]
     */
    public function userRoleSlugs($userId): array {

        // Fast path via pivot + role table (no relation required)
        return DB::table($this->pivotTable)
            ->join((new $this->roleModelClass())->getTable(), $this->pivotTable.'.'.$this->roleKey, '=', (new $this->roleModelClass())->getTable().'.id')
            ->where($this->pivotTable .'.'. $this->userKey, $userId)
            ->pluck((new $this->roleModelClass())->getTable().'.slug')
            ->toArray();
    }

    /**
     * @param $userId
     * @param array $slugs
     *
     * @return void
     */
    public function assignToUser($userId, array $slugs): void {

        if (empty($slugs)) {

            return;
        }

        $roleIds = $this->ensureRoleIds($slugs, false);

        $existing = DB::table($this->pivotTable)->where($this->userKey, '=', $userId)->pluck($this->roleKey)->toArray();

        $toAttach = array_diff($roleIds, $existing);

        foreach ($toAttach as $rid) {

            DB::table($this->pivotTable)->insert([

                $this->userKey => $userId,
                $this->roleKey => $rid,
            ]);
        }
    }

    /**
     * @param $userId
     * @param array $slugs
     * @param bool $autoCreate
     *
     * @return void
     */
    public function syncForUser($userId, array $slugs, bool $autoCreate = true): void {

        $desiredIds = $this->ensureRoleIds($slugs, $autoCreate);

        $current = DB::table($this->pivotTable) ->where($this->userKey, '=', $userId)->pluck($this->roleKey)->toArray();

        $toAttach = array_diff($desiredIds, $current);
        $toDetach = array_diff($current, $desiredIds);

        if (!empty($toDetach)) {

            DB::table($this->pivotTable)->where($this->userKey, '=', $userId)->whereIn($this->roleKey, $toDetach)->delete();
        }

        foreach ($toAttach as $rid) {

            DB::table($this->pivotTable)->insert([

                $this->userKey => $userId,
                $this->roleKey => $rid,
            ]);
        }
    }

    /**
     * @param $userId
     * @param array $slugs
     *
     * @return void
     */
    public function revokeFromUser($userId, array $slugs): void {

        if (empty($slugs)) {

            return;
        }

        /** @var Model $model */
        $model = new $this->roleModelClass();

        $ids = $model->newQuery()->whereIn('slug', $this->cleanSlugs($slugs))->pluck('id')->toArray();

        if (!empty($ids)) {

            DB::table($this->pivotTable)->where($this->userKey, '=', $userId)->whereIn($this->roleKey, $ids)->delete();
        }
    }

    /**
     * @param $userId
     * @param string $slug
     *
     * @return bool
     */
    public function userHasRole($userId, string $slug): bool {

        /** @var Model $model */
        $model = new $this->roleModelClass();

        $roleId = $model->newQuery()->where('slug', $slug)->value('id');

        if (!$roleId) {

            return false;
        }

        return DB::table($this->pivotTable)->where($this->userKey, '=', $userId)->where($this->roleKey, '=', $roleId)->exists();
    }

    /**
     * Ensure role ids exist for given slugs; optionally auto-create missing.
     *
     * @param string[] $slugs
     * @param bool     $autoCreate
     *
     * @return array<int>
     */
    private function ensureRoleIds(array $slugs, bool $autoCreate): array {

        $slugs = $this->cleanSlugs($slugs);

        if (empty($slugs)) {

            return [];
        }

        /** @var Model $model */
        $model = new $this->roleModelClass();

        $existing = $model->newQuery()->whereIn('slug', $slugs)->pluck('id', 'slug')->toArray();

        $ids = array_values($existing);

        if ($autoCreate) {

            $missing = array_diff($slugs, array_keys($existing));

            foreach ($missing as $slug) {

                /** @var Model&RoleInterface $created */
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
     * @param string[] $slugs
     *
     * @return string[]
     */
    private function cleanSlugs(array $slugs): array {

        $out = [];

        foreach ($slugs as $s) {

            if (!is_string($s)) {

                continue;
            }

            $t = strtolower(trim($s));

            if ($t !== '') {

                $out[] = $t;
            }
        }

        return array_values(array_unique($out));
    }
}
