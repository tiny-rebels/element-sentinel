<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    PersistenceRepositoryInterface,
    UserInterface,
    UserRepositoryInterface
};

use Element\Sentinel\Services\Exceptions\Auth\RelationsNotSupportedException;

/**
 * EloquentUserRepository
 *
 * Repository responsible for loading user entities from the configured
 * Eloquent model class. Supports:
 *
 *  - Session and remember-me lookup in check()
 *  - Optional runtime eager-loading (ONLY for the standard EloquentUser model)
 *  - Nested eager-loading such as "permissions.items"
 *  - Safe relation filtering against actual top-level model methods
 *  - Strict runtime-relations policy for local user models
 */
class EloquentUserRepository implements UserRepositoryInterface {

    /** @var string */
    private $userModelClass;

    /** @var PersistenceRepositoryInterface|null */
    private $persistenceRepository;

    /** @var string[] */
    private $defaultEagerRelations;

    /**
     * When false = runtime withRelations() is forbidden and will throw.
     *
     * @var bool
     */
    private $honorRuntimeRelations;

    /**
     * @param string                              $userModelClass
     * @param PersistenceRepositoryInterface|null $persistenceRepository
     * @param string[]                            $defaultEagerRelations
     * @param bool                                $honorRuntimeRelations
     */
    public function __construct(
        string $userModelClass,
        ?PersistenceRepositoryInterface $persistenceRepository = null,
        array $defaultEagerRelations = [],
        bool $honorRuntimeRelations = true
    ) {
        $this->userModelClass        = $userModelClass;
        $this->persistenceRepository = $persistenceRepository;
        $this->defaultEagerRelations = $defaultEagerRelations;
        $this->honorRuntimeRelations = $honorRuntimeRelations;
    }

    /**
     * Return the authenticated user, or null.
     *
     * Behavior:
     *  - For the standard EloquentUser model, $withRelations MAY contain
     *    nested relations (ex: "permissions.items").
     *
     *  - For any local application user model, $withRelations MUST be empty.
     *    If not, a RuntimeRelationsNotSupportedException is thrown because
     *    local models ALWAYS control their own eager-loading.
     *
     * @param string[] $withRelations
     *
     * @return UserInterface|null
     */
    public function check(array $withRelations = []): ?UserInterface {

        if (session_status() !== PHP_SESSION_ACTIVE) {

            return null;
        }

        // Runtime eager-loading is NOT allowed for local models
        if (!$this->honorRuntimeRelations && !empty($withRelations)) {

            throw new RelationsNotSupportedException(
                'Runtime eager-loading (withRelations) is not supported for local user models. Local relations must be defined directly on the application model.',
                1801,
                null,
                [
                    'withRelations' => $withRelations,
                    'userModelClass' => $this->userModelClass,
                ]
            );
        }

        $sessionUserId = $_SESSION['sentinel_user_id'] ?? null;

        if (!empty($sessionUserId)) {

            return $this->findByIdWith($sessionUserId, $withRelations);
        }

        if ($this->persistenceRepository) {

            $rememberUserId = $this->persistenceRepository->userIdFromRememberCookie();

            if (!empty($rememberUserId)) {

                $_SESSION['sentinel_user_id'] = $rememberUserId;

                return $this->findByIdWith($rememberUserId, $withRelations);
            }
        }

        return null;
    }

    /**
     * Find user by primary key with default eager-relations only.
     *
     * @param int|string $userId
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findById($userId, array $withRelations = []): ?UserInterface {

        if (!$this->honorRuntimeRelations && !empty($withRelations)) {

            throw new RelationsNotSupportedException(
                'Runtime eager-loading (withRelations) is not supported for local user models. Local relations must be defined directly on the application model.',
                1802,
                null,
                [
                    'withRelations' => $withRelations,
                    'userModelClass' => $this->userModelClass,
                ]
            );
        }

        return $this->findByIdWith($userId, $withRelations);

    }

    /**
     * Save a user entity.
     *
     * @param UserInterface $userObject
     *
     * @return void
     */
    public function save(UserInterface $userObject): void {

        if ($userObject instanceof $this->userModelClass) {

            $userObject->save();

            return;
        }

        $this->updateNonEloquentUser($userObject);
    }

    /**
     * Internal helper: find user with optional eager-loading.
     *
     * Supports nested relations such as "permissions.items".
     *
     * @param int|string $userId
     * @param string[]   $withRelations
     *
     * @return UserInterface|null
     */
    private function findByIdWith($userId, array $withRelations): ?UserInterface {

        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $this->userModelClass();

        $query = $model->newQuery();

        // Merge default eager relations with runtime ones, but only if allowed
        $relations = $this->honorRuntimeRelations ? $this->mergeRelations($this->defaultEagerRelations, $withRelations) : $this->defaultEagerRelations;

        // Fail-safe filtering: allow nested relations but check only top-level methods
        $safeRelations = $this->filterExistingRelations($model, $relations);

        if (!empty($safeRelations)) {

            $query->with($safeRelations);
        }

        $found = $query->find($userId);

        return ($found instanceof UserInterface) ? $found : null;
    }

    /**
     * Filter out relation names that cannot exist on model.
     *
     * Allows nested relations such as:
     *   permissions.items
     *   permissions.items.children
     *
     * Logic:
     *   - Split by "." → ['permissions', 'items']
     *   - Check ONLY the first segment on the model
     *   - If method exists, allow FULL nested string
     *
     * @param \Illuminate\Database\Eloquent\Model $modelInstance
     * @param string[]                            $candidateRelations
     *
     * @return string[]
     */
    private function filterExistingRelations($modelInstance, array $candidateRelations): array {

        if (empty($candidateRelations)) {

            return [];
        }

        $valid = [];

        foreach ($candidateRelations as $relationName) {

            if (!is_string($relationName)) {

                continue;
            }

            $trimmed = trim($relationName);

            if ($trimmed === '') {

                continue;
            }

            $segments = explode('.', $trimmed);
            $topLevel = $segments[0];

            if (method_exists($modelInstance, $topLevel)) {

                $valid[] = $trimmed;
            }
        }

        return array_values(array_unique($valid));
    }

    /**
     * Merge and normalize two relation lists.
     *
     * @param string[] $base
     * @param string[] $extra
     *
     * @return string[]
     */
    private function mergeRelations(array $base, array $extra): array {

        $result = [];

        foreach (array_merge($base, $extra) as $name) {

            if (!is_string($name)) {

                continue;
            }

            $trimmed = trim($name);

            if ($trimmed !== '') {

                $result[] = $trimmed;
            }
        }

        return array_values(array_unique($result));
    }

    /**
     * Minimal persistence for non-eloquent entities.
     *
     * @param UserInterface $userObject
     *
     * @return void
     */
    private function updateNonEloquentUser(UserInterface $userObject): void {

        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $this->userModelClass();

        $model->newQuery()->where('id', '=', $userObject->getId())->update([

            'is_activated' => $userObject->isActivated() ? 1 : 0,
        ]);
    }
}
