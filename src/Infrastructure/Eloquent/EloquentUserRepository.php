<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{ActivationRepositoryInterface,
    PasswordHasherInterface,
    PersistenceRepositoryInterface,
    UserInterface,
    UserRepositoryInterface};

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

    /** @var ActivationRepositoryInterface */
    private $activationsRepository;

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
     * @param string $userModelClass
     * @param ActivationRepositoryInterface|null $activationsRepository
     * @param PersistenceRepositoryInterface|null $persistenceRepository
     * @param PasswordHasherInterface $passwordHasher
     * @param string[] $defaultEagerRelations
     * @param bool $honorRuntimeRelations
     */
    public function __construct(
        string $userModelClass,
        ?ActivationRepositoryInterface $activationsRepository = null,
        ?PersistenceRepositoryInterface $persistenceRepository = null,
        PasswordHasherInterface $passwordHasher,
        array $defaultEagerRelations = [],
        bool $honorRuntimeRelations = true
    ) {
        $this->userModelClass        = $userModelClass;
        $this->activationsRepository = $activationsRepository;
        $this->persistenceRepository = $persistenceRepository;
        $this->passwordHasher        = $passwordHasher;
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

            return $this->lookupUser($sessionUserId, $withRelations);
        }

        if ($this->persistenceRepository) {

            $rememberUserId = $this->persistenceRepository->userIdFromRememberCookie();

            if (!empty($rememberUserId)) {

                $_SESSION['sentinel_user_id'] = $rememberUserId;

                return $this->lookupUser($rememberUserId, $withRelations);
            }
        }

        return null;
    }

    /**
     * Register a new user from a flat attributes array.
     * + create activation record + optionally complete activation.
     *
     * Required keys:
     *  - email (string)
     *  - password (string, plaintext)
     *  - activation_token (string)         Note! required only when $activate === false
     *
     * Optional keys (adjust to your schema):
     *  - uuid, first_name, last_name, is_activated
     *
     * @param array $attributes
     * @param bool $activate
     *
     * @return UserInterface
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public function register(array $attributes, bool $activate = false): UserInterface {

        // 1) Validate basic fields
        $email    = isset($attributes['email']) ? (string) $attributes['email'] : '';
        $password = isset($attributes['password']) ? (string) $attributes['password'] : '';

        if ($email === '' || $password === '') {

            throw new \InvalidArgumentException('Missing required fields: email and/or password.');
        }

        // UI-token required when not activating immediately
        if (!$activate) {

            if (!isset($attributes['activation_token']) || (string) $attributes['activation_token'] === '') {

                throw new \InvalidArgumentException(
                    'activation_token is required when $activate is false.'
                );
            }
        }

        /** @var \Illuminate\Database\Eloquent\Model|\Element\Sentinel\Contracts\UserInterface $user */
        $userClass = $this->userModelClass;

        // 2) Wrap all operations in a DB transaction (safe)
        return \Illuminate\Database\Capsule\Manager::connection()->transaction(function () use ($userClass, $attributes, $email, $password, $activate) {

            $user = new $userClass();

            // ---- Set core attributes
            if (isset($attributes['uuid']) && $attributes['uuid'] !== '') {

                $user->uuid = (string) $attributes['uuid'];
            }

            $user->first_name = isset($attributes['first_name']) ? (string) $attributes['first_name'] : null;
            $user->last_name  = isset($attributes['last_name'])  ? (string) $attributes['last_name']  : null;
            $user->email      = $email;

            // ---- Hash password using your configured hasher
            if (!isset($this->passwordHasher) || !method_exists($this->passwordHasher, 'hash')) {

                throw new \RuntimeException('Password hasher is not configured or missing hash() method.');
            }

            $user->password = (string) $this->passwordHasher->hash($password);

            // ---- activation_token (UI OTP)
            if ($activate) {

                $user->activation_token = null;
                $user->is_activated = 1;

            } else {

                $user->activation_token = (string) $attributes['activation_token'];
                $user->is_activated = 0;
            }

            if (!$user->save()) {

                throw new \RuntimeException('User could not be saved.');
            }

            //
            // 3) Create activation row in `activations` (ALWAYS)
            //
            // Your ActivationRepository generates its own internal activation `code`
            // via CodeGenerator::random(32).
            //
            /** @var ActivationInterface $activation */
            $activation = $this->activationsRepository->create($user);

            //
            // 4) Complete activation immediately if requested
            //
            if ($activate) {

                $this->activationsRepository->complete($user, $activation->code);

                // Clear UI-token (just to keep user-row clean)
                if ($user->activation_token !== null) {

                    $user->activation_token = null;

                    $user->save();
                }
            }

            // done
            return $user;
        });
    }

    /**
     * Find user by primary key with default eager-relations only.
     *
     * @param int $id
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public function findById(int $id, array $withRelations = []): ?UserInterface {

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

        // Delegate to the unified lookup method.
        return $this->lookupUser($id, $withRelations);
    }

    /**
     * Find a user by UUID.
     *
     * @param string $uuid
     * @param string[] $withRelations
     *
     * @return UserInterface|null
     */
    public function findByUuid(string $uuid, array $withRelations = []): ?UserInterface {

        if (!$this->honorRuntimeRelations && !empty($withRelations)) {

            throw new RelationsNotSupportedException(
                'Runtime eager-loading (withRelations) is not supported for local user models. Local relations must be defined directly on the application model.',
                1803,
                null,
                [
                    'withRelations'  => $withRelations,
                    'userModelClass' => $this->userModelClass,
                    'uuid'           => $uuid,
                ]
            );
        }

        // Delegate to the unified lookup method.
        return $this->lookupUser($uuid, $withRelations);
    }

    /**
     * Find a user by email.
     *
     * @param string $email
     * @param string[] $withRelations
     *
     * @return UserInterface|null
     */
    public function findByEmail(string $email, array $withRelations = []): ?UserInterface {

        if (!$this->honorRuntimeRelations && !empty($withRelations)) {

            throw new RelationsNotSupportedException(
                'Runtime eager-loading (withRelations) is not supported for local user models. Local relations must be defined directly on the application model.',
                1803,
                null,
                [
                    'withRelations'  => $withRelations,
                    'userModelClass' => $this->userModelClass,
                    'email'          => $email,
                ]
            );
        }

        // Delegate to the unified lookup method.
        return $this->lookupUser($email, $withRelations);
    }

    /**
     * Internal helper: Unified user lookup by either ID, UUID or email.
     *
     * Resolution order:
     *  - If $identifier is a valid email  -> where('email', $identifier)->first()
     *  - Else if $identifier looks like UUID (8-4-4-4-12) -> where('uuid', $identifier)->first()
     *  - Else -> ->find($identifier)  (primary key lookup; works for int or string PKs)
     *
     *  - Honors default eager relations and optional runtime relations (when allowed)
     *    such as "permissions.items".
     *
     * @param mixed     $identifier         Expected: int|string (ID/email/uuid)
     * @param string[]  $withRelations
     *
     * @return UserInterface|null
     */

    private function lookupUser($identifier, array $withRelations = []): ?UserInterface {

        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $this->userModelClass();
        $query = $model->newQuery();

        // Merge default eager relations with runtime ones, but only if allowed
        $relations = $this->honorRuntimeRelations ? $this->mergeRelations($this->defaultEagerRelations, $withRelations) : $this->defaultEagerRelations;

        // Fail-safe: only include relations that actually exist on the model
        $safeRelations = $this->filterExistingRelations($model, $relations);

        if (!empty($safeRelations)) {

            $query->with($safeRelations);
        }

        // Normalize to string for checks that require string
        $identifierStr = is_string($identifier) ? $identifier : (string) $identifier;

        // 1) Email?
        $isEmail = is_string($identifier) && filter_var($identifier, FILTER_VALIDATE_EMAIL);

        // 2) UUID? (generic RFC 4122 8-4-4-4-12, case-insensitive)
        $isUuid = is_string($identifier) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $identifierStr) === 1;

        if ($isEmail) {

            $found = $query->where('email', '=', $identifierStr)->first();

        } elseif ($isUuid) {

            $found = $query->where('uuid', '=', $identifierStr)->first();

        } else {

            // Primary key lookup (supports int or string PKs)
            $found = $query->find($identifier);
        }

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
