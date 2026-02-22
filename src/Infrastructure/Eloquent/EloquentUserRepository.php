<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    UserInterface,
    UserRepositoryInterface,
    PersistenceRepositoryInterface
};

/**
 * EloquentUserRepository
 *
 * Eloquent repository implementation for User records.
 * Provides generic responsibilities: findById, save, and check (session/remember-me).
 */
class EloquentUserRepository implements UserRepositoryInterface {

    /** @var PersistenceRepositoryInterface|null */
    private $persistences;

    /**
     * Optionally inject a PersistenceRepository to enable remember-me hydration in check().
     *
     * @param PersistenceRepositoryInterface|null $persistences
     */
    public function __construct(PersistenceRepositoryInterface $persistences = null) {

        $this->persistences = $persistences;
    }

    /**
     * Find a user by primary key.
     *
     * @param int|string $userId
     *
     * @return UserInterface|null
     */
    public function findById($userId): ?UserInterface {

        return EloquentUser::query()->find($userId);
    }

    /**
     * Persist a user entity.
     *
     * If the given object is the Eloquent model, save directly.
     * Otherwise, perform a best-effort update for non-Eloquent models.
     *
     * @param UserInterface $userObject
     *
     * @return void
     */
    public function save(UserInterface $userObject): void {

        if ($userObject instanceof EloquentUser) {

            $userObject->save();

            return;
        }

        $this->updateNonEloquentUser($userObject);
    }

    /**
     * Check the current authentication state and return the authenticated user if available.
     *
     * Behavior:
     * - If a session id is set, return that user.
     * - Else, if a remember cookie is present and valid (and a PersistenceRepository is configured),
     *   hydrate the session and return that user.
     *
     * @return UserInterface|null
     */
    public function check(): ?UserInterface {

        if (session_status() !== PHP_SESSION_ACTIVE) {

            return null;
        }

        $userId = $_SESSION['sentinel_user_id'] ?? null;

        if (!empty($userId)) {

            return $this->findById($userId);
        }

        if ($this->persistences) {

            $rememberUserId = $this->persistences->userIdFromRememberCookie();

            if (!empty($rememberUserId)) {

                $_SESSION['sentinel_user_id'] = $rememberUserId;

                return $this->findById($rememberUserId);
            }
        }

        return null;
    }

    /**
     * Update a non-Eloquent user entity in the database.
     * Only toggles activation flag and updated_at, assuming the record exists.
     *
     * @param UserInterface $userObject
     *
     * @return void
     */
    private function updateNonEloquentUser(UserInterface $userObject): void {

        EloquentUser::query()->where('id', '=', $userObject->getId())->update([

            'is_activated' => $userObject->isActivated() ? 1 : 0,
            'updated_at'   => date('Y-m-d H:i:s'),
        ]);
    }
}
