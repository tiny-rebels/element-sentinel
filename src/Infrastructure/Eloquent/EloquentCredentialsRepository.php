<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    CredentialsRepositoryInterface,
    UserInterface
};

use Illuminate\Database\Eloquent\Model;

/**
 * EloquentCredentialsRepository (email-only)
 *
 * Eloquent adapter for login lookup + password hash access, strictly by "email".
 */
class EloquentCredentialsRepository implements CredentialsRepositoryInterface {

    /** @var class-string<Model&UserInterface> */
    private $userModelClass;

    /**
     * @param string $userModelClass Fully-qualified class name of your Eloquent user model (implements UserInterface)
     */
    public function __construct($userModelClass) {

        $this->userModelClass = $userModelClass;
    }

    /**
     * Find user strictly by email address.
     *
     * @param string $login
     *
     * @return UserInterface|null
     */
    public function findByLogin($login): ?UserInterface {

        /** @var Model $modelInstance */
        $modelInstance = new $this->userModelClass();

        $foundUser = $modelInstance->newQuery()->where('email', '=', $login)->first();

        return ($foundUser instanceof UserInterface) ? $foundUser : null;
    }

    /**
     * Return the stored password hash for the given user.
     *
     * Uses Eloquent getAttribute to reliably read the "password" column.
     *
     * @param UserInterface $user
     *
     * @return string
     */
    public function getPasswordHash(UserInterface $user): string {

        if ($user instanceof Model) {

            $value = $user->getAttribute('password'); // works even if hidden/casted

            return is_string($value) ? $value : '';
        }

        // Fallback for non-Eloquent implementations (magic getter)
        $value = $user->password ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * Update (rehash) the stored password for the given user.
     *
     * Uses Eloquent set/get to be consistent with attribute access.
     *
     * @param UserInterface $user
     *
     * @param string $newHash
     *
     * @return void
     */
    public function updatePassword(UserInterface $user, $newHash): void {

        if ($user instanceof Model) {

            $user->setAttribute('password', $newHash);

            return;
        }

        // Fallback for non-Eloquent implementations
        if (isset($user->password)) {

            $user->password = $newHash;

        } elseif (method_exists($user, 'setPassword')) {

            $user->setPassword($newHash);
        }
    }
}
