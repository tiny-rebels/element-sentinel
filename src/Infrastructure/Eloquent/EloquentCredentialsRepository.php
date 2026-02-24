<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    CredentialsRepositoryInterface,
    UserInterface
};

use Illuminate\Database\Eloquent\Model;

/**
 * EloquentCredentialsRepository
 *
 * Eloquent adapter for login lookup (email-only in your design) + password hash access.
 * Pluggable user model class and optional eager relations (fail-safe).
 */
class EloquentCredentialsRepository implements CredentialsRepositoryInterface {

    /** @var class-string<Model&UserInterface> */
    private $userModelClass;

    /** @var string[] */
    private $eagerRelations;

    /**
     * @param string   $userModelClass FQCN of your Eloquent user model (implements UserInterface)
     *
     * @param string[] $eagerRelations Optional list of relation names to eager-load
     */
    public function __construct(string $userModelClass, array $eagerRelations = []) {

        $this->userModelClass = $userModelClass;
        $this->eagerRelations = $eagerRelations;
    }

    /**
     * Find user strictly by email address.
     *
     * @param string $login  Email value (library is email-only by design)
     *
     * @return UserInterface|null
     */
    public function findByLogin($login): ?UserInterface {

        /** @var Model $model */
        $model = new $this->userModelClass();

        $query = $model->newQuery();


        $exists = $model->newQuery()->where('email', '=', $login)->exists();
        error_log(sprintf(
            '[Sentinel DIAG] model=%s table=%s email=%s exists=%s',
            get_class($model),
            $model->getTable(),
            $login,
            $exists ? '1' : '0'
        ));


        $safeRelations = $this->filterExistingRelations($model, $this->eagerRelations);

        if (!empty($safeRelations)) {

            $query->with($safeRelations);
        }

        $foundUser = $query->where('email', $login)->first();

        return ($foundUser instanceof UserInterface) ? $foundUser : null;
    }

    /**
     * Return the stored password hash for the given user.
     *
     * @param UserInterface $user
     *
     * @return string
     */
    public function getPasswordHash(UserInterface $user): string {

        if (is_object($user)) {

            if (property_exists($user, 'password')) {

                return (string) $user->password;
            }

            if (method_exists($user, 'getPassword')) {

                return (string) $user->getPassword();
            }
        }

        return '';
    }

    /**
     * Update (rehash) the stored password for the given user.
     *
     * @param UserInterface $user
     *
     * @param string        $newHash
     *
     * @return void
     */
    public function updatePassword(UserInterface $user, $newHash): void {

        if (is_object($user)) {

            if (property_exists($user, 'password')) {

                $user->password = $newHash;

            } elseif (method_exists($user, 'setPassword')) {

                $user->setPassword($newHash);
            }
        }
        // Persisting is handled by the caller via UserRepository::save()
    }

    /**
     * Return only relations that actually exist as methods on the model.
     *
     * @param Model    $modelInstance
     * @param string[] $candidateRelations
     *
     * @return string[]
     */
    private function filterExistingRelations(Model $modelInstance, array $candidateRelations): array {

        if (empty($candidateRelations)) {

            return [];
        }

        $valid = [];

        foreach ($candidateRelations as $relationName) {

            if (!is_string($relationName) || $relationName === '') {

                continue;
            }

            if (method_exists($modelInstance, $relationName)) {

                $valid[] = $relationName;
            }
        }

        return array_values(array_unique($valid));
    }
}
