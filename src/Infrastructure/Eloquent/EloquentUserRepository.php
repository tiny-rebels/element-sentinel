<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    UserInterface,
    UserRepositoryInterface
};

/**
 * Eloquent repository implementation for User records.
 */
class EloquentUserRepository implements UserRepositoryInterface {

    /**
     * @param int|string $userId
     *
     * @return UserInterface|null
     */
    public function findById($userId){

        return EloquentUser::query()->find($userId);
    }

    /**
     * @param UserInterface $userObject
     *
     * @return void
     */
    public function save(UserInterface $userObject) {

        if (!($userObject instanceof EloquentUser)) {

            $this->updateNonEloquentUser($userObject);

            return;
        }

        $userObject->save();
    }

    /**
     * Allows saving activation flag on non‑eloquent User models.
     *
     * @param UserInterface $userObject
     *
     * @return void
     */
    private function updateNonEloquentUser(UserInterface $userObject) {

        EloquentUser::query()
            ->where('id', $userObject->getId())
            ->update([
                'activated'   => $userObject->isActivated() ? 1 : 0,
                'updated_at'  => date('Y-m-d H:i:s'),
            ]);
    }
}