<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\{
    ActivationInterface,
    ActivationRepositoryInterface,
    UserInterface
};

use Element\Sentinel\Support\CodeGenerator;

class EloquentActivationRepository implements ActivationRepositoryInterface {

    /**
     * @param UserInterface $userObject
     *
     * @return ActivationInterface
     *
     * @throws \Exception
     */
    public function create(UserInterface $userObject): ActivationInterface {

        try {

            $activationCode = CodeGenerator::random(32); // or 64

        } catch (\Exception $exception) {

            // random_bytes kan kaste en generisk Exception i PHP 7.x
            throw $exception; // eller håndter som du ønsker
        }

        return EloquentActivation::create([

            'user_id'     => $userObject->getId(),
            'code'        => $activationCode,
            'completed_at'=> null
        ]);
    }

    /**
     * @param UserInterface $userObject
     *
     * @return bool
     */
    public function exists(UserInterface $userObject): bool {

        return EloquentActivation::query()->where('user_id', '=', $userObject->getId())->whereNull('completed_at')->exists();
    }

    /**
     * @param UserInterface $userObject
     *
     * @return ActivationInterface|null
     */
    public function findOpenByUser(UserInterface $userObject): ?ActivationInterface {

        return EloquentActivation::query()->where('user_id', '=', $userObject->getId())->whereNull('completed_at')->orderByDesc('created_at')->first();
    }

    /**
     * @param string $code
     *
     * @return ActivationInterface|null
     */
    public function findByCode(string $code): ?ActivationInterface {

        return EloquentActivation::query()->where('code', '=', $code)->first();
    }

    /**
     * @param UserInterface $user
     * @param string $code
     *
     * @return bool
     */
    public function complete(UserInterface $user, string $code): bool {

        $activationRecord = EloquentActivation::query()->where('user_id', '=', $user->getId())->where('code', '=', $code)->whereNull('completed_at')->first();

        if (!$activationRecord) {

            return false;
        }

        $activationRecord->completed    = 1;
        $activationRecord->completed_at = date('Y-m-d H:i:s');

        $activationRecord->save();

        $user->markActivated();

        if ($user instanceof EloquentUser) {

            $user->save();
        }

        return true;
    }
}
