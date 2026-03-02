<?php

namespace Element\Sentinel\Services\Security;

use Element\Sentinel\Contracts\UserInterface;

use Element\Sentinel\Services\Exceptions\Auth\UserNotActivatedException;

/**
 * ActivationCheckpoint
 *
 * Ensures that the user is activated before granting access.
 * Should be called in the authentication flow after the user entity
 * has been identified (credentials matched) but before session/persistences are finalized.
 */
final class ActivationCheckpoint {

    /** @var bool */
    private $enabled;

    /**
     * @param bool $enabled  Allow disabling during QA or specific flows.
     */
    public function __construct(bool $enabled = true) {

        $this->enabled = $enabled;
    }

    /**
     * Throws if the given user is not activated.
     *
     * @param UserInterface $user
     *
     * @return void
     */
    public function check(UserInterface $user): void {

        if (!$this->enabled) {

            return;
        }

        // Your UserInterface exposes isActivated(); you already use it in repos/services.
        if (method_exists($user, 'isActivated') && !$user->isActivated()) {

            throw new UserNotActivatedException('Account is not activated.', 1403, null, [

                'user_id' => $user->getId(),
            ]);
        }
    }
}
