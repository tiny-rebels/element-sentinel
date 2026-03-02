<?php

namespace Element\Sentinel\Services;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    PersistenceRepositoryInterface,
    UserRepositoryInterface
};

use Psr\Log\LoggerInterface;

/**
 * ActivationManager
 *
 * Encapsulates the user activation workflow behind a small, expressive API.
 * This service coordinates between the user repository and the activation
 * repository in order to check, complete and resend activations.
 *
 * Responsibilities:
 * - activationExists($id): bool
 * - activateUser($id): bool
 * - resendActivation($id): bool
 *
 * Notes:
 * - This manager is framework-agnostic and expects repository interfaces
 *   to provide the required methods. It throws clear RuntimeExceptions when
 *   required capabilities are missing.
 */
final class ActivationManager {

    /** @var UserRepositoryInterface */
    private $userRepository;

    /** @var ActivationRepositoryInterface */
    private $activationRepository;

    /** @var PersistenceRepositoryInterface|null */
    private $persistenceRepository;

    /** @var LoggerInterface|null */
    private $logger;

    /**
     * @param UserRepositoryInterface $userRepository
     * @param ActivationRepositoryInterface $activationRepository
     * @param PersistenceRepositoryInterface|null $persistenceRepository
     * @param LoggerInterface|null $logger
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ActivationRepositoryInterface $activationRepository,
        PersistenceRepositoryInterface $persistenceRepository = null,
        LoggerInterface $logger = null
    ) {
        $this->userRepository        = $userRepository;
        $this->activationRepository  = $activationRepository;
        $this->persistenceRepository = $persistenceRepository;
        $this->logger                = $logger;
    }

    /**
     * Determine whether a pending activation exists for the given user identifier.
     *
     * @param mixed $id The user identifier (typically the primary key).
     *
     * @return bool TRUE when a pending activation exists; otherwise FALSE.
     *
     * @throws \RuntimeException When the activation repository lacks the exists() method.
     */
    public function activationExists($id): bool {

        if (!method_exists($this->activationRepository, 'exists')) {

            throw new \RuntimeException('Activation repository lacks required method: exists().');
        }

        $userIdentifier = (int) $id;
        $user = $this->userRepository->findById($userIdentifier);

        if ($user === null) {

            return false;
        }

        return (bool) $this->activationRepository->exists($user);
    }

    /**
     * Activate a user by completing the latest open activation record.
     *
     * Behavior:
     * - Returns TRUE if an open activation exists and completes successfully.
     * - Returns FALSE if the user cannot be resolved or no open activation exists.
     * - On success, this method establishes authentication state (session) and
     *   optionally sets a remember-me cookie when $remember === TRUE.
     *
     * Requirements on the ActivationRepository:
     * - findOpenByUser(UserInterface): ?ActivationInterface
     * - complete(UserInterface, string): bool
     *
     * @param mixed $id        The user identifier (typically the primary key).
     * @param bool $remember  When TRUE, set remember-me persistence after activation.
     *
     * @return bool TRUE if activation completed (and login state established); otherwise FALSE.
     *
     * @throws \RuntimeException When required repository methods are unavailable.
     */
    public function activateUser($id, bool $remember = false): bool {

        if (!method_exists($this->activationRepository, 'findOpenByUser')) {

            throw new \RuntimeException('Activation repository lacks required method: findOpenByUser().');
        }

        if (!method_exists($this->activationRepository, 'complete')) {

            throw new \RuntimeException('Activation repository lacks required method: complete().');
        }

        $userIdentifier = (int) $id;
        $user = $this->userRepository->findById($userIdentifier);

        if ($user === null) {

            return false;
        }

        $activation = $this->activationRepository->findOpenByUser($user);

        if ($activation === null) {

            return false;
        }

        $activationCode = isset($activation->code) ? (string) $activation->code : '';

        if ($activationCode === '') {

            if ($this->logger) {

                $this->logger->warning('Activation record has no code.', [

                    'user_id' => $user->getId(),
                ]);
            }

            return false;
        }

        $completed = (bool) $this->activationRepository->complete($user, $activationCode);

        if (!$completed) {

            return false;
        }

        // ---- Establish login state (same semantics as AuthManager::finalizeLogin) ----
        if (session_status() !== PHP_SESSION_ACTIVE) {

            session_start();
        }

        // Prevent session fixation
        session_regenerate_id(true);

        // Store current user id
        $_SESSION['sentinel_user_id'] = $user->getId();

        // Optional remember-me cookie
        if ($remember && $this->persistenceRepository) {

            try {

                $this->persistenceRepository->remember((string) $user->getId());

            } catch (\Throwable $error) {

                if ($this->logger) {

                    $this->logger->warning('Failed to set remember-me during activation login', [

                        'user_id' => $user->getId(),
                        'error'   => $error->getMessage(),
                    ]);
                }
            }
        }

        if ($this->logger) {

            $this->logger->info('User activated and logged in', [

                'user_id'  => $user->getId(),
                'remember' => (bool) $remember,
            ]);
        }

        return true;
    }

    /**
     * Resend (or recreate) an activation for the given user.
     *
     * Preferred behavior:
     * - If the activation repository provides resend(UserInterface): bool, this method calls it.
     *
     * Fallback behavior:
     * - If resend() is not available but create(UserInterface) exists, this method attempts to
     *   create (or recreate) a new activation entry and returns TRUE upon success.
     *   Note: The repository or caller is expected to handle the actual notification delivery.
     *
     * @param mixed $id The user identifier (typically the primary key).
     *
     * @return bool TRUE if a resend or recreation succeeded; otherwise FALSE.
     *
     * @throws \RuntimeException When neither resend() nor create() is supported.
     */
    public function resendActivation($id): bool {

        $userIdentifier = (int) $id;
        $user = $this->userRepository->findById($userIdentifier);

        if ($user === null) {

            return false;
        }

        if (method_exists($this->activationRepository, 'resend')) {

            return (bool) $this->activationRepository->resend($user);
        }

        if (method_exists($this->activationRepository, 'create')) {

            $created = $this->activationRepository->create($user);

            return $created ? true : false;
        }

        throw new \RuntimeException(
            'Activation repository supports neither resend($user) nor create($user).'
        );
    }
}
