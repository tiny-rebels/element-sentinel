<?php

namespace Element\Sentinel\Services;

use Element\Sentinel\Contracts\{
    CredentialsRepositoryInterface,
    PasswordHasherInterface,
    UserInterface,
    UserRepositoryInterface
};

use Element\Sentinel\Infrastructure\Eloquent\EloquentPersistenceRepository;

use Element\Sentinel\Services\{
    Security\ThrottleCheckpoint,
    Security\ActivationCheckpoint
};

/**
 * AuthManager
 *
 * Handles user authentication lifecycle:
 *  - Throttle checkpoint (pre-attempt)
 *  - Credentials verification
 *  - Activation checkpoint (post-identity, pre-login)
 *  - Optional activation lottery cleanup
 *  - Session / remember-me persistence on success
 */
final class AuthManager {

    /** @var UserRepositoryInterface */
    private $userRepository;

    /** @var object */
    private $activationsRepository;

    /** @var PasswordHasherInterface */
    private $passwordHasher;

    /** @var CredentialsRepositoryInterface */
    private $credentialsRepository;

    /** @var EloquentPersistenceRepository */
    private $persistencesRepository;

    /** @var \Psr\Log\LoggerInterface|null */
    private $logger;

    /**
     * Ordered checkpoints evaluated during authenticate():
     *   - ThrottleCheckpoint (pre-attempt)
     *   - ActivationCheckpoint (post-identity)
     *
     * @var array<int,object>
     */
    private $orderedCheckpoints = [];

    /** @var ThrottleCheckpoint */
    private $throttleCheckpoint;

    /** @var ActivationCheckpoint */
    private $activationCheckpoint;

    /**
     * Activation policy value-object providing:
     *  - expirationSeconds(): int
     *  - shouldRunLottery(): bool
     *
     * @var object|null
     */
    private $activationPolicy;

    /**
     * @param UserRepositoryInterface          $userRepository
     * @param object $activationsRepository
     * @param PasswordHasherInterface          $passwordHasher
     * @param CredentialsRepositoryInterface   $credentialsRepository
     * @param EloquentPersistenceRepository    $persistencesRepository
     * @param \Psr\Log\LoggerInterface|null    $logger
     */
    public function __construct(
        UserRepositoryInterface        $userRepository,
        object                         $activationsRepository,
        PasswordHasherInterface        $passwordHasher,
        CredentialsRepositoryInterface $credentialsRepository,
        EloquentPersistenceRepository  $persistencesRepository,
        ?\Psr\Log\LoggerInterface      $logger = null
    ) {
        $this->userRepository         = $userRepository;
        $this->activationsRepository  = $activationsRepository;
        $this->passwordHasher         = $passwordHasher;
        $this->credentialsRepository  = $credentialsRepository;
        $this->persistencesRepository = $persistencesRepository;
        $this->logger                 = $logger;
    }

    /**
     * Inject security components and policy (wired by NormalizeConfig).
     *
     * @param array<int,object>   $orderedCheckpoints
     * @param ThrottleCheckpoint  $throttleCheckpoint
     * @param ActivationCheckpoint $activationCheckpoint
     * @param object|null $activationPolicy
     *
     * @return void
     */
    public function configureSecurity(
        array $orderedCheckpoints,
        ThrottleCheckpoint $throttleCheckpoint,
        ActivationCheckpoint $activationCheckpoint,
        object $activationPolicy = null
    ): void {
        $this->orderedCheckpoints   = $orderedCheckpoints;
        $this->throttleCheckpoint   = $throttleCheckpoint;
        $this->activationCheckpoint = $activationCheckpoint;
        $this->activationPolicy     = $activationPolicy;
    }

    /**
     * Return the currently authenticated user or null.
     *
     * NOTE:
     *  - Runtime eager-loading via $withRelations is only honored by the repository
     *    when the configured user model is the standard EloquentUser.
     *  - For local application models, a non-empty $withRelations should cause the repository
     *    to throw (by design).
     *
     * @param string[] $withRelations
     *
     * @return UserInterface|null
     */
    public function check(array $withRelations = []): ?UserInterface {

        return $this->userRepository->check($withRelations);
    }

    /**
     * Authenticate a user by login identifier and password.
     *
     * Flow:
     *  1) Throttle pre-check (no user id known yet)
     *  2) Find user by email
     *  3) Verify password (using configured PasswordHasherInterface)
     *  4) Activation checkpoint (user must be activated)
     *  5) Optional activation lottery cleanup
     *  6) Clear throttle on success
     *  7) Persist session and optional remember-me
     *
     * @param string $email
     * @param string $password
     * @param bool   $remember
     *
     * @return UserInterface
     *
     * @throws \RuntimeException|\Throwable
     */
    public function authenticate(string $email, string $password, bool $remember = false): UserInterface {

        $ipAddress = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // 1) Throttle pre-check
        foreach ($this->orderedCheckpoints as $checkpoint) {

            if ($checkpoint instanceof ThrottleCheckpoint) {

                $checkpoint->check(null, $ipAddress);
            }
        }

        try {

            // 2) Identify user by login identifier
            $user = $this->credentialsRepository->find($email);

            if (!$user instanceof UserInterface) {

                // Unknown identity → count attempt on IP level
                $this->throttleCheckpoint->hit(null, $ipAddress);

                throw new \RuntimeException('User not found for given credentials.');
            }

            // 3) Verify password
            if (!$this->credentialsRepository->verify($user, $password, $this->passwordHasher)) {

                // Wrong password → throttle hit for both ip and user
                $this->throttleCheckpoint->hit((string) $user->getId(), $ipAddress);

                throw new \RuntimeException('Invalid password.');
            }

            // 4) Activation checkpoint (user must be activated)
            foreach ($this->orderedCheckpoints as $checkpoint) {

                if ($checkpoint instanceof ActivationCheckpoint) {

                    $checkpoint->check($user);
                }
            }

            // 5) Activation lottery cleanup (optional)
            if ($this->activationPolicy && method_exists($this->activationPolicy, 'shouldRunLottery') && $this->activationPolicy->shouldRunLottery()) {

                try {

                    $expirationSeconds = method_exists($this->activationPolicy, 'expirationSeconds') ? (int) $this->activationPolicy->expirationSeconds() : 0;

                    if ($expirationSeconds > 0 && method_exists($this->activationsRepository, 'removeExpired')) {

                        $this->activationsRepository->removeExpired($expirationSeconds);
                    }

                } catch (\Throwable $cleanupError) {

                    if ($this->logger) {

                        $this->logger->warning('Activation lottery cleanup failed', [

                            'error' => $cleanupError->getMessage(),
                        ]);
                    }
                }
            }

            // 6) Clear throttle counters on success (ip + user)
            $this->throttleCheckpoint->clear((string) $user->getId(), $ipAddress);

            // 7) Finalize login (session + remember-me)
            $this->finalizeLogin($user, $remember);

            if ($this->logger) {

                $this->logger->info('User authenticated', [

                    'user_id'  => $user->getId(),
                    'remember' => $remember,
                ]);
            }

            return $user;

        } catch (\Throwable $error) {

            // If user was not identified, ensure we at least hit the IP throttle
            if (!isset($user) || !$user instanceof UserInterface) {

                $this->throttleCheckpoint->hit(null, $ipAddress);
            }

            throw $error;
        }
    }

    /**
     * Logout the currently authenticated user.
     *
     * @return void
     */
    public function logout(): void {

        if (session_status() !== PHP_SESSION_ACTIVE) {

            session_start();
        }

        // Remove user id from session
        if (isset($_SESSION['sentinel_user_id'])) {

            unset($_SESSION['sentinel_user_id']);
        }

        // Forget remember-me cookie
        if ($this->persistencesRepository) {

            try {

                $this->persistencesRepository->forget();

            } catch (\Throwable $error) {

                if ($this->logger) {

                    $this->logger->warning('Failed to clear remember-me cookie', [

                        'error' => $error->getMessage(),
                    ]);
                }
            }
        }

        // Regenerate session id to prevent fixation
        session_regenerate_id(true);

        if ($this->logger) {

            $this->logger->info('User logged out');
        }
    }

    /**
     * Finalize login by updating session and remember-me persistence.
     *
     * @param UserInterface $user
     * @param bool          $remember
     *
     * @return void
     */
    private function finalizeLogin(UserInterface $user, bool $remember): void {

        if (session_status() !== PHP_SESSION_ACTIVE) {

            session_start();
        }

        // Prevent session fixation
        session_regenerate_id(true);

        // Store current user id
        $_SESSION['sentinel_user_id'] = $user->getId();

        // Optional remember-me cookie
        if ($remember) {

            $this->persistencesRepository->remember((string) $user->getId());
        }
    }
}
