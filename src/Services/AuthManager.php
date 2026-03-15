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
    Exceptions\Auth\InvalidCurrentPasswordException,
    Exceptions\Auth\UserNotFoundException,
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
     * Validate a user's credentials without performing a login.
     *
     * This method performs a read-only credential check using the configured
     * CredentialsRepositoryInterface and PasswordHasherInterface. It does NOT
     * establish any authentication state (no session/remember-me), and it does
     * NOT run the activation checkpoint. These responsibilities remain in
     * authenticate().
     *
     * Flow:
     * 1) Optional throttle pre-check on IP scope (no user identity yet).
     * 2) Resolve the user by email using the credentials repository.
     * 3) Verify the provided password using the configured hasher.
     * 4) Optional transparent password rehash on success (if supported by the repository).
     * 5) Throttle accounting:
     *    - Unknown user → hit IP scope.
     *    - Invalid password → hit IP and user scopes.
     *    - Success → clear IP and user scopes.
     *
     * Return semantics:
     * - Returns TRUE when the email exists and the password matches.
     * - Returns FALSE otherwise.
     *
     * Side effects:
     * - May perform throttle hits/clear as described above.
     * - May rehash and persist the password when the repository supports it and
     *   the hasher indicates that rehash is needed.
     *
     * @param string $email
     *        The login identifier. In the Eloquent adapter this is strictly the user's email address.
     * @param string $password
     *        The plaintext password provided by the caller.
     * @param UserInterface|null $authenticatedUser
     *        Output parameter. On success, this will be set to the resolved user instance.
     *        On failure, it will remain NULL.
     *
     * @return bool
     *         TRUE if the provided credentials are valid; otherwise FALSE.
     */
    public function validateCredentials(string $email, string $password,?UserInterface &$authenticatedUser = null): bool {

        $authenticatedUser = null;

        // Resolve caller IP address in a defensive way
        $ipAddress = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // (1) Throttle pre-check (IP-only; no user identity known yet)
        // Mirror the pattern already used in authenticate()
        foreach ($this->orderedCheckpoints as $checkpoint) {

            if ($checkpoint instanceof \Element\Sentinel\Services\Security\ThrottleCheckpoint) {

                $checkpoint->check(null, $ipAddress);
            }
        }

        // (2) Attempt to locate the user by email via the credentials repository
        $user = $this->credentialsRepository->find($email);

        if (!$user instanceof UserInterface) {

            // Unknown identity → throttle hit at IP scope and return false
            $this->throttleCheckpoint->hit(null, $ipAddress);

            if ($this->logger) {

                $this->logger->info('Credential validation failed: user not found', [

                    'email'      => $email,
                    'ip_address' => $ipAddress,
                ]);
            }

            return false;
        }

        // (3) Verify the password using the configured hasher.
        // Prefer a descriptive method name if available; fall back to the generic one.
        $isPasswordValid = false;
        if (method_exists($this->credentialsRepository, 'verifyPassword')) {

            // Signature: verifyPassword(UserInterface $user, string $plainPassword, PasswordHasherInterface $hasher): bool
            $isPasswordValid = (bool) $this->credentialsRepository->verifyPassword($user, $password, $this->passwordHasher);

        } elseif (method_exists($this->credentialsRepository, 'verify')) {

            // Signature: verify(UserInterface $user, string $plainPassword, PasswordHasherInterface $hasher): bool
            $isPasswordValid = (bool) $this->credentialsRepository->verify($user, $password, $this->passwordHasher);

        } else {

            // Repository does not expose a verification API — treat as invalid for safety.
            if ($this->logger) {

                $this->logger->warning('Credentials repository does not implement a known verify method.');
            }

            // Count the attempt to user + IP scopes since we did resolve a user
            $this->throttleCheckpoint->hit((string) $user->getId(), $ipAddress);

            return false;
        }

        if (!$isPasswordValid) {

            // Wrong password → throttle hit for both IP and user
            $this->throttleCheckpoint->hit((string) $user->getId(), $ipAddress);

            if ($this->logger) {

                $this->logger->info('Credential validation failed: invalid password', [

                    'user_id'    => $user->getId(),
                    'email'      => $email,
                    'ip_address' => $ipAddress,
                ]);
            }

            return false;
        }

        // (4) Optional: transparent rehash on success if the repository supports it.
        // We only attempt this when a getter is available, to avoid coupling.
        try {

            $storedPasswordHash = null;

            if (method_exists($this->credentialsRepository, 'getPasswordHash')) {

                $storedPasswordHash = (string) $this->credentialsRepository->getPasswordHash($user);
            }

            if (is_string($storedPasswordHash) && $storedPasswordHash !== '' && method_exists($this->passwordHasher, 'needsRehash') && $this->passwordHasher->needsRehash($storedPasswordHash) && method_exists($this->credentialsRepository, 'updatePassword')) {

                $newPasswordHash = (string) $this->passwordHasher->hash($password);
                $this->credentialsRepository->updatePassword($user, $newPasswordHash);

                // Persist immediately when the user is an Eloquent model
                if ($user instanceof \Illuminate\Database\Eloquent\Model) {

                    $user->save();
                }

                if ($this->logger) {

                    $this->logger->info('Password hash transparently rehashed during validation', [

                        'user_id' => $user->getId(),
                    ]);
                }
            }

        } catch (\Throwable $rehashError) {

            // Never fail the credential validation due to rehash issues; log for diagnostics only.
            if ($this->logger) {

                $this->logger->warning('Password rehash failed during credential validation', [

                    'user_id' => $user->getId(),
                    'error'   => $rehashError->getMessage(),
                ]);
            }
        }

        // (5) Success → clear throttle counters and output the resolved user
        $this->throttleCheckpoint->clear((string) $user->getId(), $ipAddress);
        $authenticatedUser = $user;

        if ($this->logger) {

            $this->logger->info('Credential validation succeeded', [

                'user_id'    => $user->getId(),
                'email'      => $email,
                'ip_address' => $ipAddress,
            ]);
        }

        return true;
    }

    /**
     * Update a user's password.
     *
     * Behavior:
     * - Resolves the user by identifier using the configured UserRepositoryInterface.
     * - When $verifyCurrent is TRUE, the provided $currentPassword must match the
     *   existing password for the user; otherwise the update fails and returns FALSE.
     * - On success (or when verification is not requested), the new password is hashed
     *   and persisted through the CredentialsRepositoryInterface. This method will also
     *   call $user->save() for Eloquent-backed user instances as an additional safety net.
     *
     * Security:
     * - This method never logs plaintext passwords.
     *
     * @param mixed  $id                The user identifier (typically the primary key).
     * @param string $newPassword       The new plaintext password (will be hashed).
     * @param bool   $verifyCurrent     If TRUE, validate $currentPassword before update.
     * @param string $currentPassword   The current plaintext password for verification.
     *
     * @return bool TRUE on success; FALSE when the user is not found or verification fails.
     *
     * @throws \RuntimeException When the credentials repository lacks required methods.
     */
    public function updatePassword($id, string $newPassword, bool $verifyCurrent = false, string $currentPassword = ''): bool {

        // Resolve context (useful for audit)
        $ipAddress = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // 1) Resolve the user
        $userIdentifier = (int) $id;
        $user = $this->userRepository->findById($userIdentifier);

        if (!$user instanceof \Element\Sentinel\Contracts\UserInterface) {

            if ($this->logger) {

                $this->logger->info('Password update failed: user not found', [

                    'user_identifier' => $id,
                    'ip_address'      => $ipAddress,
                ]);
            }

            throw new UserNotFoundException('User not found from the provided id.');
        }

        // 2) Optional verification of the current password
        if ($verifyCurrent === true) {

            $isValid = false;

            if (method_exists($this->credentialsRepository, 'verifyPassword')) {

                $isValid = (bool) $this->credentialsRepository->verifyPassword($user, $currentPassword, $this->passwordHasher);

            } elseif (method_exists($this->credentialsRepository, 'verify')) {

                $isValid = (bool) $this->credentialsRepository->verify($user, $currentPassword, $this->passwordHasher);

            } else {

                throw new \RuntimeException('Credentials repository lacks a verify method (verifyPassword or verify).');
            }

            if ($isValid !== true) {

                if ($this->logger) {

                    $this->logger->info('Password update failed: current password mismatch', [

                        'user_id'    => $user->getId(),
                        'ip_address' => $ipAddress,
                    ]);
                }

                throw new InvalidCurrentPasswordException('The provided current password does not match the user\'s existing password.');
            }
        }

        // 3) Ensure the repository can apply the update
        if (!method_exists($this->credentialsRepository, 'updatePassword')) {

            throw new \RuntimeException('Credentials repository lacks method: updatePassword().');
        }

        // 4) Hash and delegate to the repository
        $newHash = (string) $this->passwordHasher->hash($newPassword);

        if ($this->logger) {

            $this->logger->info('About to update password', [

                'user_id'    => $user->getId(),
                'ip_address' => $ipAddress,
            ]);
        }

        // The repository assigns the hash and (per Solution B) persists to the database.
        $this->credentialsRepository->updatePassword($user, $newHash);

        // 5) EXTRA SAFETY: persist again when the user is an Eloquent model
        if ($user instanceof \Illuminate\Database\Eloquent\Model) {

            // Optional: log dirty set after assignment (diagnostic)
            if ($this->logger) {

                $this->logger->info('Dirty before save (post-repo)', ['dirty' => $user->getDirty()]);
            }

            $savedOk = $user->save();

            if ($this->logger) {

                $this->logger->info('Password saved to database (AuthManager safety save)', [

                    'user_id' => $user->getId(),
                    'ok'      => (bool) $savedOk,
                ]);
            }
        }

        if ($this->logger) {

            $this->logger->info('Password updated successfully', [

                'user_id'    => $user->getId(),
                'ip_address' => $ipAddress,
            ]);
        }

        return true;
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
