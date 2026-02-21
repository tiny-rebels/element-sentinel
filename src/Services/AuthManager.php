<?php

namespace Element\Sentinel\Services;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    AuthManagerInterface,
    CredentialsRepositoryInterface,
    PasswordHasherInterface,
    PersistenceRepositoryInterface,
    UserInterface,
    UserRepositoryInterface
};

use Psr\Log\LoggerInterface;

/**
 * AuthManager
 *
 * Authentication service that orchestrates repositories, password hasher,
 * session management and remember-me persistence in a framework-agnostic way.
 */
final class AuthManager implements AuthManagerInterface {

    /** @var UserRepositoryInterface */
    private $userRepository;

    /** @var ActivationRepositoryInterface */
    private $activationRepository;

    /** @var PasswordHasherInterface */
    private $passwordHasher;

    /** @var CredentialsRepositoryInterface */
    private $credentialsRepository;

    /** @var PersistenceRepositoryInterface|null */
    private $persistenceRepository;

    /** @var LoggerInterface|null Optional logger (not part of the interface) */
    private $logger;

    /**
     * @param UserRepositoryInterface             $userRepository
     *
     * @param ActivationRepositoryInterface       $activationRepository
     *
     * @param PasswordHasherInterface             $passwordHasher
     *
     * @param CredentialsRepositoryInterface      $credentialsRepository
     *
     * @param PersistenceRepositoryInterface|null $persistenceRepository
     *
     * @param LoggerInterface|null                $logger Optional
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ActivationRepositoryInterface $activationRepository,
        PasswordHasherInterface $passwordHasher,
        CredentialsRepositoryInterface $credentialsRepository,
        PersistenceRepositoryInterface $persistenceRepository = null,
        LoggerInterface $logger = null
    ) {
        $this->userRepository        = $userRepository;
        $this->activationRepository  = $activationRepository;
        $this->passwordHasher        = $passwordHasher;
        $this->credentialsRepository = $credentialsRepository;
        $this->persistenceRepository = $persistenceRepository;
        $this->logger                = $logger; // optional
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(array $credentials, bool $remember = false, bool $requireActivated = true): ?UserInterface {

        $emailAddress  = isset($credentials['email']) ? trim((string) $credentials['email']) : '';
        $plainPassword = isset($credentials['password']) ? (string) $credentials['password'] : '';

        if ($emailAddress === '' || $plainPassword === '') {

            $this->log('warning', 'AuthManager: missing email or password', ['email' => $emailAddress]);

            return null;
        }

        // 1) Lookup by email
        $user = $this->credentialsRepository->findByLogin($emailAddress);

        if (!$user) {

            $this->log('notice', 'AuthManager: user not found for email', ['email' => $emailAddress]);

            return null;
        }

        // 2) Activation gate
        if ($requireActivated && method_exists($user, 'isActivated') && !$user->isActivated()) {

            $this->log('notice', 'AuthManager: user not activated', ['user_id' => $user->getId()]);

            return null;
        }

        // 3) Verify password
        $storedHash = (string) $this->credentialsRepository->getPasswordHash($user);

        if ($storedHash === '' || !$this->passwordHasher->verify($plainPassword, $storedHash)) {

            $this->log('notice', 'AuthManager: invalid password', ['user_id' => $user->getId()]);

            return null;
        }

        // 4) Rehash if needed
        if ($this->passwordHasher->needsRehash($storedHash)) {

            $newHash = $this->passwordHasher->hash($plainPassword);
            $this->credentialsRepository->updatePassword($user, $newHash);
            $this->userRepository->save($user);
            $this->log('info', 'AuthManager: password rehashed on login', ['user_id' => $user->getId()]);
        }

        // 5) Session + remember-me
        if (session_status() === PHP_SESSION_ACTIVE) {

            $_SESSION['sentinel_user_id'] = $user->getId();
            session_regenerate_id(true);
        }

        if ($remember && $this->persistenceRepository) {

            try {

                $this->persistenceRepository->remember($user->getId());

            } catch (\Throwable $exception) {

                $this->log('error', 'AuthManager: remember-me failed', [

                    'user_id' => $user->getId(),
                    'err'     => $exception->getMessage(),
                ]);
            }
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function logout(): void {

        $userId = null;

        if (session_status() === PHP_SESSION_ACTIVE) {

            $userId = $_SESSION['sentinel_user_id'] ?? null;
        }

        if ($this->persistenceRepository) {

            if (!empty($userId)) {

                $this->persistenceRepository->forgetUser($userId);

            } else {

                $this->persistenceRepository->forgetCurrent();
            }
        }

        if (session_status() === PHP_SESSION_ACTIVE) {

            unset($_SESSION['sentinel_user_id']);
            session_regenerate_id(true);
        }
    }

    /**
     * Internal logger helper (no-op if no logger is configured).
     *
     * @param string $level
     *
     * @param string $message
     *
     * @param array  $context
     *
     * @return void
     */
    private function log($level, $message, array $context = []): void {

        if ($this->logger && method_exists($this->logger, $level)) {

            $this->logger->{$level}($message, $context);
        }
    }
}
