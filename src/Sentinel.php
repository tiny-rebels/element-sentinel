<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    CredentialsRepositoryInterface,
    PasswordHasherInterface,
    PersistenceRepositoryInterface,
    UserInterface,
    UserRepositoryInterface,
    AuthManagerInterface
};

use Element\Sentinel\Support\NormalizeConfig;

use Psr\Log\LoggerInterface;

/**
 * Sentinel (Facade)
 *
 * Framework-agnostic static facade that exposes:
 * - deploy(array $config): build the global instance from normalized config
 * - repository shortcuts: users(), activations(), hasher()
 * - authentication shortcuts: authenticate(), logout()
 *
 * All business logic lives in Services\AuthManager.
 */
final class Sentinel {

    /** @var UserRepositoryInterface */
    private $userRepository;

    /** @var ActivationRepositoryInterface */
    private $activationRepository;

    /** @var PasswordHasherInterface */
    private $passwordHasher;

    /** @var LoggerInterface|null */
    private $logger;

    /** @var CredentialsRepositoryInterface|null */
    private $credentialsRepository;

    /** @var PersistenceRepositoryInterface|null */
    private $persistenceRepository;

    /** @var AuthManagerInterface|null */
    private $authManager;

    /** @var self|null */
    private static $instance = null;

    /**
     * Construct a Sentinel facade instance with concrete dependencies.
     *
     * @param UserRepositoryInterface             $userRepository
     *
     * @param ActivationRepositoryInterface       $activationRepository
     *
     * @param PasswordHasherInterface             $passwordHasher
     *
     * @param LoggerInterface|null                $logger
     *
     * @param CredentialsRepositoryInterface|null $credentialsRepository
     *
     * @param PersistenceRepositoryInterface|null $persistenceRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ActivationRepositoryInterface $activationRepository,
        PasswordHasherInterface $passwordHasher,
        LoggerInterface $logger = null,
        CredentialsRepositoryInterface $credentialsRepository = null,
        PersistenceRepositoryInterface $persistenceRepository = null
    ) {
        $this->userRepository        = $userRepository;
        $this->activationRepository  = $activationRepository;
        $this->passwordHasher        = $passwordHasher;
        $this->logger                = $logger;
        $this->credentialsRepository = $credentialsRepository;
        $this->persistenceRepository = $persistenceRepository;
        $this->authManager           = null; // bound during deploy()
    }

    /**
     * Deploy Sentinel from a (possibly symbolic/file-backed) array config.
     * Uses Support\NormalizeConfig to produce canonical instances + services.
     *
     * @param array $config
     *
     * @return self
     */
    public static function deploy(array $config): self {

        $canonical = NormalizeConfig::normalize($config);

        $userRepository        = $canonical['repositories']['users'];
        $activationRepository  = $canonical['repositories']['activations'];
        $credentialsRepository = $canonical['repositories']['credentials'];
        $persistenceRepository = $canonical['repositories']['persistences'];
        $passwordHasher        = $canonical['hasher'];
        $loggerInstance        = $canonical['logger'] ?? null;

        $instance = new self(
            $userRepository,
            $activationRepository,
            $passwordHasher,
            $loggerInstance,
            $credentialsRepository,
            $persistenceRepository
        );

        // Bind the AuthManager service built by NormalizeConfig
        $instance->authManager = $canonical['services']['auth'] ?? null;

        self::$instance = $instance;

        return $instance;
    }

    /**
     * Get the global Sentinel instance set by deploy().
     *
     * @return self
     *
     * @throws \RuntimeException
     */
    public static function instance(): self {

        if (!self::$instance) {

            throw new \RuntimeException('Sentinel::deploy() has not been called yet.');
        }

        return self::$instance;
    }

    /**
     * Repository shortcut: users().
     *
     * @return UserRepositoryInterface
     */
    public static function users(): UserRepositoryInterface {

        return self::instance()->userRepository;
    }

    /**
     * Repository shortcut: activations().
     *
     * @return ActivationRepositoryInterface
     */
    public static function activations(): ActivationRepositoryInterface {

        return self::instance()->activationRepository;
    }

    /**
     * Shortcut: hasher() → password hasher instance.
     *
     * @return PasswordHasherInterface
     */
    public static function hasher(): PasswordHasherInterface {

        return self::instance()->passwordHasher;
    }

    /**
     * Optional access to configured logger.
     *
     * @return LoggerInterface|null
     */
    public function logger(): ?LoggerInterface {

        return $this->logger;
    }

    /**
     * Sentinel::check() returns the authenticated user or null.
     *
     * @return UserInterface|null
     */
    public static function check(): ?UserInterface {

        return self::instance()->userRepository->check();
    }

    /**
     * Authenticate via the AuthManager service (static convenience).
     *
     * Expected input:
     * [
     *   'email'    => 'user@example.com',
     *   'password' => 'PlainTextOrInput',
     * ]
     *
     * @param array{email:string,password:string} $credentials
     *
     * @param bool $remember         If true, create a remember-me token and cookie.
     *
     * @param bool $requireActivated If true, the user must be activated.
     *
     * @return UserInterface|null
     */
    public static function authenticate(array $credentials, bool $remember = false, bool $requireActivated = true): ?UserInterface {

        $core = self::instance();

        if (!$core->authManager) {

            throw new \RuntimeException('AuthManager service not available. Check NormalizeConfig/deploy wiring.');
        }

        return $core->authManager->authenticate($credentials, $remember, $requireActivated);
    }

    /**
     * Determine if the current visitor is a guest (not authenticated).
     *
     * This is a static convenience wrapper calling into the UserRepository's check()
     * which itself handles both session-based and remember-me authentication.
     *
     * @return bool True if not authenticated, false otherwise.
     */
    public static function guest(): bool {

        $core = self::instance();

        // UserRepository::check() returns UserInterface|null
        $user = $core->userRepository->check();

        return $user === null;
    }

    /**
     * Logout via the AuthManager service (static convenience).
     *
     * @return void
     */
    public static function logout(): void {

        $core = self::instance();

        if (!$core->authManager) {

            throw new \RuntimeException('AuthManager service not available. Check NormalizeConfig/deploy wiring.');
        }

        $core->authManager->logout();
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
