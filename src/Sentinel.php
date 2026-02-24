<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\{ActivationRepositoryInterface,
    CredentialsRepositoryInterface,
    PasswordHasherInterface,
    PermissionRepositoryInterface,
    PersistenceRepositoryInterface,
    RoleRepositoryInterface,
    UserInterface,
    UserRepositoryInterface,
    AuthManagerInterface};

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

    /** @var ActivationRepositoryInterface */
    private $activationRepository;

    /** @var CredentialsRepositoryInterface */
    private $credentialsRepository;

    /** @var PermissionRepositoryInterface */
    private $permissionRepository;

    /** @var PersistenceRepositoryInterface */
    private $persistenceRepository;

    /** @var RoleRepositoryInterface */
    private $roleRepository;

    /** @var UserRepositoryInterface */
    private $userRepository;



    /** @var PasswordHasherInterface */
    private $passwordHasher;

    /** @var LoggerInterface|null */
    private $logger;

    /** @var AuthManagerInterface|null */
    private $authManager;

    /** @var self|null */
    private static $instance = null;

    /**
     * Construct a Sentinel facade instance with concrete dependencies.
     *
     * @param ActivationRepositoryInterface     $activationRepository
     *
     * @param CredentialsRepositoryInterface    $credentialsRepository
     *
     * @param PermissionRepositoryInterface     $permissionRepository
     *
     * @param PersistenceRepositoryInterface    $persistenceRepository
     *
     * @param RoleRepositoryInterface           $roleRepository
     *
     * @param UserRepositoryInterface           $userRepository
     *
     * @param PasswordHasherInterface           $passwordHasher
     *
     * @param LoggerInterface                   $logger
     */
    public function __construct(

        ActivationRepositoryInterface $activationRepository,
        CredentialsRepositoryInterface $credentialsRepository,
        PermissionRepositoryInterface $permissionRepository,
        PersistenceRepositoryInterface $persistenceRepository,
        RoleRepositoryInterface $roleRepository,
        UserRepositoryInterface $userRepository,
        PasswordHasherInterface $passwordHasher,
        LoggerInterface $logger) {

        $this->activationRepository     = $activationRepository;
        $this->credentialsRepository    = $credentialsRepository;
        $this->permissionRepository     = $permissionRepository;
        $this->persistenceRepository    = $persistenceRepository;
        $this->roleRepository           = $roleRepository;
        $this->userRepository           = $userRepository;
        $this->passwordHasher           = $passwordHasher;
        $this->logger                   = $logger;
        $this->authManager              = null; // bound during deploy()
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

        $activationRepository  = $canonical['repositories']['activations'];
        $credentialsRepository = $canonical['repositories']['credentials'];
        $permissionRepository  = $canonical['repositories']['permissions'];
        $persistenceRepository = $canonical['repositories']['persistences'];
        $roleRepository        = $canonical['repositories']['roles'];
        $userRepository        = $canonical['repositories']['users'];
        $passwordHasher        = $canonical['hasher'];
        $loggerInstance        = $canonical['logger'] ?? null;

        $instance = new self(
            $activationRepository,
            $credentialsRepository,
            $permissionRepository,
            $persistenceRepository,
            $roleRepository,
            $userRepository,
            $passwordHasher,
            $loggerInstance
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
     * Repository shortcut: activations().
     *
     * @return ActivationRepositoryInterface
     */
    public static function activations(): ActivationRepositoryInterface {

        return self::instance()->activationRepository;
    }

    /**
     * Repository shortcut: permissions().
     *
     * @return PermissionRepositoryInterface
     */
    public static function permissions(): PermissionRepositoryInterface {

        return self::instance()->permissionRepository;
    }

    /**
     * Repository shortcut: roles().
     *
     * @return RoleRepositoryInterface
     */
    public static function roles(): RoleRepositoryInterface {

        return self::instance()->roleRepository;
    }

    /**
     * Repository shortcut: users().
     *
     * @return UserRepositoryInterface
     */
    public static function user(): UserRepositoryInterface {

        return self::instance()->userRepository;
    }

    public static function users(): UserRepositoryInterface {

        return self::instance()->userRepository;
    }

    public static function auth(): UserRepositoryInterface {

        return self::instance()->userRepository;
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
     * @param array $withRelations
     *
     * @return UserInterface|null
     */
    public static function check(array $withRelations = []): ?UserInterface {

        return self::instance()->userRepository->check($withRelations);
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
