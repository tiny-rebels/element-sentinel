<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\UserRepositoryInterface;
use Element\Sentinel\Support\NormalizeConfig;

/**
 * Sentinel
 *
 * Main façade / static entrypoint for accessing the authentication system.
 * - Static facade pattern (similar to Cartalyst style).
 * - Parameterless singleton constructor (safe lazy init).
 * - Configurable via deploy() -> NormalizeConfig.
 */
final class Sentinel {

    /** @var Sentinel|null */
    private static $instance = null;

    /** @var array<string,mixed> Canonical services (auth, roles, permissions, security[...]) */
    private $services = [];

    /** @var array<string,mixed> Arbitrary repositories bag (e.g., ['users' => ..., 'credentials' => ...]) */
    private $repositories = [];

    /** @var UserRepositoryInterface|null Direct shortcut to the user repository (optional convenience) */
    protected $userRepository;

    /** @var mixed|null Optional PSR logger or any logger (injected via deploy) */
    protected $logger;

    /**
     * Prevent external instantiation.
     * Keep parameterless to allow Sentinel::instance() to work without DI surprises.
     */
    private function __construct() {

        self::$instance = $this;
    }

    /**
     * Get singleton instance (construct if needed).
     *
     * @return Sentinel
     */
    public static function instance(): Sentinel {

        if (self::$instance === null) {

            self::$instance = new Sentinel(); // parameterless is intentional
        }

        return self::$instance;
    }

    /**
     * Deploy Sentinel by providing the raw configuration.
     * This uses NormalizeConfig::normalize() to produce the canonical array:
     *
     *  [
     *      'services' => [
     *          'auth'        => AuthManager,
     *          'roles'       => RoleManager,
     *          'permissions' => PermissionManager,
     *          'security'    => [ 'throttle' => ..., 'activation' => ..., ... ]
     *      ],
     *      'repositories' => [
     *          'users'        => UserRepositoryInterface,
     *          'credentials'  => CredentialsRepositoryInterface,
     *          'persistences' => EloquentPersistenceRepository,
     *          'throttle'     => EloquentThrottleRepository,
     *          ...
     *      ],
     *      'logger' => Psr\Log\LoggerInterface|null
     *  ]
     *
     * @param array $inputConfiguration
     * @return void
     */
    public static function deploy(array $inputConfiguration): void {

        $canonical = NormalizeConfig::normalize($inputConfiguration);

        $instance = self::instance();

        // Store services (auth, roles, permissions, security)
        if (isset($canonical['services']) && is_array($canonical['services'])) {

            $instance->services = $canonical['services'];
        }

        // Store logger (optional)
        if (isset($canonical['logger'])) {

            $instance->logger = $canonical['logger'];
        }

        // Store repositories (optional)
        if (isset($canonical['repositories']) && is_array($canonical['repositories'])) {

            $instance->repositories = $canonical['repositories'];

            // If a 'users' repository is present, mirror it to the dedicated property for fast access
            if (isset($canonical['repositories']['users']) && $canonical['repositories']['users'] instanceof UserRepositoryInterface) {

                $instance->userRepository = $canonical['repositories']['users'];
            }
        }
    }

    /**
     * Optional setter for the user repository (when wiring outside deploy()).
     *
     * @param UserRepositoryInterface $users
     * @return void
     */
    public static function setUserRepository(UserRepositoryInterface $users): void {

        self::instance()->userRepository = $users;
    }

    /**
     * Return the currently authenticated user or null.
     *
     * NOTE: $withRelations is only honored if the underlying repository supports it.
     *
     * @param string[] $withRelations
     * @return mixed|null (UserInterface|null)
     */
    public static function check(array $withRelations = []) {

        $authManager = self::instance()->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        return $authManager->check($withRelations);
    }

    /**
     * Authenticate a user by credential (email/password).
     * Delegates to AuthManager::authenticate().
     *
     * @param string $email
     * @param string $password
     * @param bool   $remember
     * @return mixed (UserInterface)
     */
    public static function authenticate(string $email, string $password, bool $remember = false) {

        $authManager = self::instance()->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        return $authManager->authenticate($email, $password, $remember);
    }

    /**
     * Helper (shortcut) for reaching the user repository (singular).
     *
     * @return UserRepositoryInterface|null
     */
    public static function user() {

        $inst = self::instance();

        // Prefer the dedicated property if set
        if ($inst->userRepository instanceof UserRepositoryInterface) {

            return $inst->userRepository;
        }

        // Fallback to repositories bag
        if (isset($inst->repositories['users']) && $inst->repositories['users'] instanceof UserRepositoryInterface) {

            return $inst->repositories['users'];
        }

        // If a 'user' key is used instead of 'users'
        if (isset($inst->repositories['user']) && $inst->repositories['user'] instanceof UserRepositoryInterface) {

            return $inst->repositories['user'];
        }

        return null;
    }

    /**
     * Plural alias for the user repository.
     * Sentinel::users() === Sentinel::user()
     *
     * @return UserRepositoryInterface|null
     */
    public static function users() {

        return self::user();
    }

    /**
     * Determine if the current visitor is NOT authenticated.
     *
     * @return bool
     */
    public static function guest(): bool {

        return self::check() === null;
    }

    /**
     * Log out the currently authenticated user.
     *
     * @return void
     */
    public static function logout(): void {

        $authManager = self::instance()->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        $authManager->logout();
    }

    /**
     * Get the underlying service array (advanced usage).
     *
     * @return array<string,mixed>
     */
    public static function services(): array {

        return self::instance()->services;
    }
}
