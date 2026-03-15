<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    UserRepositoryInterface
};

use Element\Sentinel\Services\{
    ActivationManager,
    AuthManager,
    PermissionManager,
    RoleManager
};

use Element\Sentinel\Support\NormalizeConfig;

use Psr\Log\{
    LoggerInterface,
    NullLogger
};

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
     *
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
     * Register a new user via the configured UserRepository.
     *
     * When $login === TRUE, this method will also authenticate the newly created
     * user by delegating to the configured AuthManager, using the email and password
     * provided in $attributes. When $remember === TRUE, a persistent "remember me"
     * cookie will be set as part of the authentication flow.
     *
     * @param array $attributes  Associative array: must include 'email' and 'password'.
     *                           Optional keys: uuid, first_name, last_name, activation_token, ...
     * @param bool  $activate    If TRUE, the user is created as activated immediately.
     * @param bool  $login       If TRUE, authenticate the user after successful registration.
     * @param bool  $remember    Used only when $login === TRUE; sets remember-me persistence.
     *
     * @return mixed  (\Element\Sentinel\Contracts\UserInterface)
     *
     * @throws \RuntimeException
     *         When the users repository is not configured.
     * @throws \InvalidArgumentException|\RuntimeException
     *         Bubbled up from repository validation/persistence.
     */
    public static function register(array $attributes, bool $activate = false, bool $login = false, bool $remember = false) {

        $instance = self::instance();

        // Resolve the users repository
        $usersRepository = null;

        if (isset($instance->userRepository) && $instance->userRepository) {

            $usersRepository = $instance->userRepository;

        } elseif (isset($instance->repositories['users']) && $instance->repositories['users']) {

            $usersRepository = $instance->repositories['users'];

        } elseif (isset($instance->repositories['user']) && $instance->repositories['user']) {

            $usersRepository = $instance->repositories['user'];
        }

        if ($usersRepository === null) {

            throw new \RuntimeException('Users repository is not configured on Sentinel.');
        }

        // 1) Register user using the repository
        $user = $usersRepository->register($attributes, $activate);

        // 2) Optionally authenticate immediately after registration
        if ($login === true) {

            // Extract email and password from attributes for the authentication call.
            // The repository has already hashed and persisted the password, so we use
            // the plaintext from attributes (as provided by the caller) for verification.
            $emailFromAttributes    = isset($attributes['email']) ? (string) $attributes['email'] : '';
            $passwordFromAttributes = isset($attributes['password']) ? (string) $attributes['password'] : '';

            if ($emailFromAttributes !== '' && $passwordFromAttributes !== '') {

                $authManager = $instance->services['auth'] ?? null;

                if ($authManager === null) {

                    throw new \RuntimeException('Auth service is not configured on Sentinel.');
                }

                // authenticate(email, password, activate, login, remember)
                // - We do not auto-activate here; $activate was already applied by the repository.
                // - We DO establish login state (session/remember-me) here.
                $authManager->authenticate(
                    $emailFromAttributes,
                    $passwordFromAttributes,
                    /* activate */ false,
                    /* login    */ true,
                    /* remember */ $remember
                );
            }
        }

        return $user;
    }

    /**
     * Validate a user's credentials without performing a login.
     *
     * This static helper proxies to AuthManager::validateCredentials() and is
     * intended for read-only credential checks (e.g., preflight checks in APIs,
     * gating sensitive changes, etc.). It does NOT establish any authentication
     * state (no session, no remember-me) and it does NOT execute activation checks.
     * These responsibilities remain within authenticate().
     *
     * Return semantics:
     * - Returns TRUE when the email exists and the password matches.
     * - Returns FALSE otherwise.
     *
     * Side effects:
     * - May perform throttle hits/clears depending on the AuthManager configuration.
     * - May transparently rehash and persist the password if supported by the
     *   underlying repository and the configured hasher.
     *
     * @param string $email
     *        The email address used as the login identifier.
     * @param string $password
     *        The plaintext password provided by the caller.
     * @param \Element\Sentinel\Contracts\UserInterface|null $authenticatedUser
     *        Output parameter. On success, this will be set to the resolved user instance.
     *        On failure, it will remain NULL.
     *
     * @return bool
     *         TRUE if the provided credentials are valid; otherwise FALSE.
     *
     * @throws \RuntimeException
     *         When the Auth service is not configured on Sentinel.
     */
    public static function validateCredentials(string $email, string $password, ?\Element\Sentinel\Contracts\UserInterface &$authenticatedUser = null): bool {

        $authManager = self::instance()->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        // Delegate to the AuthManager for the actual validation logic
        return $authManager->validateCredentials($email, $password, $authenticatedUser);
    }

    /**
     * Update a user's password.
     *
     * This static helper delegates the password update workflow to the configured
     * AuthManager instance. The AuthManager resolves the user, optionally verifies
     * the current password, hashes the new password using the configured hasher,
     * and persists the change via the credentials repository.
     *
     * Security:
     * - This method never logs plaintext passwords, and neither should callers.
     *
     * @param mixed  $id
     *        The user identifier (typically the primary key).
     * @param string $newPassword
     *        The new plaintext password (will be hashed by the AuthManager).
     * @param bool $verifyCurrent
     *        If TRUE, the provided $currentPassword must match the user's current password.
     * @param string $currentPassword
     *        The current plaintext password used for verification when $verifyCurrent === TRUE.
     *
     * @return bool
     *         TRUE on success; FALSE when the user is not found or verification fails.
     *
     * @throws \RuntimeException
     *         When the Auth service is not configured on Sentinel.
     */
    public static function updatePassword($id, string $newPassword, bool $verifyCurrent = false, string $currentPassword = ''): bool {

        $authManager = self::instance()->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        return $authManager->updatePassword($id, $newPassword, $verifyCurrent, $currentPassword);
    }

    /**
     * Get the configured ActivationRepository instance.
     *
     * This static helper provides direct access to the underlying activation
     * service responsible for creating, locating and completing activation
     * records for users. It exposes the same instance that was created and
     * registered during Sentinel::deploy().
     *
     * Typical usage:
     *
     *     $activation = Sentinel::activation()->exists($user);
     *
     * @return object
     *
     * @throws \RuntimeException
     *         When the activation service is not configured.
     */
    public static function activation(): object {

        $instance = self::instance();

        $activationRepository = $instance->services['activations'] ?? null;

        if ($activationRepository === null) {

            throw new \RuntimeException('Activation service is not configured on Sentinel.');
        }

        return $activationRepository;
    }

    /**
     * Plural alias for the activation repository.
     * Sentinel::activations() === Sentinel::activation()
     *
     * @return ActivationRepositoryInterface|null
     */
    public static function activations(): ?ActivationRepositoryInterface {

        return self::activation();
    }

    /**
     * Helper (shortcut) for reaching the user repository (singular).
     *
     * @return UserRepositoryInterface|null
     */
    public static function user(): ?UserRepositoryInterface {

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
    public static function users(): ?UserRepositoryInterface {

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
     * Get the configured ActivationManager instance.
     *
     * This static helper returns the ActivationManager that was registered
     * during Sentinel::deploy() via NormalizeConfig. It provides the activation
     * API without adding any business logic to the Sentinel facade.
     *
     * @return ActivationManager
     *
     * @throws \RuntimeException When the activation manager is not configured.
     */
    public static function activationManager(): ActivationManager {

        $instance = self::instance();

        $manager = $instance->services['activation'] ?? null;

        if ($manager === null) {

            throw new \RuntimeException('Activation manager is not configured on Sentinel.');
        }

        return $manager;
    }

    /**
     * Activate a user by completing the pending activation record.
     *
     * This static helper resolves the user by the provided identifier and attempts
     * to complete the activation using the configured ActivationRepository.
     *
     * Behavior:
     * - Returns TRUE if a pending activation exists and was successfully completed.
     * - Returns FALSE if the user cannot be resolved or no pending activation exists.
     *
     * Requirements:
     * - The activation repository must be available under services['activations'],
     *   as produced by NormalizeConfig() during Sentinel::deploy().
     * - The user repository must implement findById().
     *
     * Common usage:
     *
     *     Sentinel::activateUser($userId);
     *
     * @param mixed $id
     *         The user identifier (typically a primary key). Cast to int for
     *         compatibility with common user-repository implementations.
     * @param bool $remember
     *
     * @return bool
     *         TRUE if activation was successfully completed; otherwise FALSE.
     *
     */
    public static function activateUser($id, bool $remember = false): bool {

        return self::activationManager()->activateUser($id, $remember);
    }

    /**
     * Determine whether a pending activation exists for the given user.
     *
     * Resolves the user by identifier and returns TRUE when the activation
     * repository reports an existing (not completed) activation record.
     *
     * @param  mixed $id
     *         The user identifier (typically the primary key).
     *
     * @return bool
     *         TRUE when a pending activation exists; otherwise FALSE.
     *
     * @throws \RuntimeException
     *         When the activation or user repository is not configured, or the
     *         activation repository does not implement the required methods.
     */
    public static function activationExists($id): bool {

        return self::activationManager()->activationExists($id);
    }

    /**
     * Resend (or recreate) an activation for the given user.
     *
     * Preferred behavior:
     * - If the activation repository implements resend(UserInterface): bool,
     *   this method will call it and return the result.
     *
     * Fallback behavior:
     * - If resend() is not available but create(UserInterface) exists,
     *   this helper will attempt to create (or recreate) a new activation row
     *   and return TRUE on success. It assumes the repository or the caller
     *   handles the actual notification delivery.
     *
     * @param  mixed $id
     *         The user identifier (typically the primary key).
     *
     * @return bool
     *         TRUE if the resend or recreation succeeded; otherwise FALSE.
     *
     * @throws \RuntimeException
     *         When the activation or user repository is not configured and when
     *         the activation repository supports neither resend() nor create().
     */
    public static function resendActivation($id): bool {

        return self::activationManager()->resendActivation($id);
    }

    /**
     * Get the configured AuthManager instance.
     *
     * This static helper provides direct access to the underlying authentication
     * service (AuthManager) that powers methods like authenticate(), check(), and logout().
     * It is useful when consumers need imperative access to lower-level operations
     * (e.g., custom authentication flows, reusing validation helpers, or reading
     * configuration-dependent behaviors) without re-wiring the service container.
     *
     * @return AuthManager
     *
     * @throws \RuntimeException
     *         When the Auth service is not configured on Sentinel::deploy().
     */
    public static function auth(): AuthManager {

        $instance = self::instance();

        // All services are wired by NormalizeConfig::normalize(...) in deploy().
        // The 'auth' key is expected to hold the AuthManager instance.
        $authManager = $instance->services['auth'] ?? null;

        if ($authManager === null) {

            throw new \RuntimeException('Auth service is not configured on Sentinel.');
        }

        return $authManager;
    }

    /**
     * Get the configured PSR-3 logger instance.
     *
     * This static helper returns the logger that was injected through
     * Sentinel::deploy(). If no logger was configured, a Psr\Log\NullLogger
     * instance is returned so that callers can safely log without additional
     * null checks.
     *
     * Typical usage:
     *
     *   Sentinel::log()->info('Something happened', ['context' => 'value']);
     *
     * @return LoggerInterface
     */
    public static function log(): LoggerInterface {

        $instance = self::instance();

        if ($instance->logger instanceof LoggerInterface) {

            return $instance->logger;
        }

        // Provide a fallback PSR-3 compliant logger.
        $instance->logger = new NullLogger();

        return $instance->logger;
    }

    /**
     * Get the configured PermissionManager instance.
     *
     * This static helper provides direct access to the underlying permission
     * service that manages permission definitions and evaluation rules. It allows
     * consumers to retrieve the permission manager without manually accessing the
     * internal services array created during Sentinel::deploy().
     *
     * Typical usage:
     *
     *   $permission = Sentinel::permission()->findBySlug('posts.publish');
     *   $canPublish = Sentinel::permission()->userHasPermission($user, 'posts.publish');
     *
     * @return PermissionManager
     *
     * @throws \RuntimeException
     *         When the permission service is not configured on Sentinel::deploy().
     */
    public static function permission(): PermissionManager {

        $instance = self::instance();

        $permissionManager = $instance->services['permissions'] ?? null;

        if ($permissionManager === null) {

            throw new \RuntimeException('Permission service is not configured on Sentinel.');
        }

        return $permissionManager;
    }

    /**
     * Plural alias for the Permission Manager.
     * Sentinel::permissions() === Sentinel::permission()
     *
     * @return PermissionManager
     */
    public static function permissions(): PermissionManager {

        return self::permission();
    }

    /**
     * Get the configured RoleManager instance.
     *
     * This static helper provides direct access to the underlying role service
     * that manages role creation, updating and assignment. It allows consumers
     * to retrieve the role manager without manually accessing the internal
     * services array created during Sentinel::deploy().
     *
     * Typical usage:
     *
     *   Sentinel::role()->findByName('admin');
     *   Sentinel::role()->assignRoleToUser($user, 'editor');
     *
     * @return RoleManager
     *
     * @throws \RuntimeException
     *         When the role service is not configured on Sentinel::deploy().
     */
    public static function role(): RoleManager {

        $instance = self::instance();

        $roleManager = $instance->services['roles'] ?? null;

        if ($roleManager === null) {

            throw new \RuntimeException('Role service is not configured on Sentinel.');
        }

        return $roleManager;
    }

    /**
     * Plural alias for the Role Manager.
     * Sentinel::roles() === Sentinel::role()
     *
     * @return RoleManager
     */
    public static function roles(): RoleManager {

        return self::role();
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
