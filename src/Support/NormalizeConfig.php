<?php

namespace Element\Sentinel\Support;

use Element\Sentinel\Infrastructure\Eloquent\{
    EloquentActivationRepository,
    EloquentCredentialsRepository,
    EloquentPermission,
    EloquentPermissionRepository,
    EloquentPersistenceRepository,
    EloquentRole,
    EloquentRoleRepository,
    EloquentThrottleRepository,
    EloquentUser,
    EloquentUserRepository
};

use Element\Sentinel\Infrastructure\Policies\ThrottlePolicy;

use Element\Sentinel\Services\{
    AuthManager,
    LogManager,
    PermissionManager,
    RoleManager
};

use Element\Sentinel\Services\Security\{
    ThrottleCheckpoint,
    ActivationCheckpoint
};

/**
 * NormalizeConfig
 *
 * Transforms user-facing configuration into the canonical array structure
 * required by Sentinel::deploy().
 */
final class NormalizeConfig {

    /**
     * Normalize any supported input into the canonical deploy array.
     *
     * @param array $inputConfiguration
     *
     * @return array
     */
    public static function normalize(array $inputConfiguration): array {

        $rawConfiguration = self::extractArray($inputConfiguration);

        // Preferred top-level section is "sentinel"; fallback to "auth" or root.
        $configuration = (isset($rawConfiguration['sentinel']) && is_array($rawConfiguration['sentinel']))
            ? $rawConfiguration['sentinel']
            : ((isset($rawConfiguration['auth']) && is_array($rawConfiguration['auth'])) ? $rawConfiguration['auth'] : $rawConfiguration);

        /*
         * 1) Adapter → repositories
         */
        $adapterName = isset($configuration['adapter']) ? strtolower((string) $configuration['adapter']) : 'eloquent';

        switch ($adapterName) {

            case 'eloquent':

                /*
                 * Remember‑me cookie configuration
                 */
                $cookieName = isset($configuration['cookie']) ? (string) $configuration['cookie'] : 'element_sentinel';

                $rememberSection = (isset($configuration['remember']) && is_array($configuration['remember']))
                    ? $configuration['remember']
                    : [];

                $lifetimeSeconds = isset($rememberSection['lifetime_seconds']) ? (int) $rememberSection['lifetime_seconds'] : (60 * 60 * 24 * 30);
                $cookiePath      = isset($rememberSection['path'])      ? (string) $rememberSection['path']      : '/';
                $cookieDomain    = isset($rememberSection['domain'])    ? (string) $rememberSection['domain']    : null;
                $cookieSecure    = array_key_exists('secure', $rememberSection) ? (bool) $rememberSection['secure'] : null;
                $cookieHttpOnly  = !array_key_exists('http_only', $rememberSection) || (bool) $rememberSection['http_only'];
                $cookieSameSite  = isset($rememberSection['same_site']) ? (string) $rememberSection['same_site'] : 'Lax';

                /*
                 * User model (pluggable) — NO relations from YAML
                 */
                $userModelClass = (isset($configuration['models']['users']['class']) && is_string($configuration['models']['users']['class']))
                    ? $configuration['models']['users']['class']
                    : EloquentUser::class;

                // Validator and NativePasswordHasher are in the same namespace (Support), so no import is required.
                Validator::validateUserModel($userModelClass);

                // No YAML relations → intentionally empty
                $defaultEagerRelations = [];

                // Only honor runtime withRelations when using the standard EloquentUser
                $honorRuntimeRelations = ($userModelClass === EloquentUser::class);

                /*
                 * Persistence repository (remember‑me)
                 */
                $persistencesRepository = new EloquentPersistenceRepository(
                    $cookieName,
                    (int) $lifetimeSeconds,
                    $cookiePath,
                    $cookieDomain,
                    $cookieSecure,
                    $cookieHttpOnly,
                    $cookieSameSite
                );

                /*
                 * Users repository
                 */
                $usersRepository = new EloquentUserRepository(
                    $userModelClass,
                    $persistencesRepository,
                    $defaultEagerRelations,
                    $honorRuntimeRelations
                );

                /*
                 * Activations
                 */
                $activationsRepository = new EloquentActivationRepository();

                /*
                 * Credentials (email‑only, pluggable model)
                 */
                $credentialsRepository = new EloquentCredentialsRepository(
                    $userModelClass,
                    [] // no default eager relations
                );

                /*
                 * Roles (pluggable)
                 */
                $rolesConfiguration = (isset($configuration['models']['roles']) && is_array($configuration['models']['roles']))
                    ? $configuration['models']['roles']
                    : [];

                $roleModelClass = (isset($rolesConfiguration['class']) && is_string($rolesConfiguration['class']))
                    ? $rolesConfiguration['class']
                    : EloquentRole::class;

                Validator::validateRoleModel($roleModelClass);

                $rolePivotTable = isset($rolesConfiguration['pivot'])    ? (string) $rolesConfiguration['pivot']    : 'role_user';
                $roleUserKey    = isset($rolesConfiguration['user_key']) ? (string) $rolesConfiguration['user_key'] : 'user_id';
                $roleRoleKey    = isset($rolesConfiguration['role_key']) ? (string) $rolesConfiguration['role_key'] : 'role_id';

                $rolesRepository = new EloquentRoleRepository(
                    $roleModelClass,
                    $userModelClass,
                    $rolePivotTable,
                    $roleUserKey,
                    $roleRoleKey
                );

                $automaticallyCreateMissingRoles = !isset($configuration['roles']['auto_create']) || (bool)$configuration['roles']['auto_create'];

                /*
                 * Permissions (pluggable) — user-based column "user" (hasMany) + role pivot (permission_role)
                 */
                $permissionsConfiguration = (isset($configuration['models']['permissions']) && is_array($configuration['models']['permissions']))
                    ? $configuration['models']['permissions']
                    : [];

                $permissionModelClass = (isset($permissionsConfiguration['class']) && is_string($permissionsConfiguration['class']))
                    ? $permissionsConfiguration['class']
                    : EloquentPermission::class;

                Validator::validatePermissionModel($permissionModelClass);

                $permissionRolePivotTable = isset($permissionsConfiguration['role_pivot'])      ? (string) $permissionsConfiguration['role_pivot']      : 'permission_role';
                $roleUserPivotTable       = isset($rolesConfiguration['pivot'])                 ? (string) $rolesConfiguration['pivot']                 : 'role_user';
                $permissionUserForeignKey = isset($permissionsConfiguration['user_key'])        ? (string) $permissionsConfiguration['user_key']        : 'user';
                $permissionRoleForeignKey = isset($permissionsConfiguration['role_key'])        ? (string) $permissionsConfiguration['role_key']        : 'role_id';
                $permissionForeignKey     = isset($permissionsConfiguration['permission_key'])  ? (string) $permissionsConfiguration['permission_key']  : 'permission_id';

                $permissionsRepository = new EloquentPermissionRepository(
                    $permissionModelClass,
                    $userModelClass,
                    $permissionRolePivotTable,
                    $roleUserPivotTable,
                    $permissionUserForeignKey,
                    $permissionRoleForeignKey,
                    $permissionForeignKey
                );

                $automaticallyCreateMissingPermissions = !isset($configuration['permissions']['auto_create']) || (bool)$configuration['permissions']['auto_create'];

                /*
                 * Throttling (global/ip/user) + Checkpoints
                 * YAML examples under: sentinel.throttling and sentinel.checkpoints
                 */
                $throttlingConfig = isset($configuration['throttling']) && is_array($configuration['throttling'])
                    ? $configuration['throttling']
                    : [];

                // Helper to build a ThrottlePolicy per scope (with suspension_seconds)
                $buildPolicy = function (array $cfg, string $scope, int $defaultInterval, $defaultThresholds, int $defaultSuspensionSeconds) {
                    $scopeCfg   = isset($cfg[$scope]) && is_array($cfg[$scope]) ? $cfg[$scope] : [];
                    $interval   = isset($scopeCfg['interval']) ? (int) $scopeCfg['interval'] : $defaultInterval;
                    $thresholds = $scopeCfg['thresholds'] ?? $defaultThresholds;
                    $suspension = isset($scopeCfg['suspension_seconds']) ? (int) $scopeCfg['suspension_seconds'] : $defaultSuspensionSeconds;

                    // Note: for map-thresholds (e.g., global), ThrottlePolicy resolves suspension from the map (minutes→seconds),
                    // and this $suspension value is effectively ignored.
                    return new ThrottlePolicy($interval, $thresholds, $suspension);
                };

                // Your YAML example: global has a map (attempts => minutes), ip/user use integers
                $globalPolicy = $buildPolicy($throttlingConfig, 'global', 900, [], 60);
                $ipPolicy     = $buildPolicy($throttlingConfig, 'ip',     900, 5,  60);
                $userPolicy   = $buildPolicy($throttlingConfig, 'user',   900, 5,  60);

                $throttleRepository = new EloquentThrottleRepository(
                    'throttle',
                    $globalPolicy,
                    $ipPolicy,
                    $userPolicy
                );

                // Checkpoints list from YAML (ordered). Default: throttle + activation
                $checkpointsList = [];

                if (isset($configuration['checkpoints']) && is_array($configuration['checkpoints'])) {

                    foreach ($configuration['checkpoints'] as $cp) {

                        if (is_string($cp)) {

                            $name = trim($cp);

                            if ($name !== '') {

                                $checkpointsList[] = strtolower($name);
                            }
                        }
                    }
                }

                $throttleCheckpointEnabled = in_array('throttle', $checkpointsList, true) || empty($checkpointsList);
                $throttleCheckpoint        = new ThrottleCheckpoint($throttleRepository, $throttleCheckpointEnabled);

                // Activation policy (expires + lottery)
                $activationsCfg         = (isset($configuration['activations']) && is_array($configuration['activations'])) ? $configuration['activations'] : [];
                $activationExpires      = isset($activationsCfg['expires']) ? (int) $activationsCfg['expires'] : 0; // 0 = never expires
                $activationLotteryArray = (isset($activationsCfg['lottery']) && is_array($activationsCfg['lottery'])) ? $activationsCfg['lottery'] : [0, 0];

                $activationLotteryNumerator   = isset($activationLotteryArray[0]) ? (int) $activationLotteryArray[0] : 0;
                $activationLotteryDenominator = isset($activationLotteryArray[1]) ? (int) $activationLotteryArray[1] : 0;

                // Minimal activation policy value-object
                $activationPolicy = new class($activationExpires, $activationLotteryNumerator, $activationLotteryDenominator) {

                    /** @var int */
                    private $expirationSeconds;
                    /** @var int */
                    private $lotteryNumerator;
                    /** @var int */
                    private $lotteryDenominator;

                    public function __construct(int $expirationSeconds, int $lotteryNumerator, int $lotteryDenominator) {

                        $this->expirationSeconds   = $expirationSeconds;
                        $this->lotteryNumerator    = $lotteryNumerator;
                        $this->lotteryDenominator  = $lotteryDenominator;
                    }

                    public function expirationSeconds(): int { return $this->expirationSeconds; }
                    public function lotteryNumerator(): int  { return $this->lotteryNumerator; }
                    public function lotteryDenominator(): int { return $this->lotteryDenominator; }
                    public function shouldRunLottery(): bool {

                        if ($this->lotteryDenominator <= 0 || $this->lotteryNumerator <= 0) {

                            return false;
                        }

                        return mt_rand(1, $this->lotteryDenominator) <= $this->lotteryNumerator;
                    }
                };

                $activationCheckpointEnabled = in_array('activation', $checkpointsList, true) || empty($checkpointsList);
                $activationCheckpoint        = new ActivationCheckpoint($activationCheckpointEnabled);

                // Ordered checkpoints
                $orderedCheckpoints = [];

                if (!empty($checkpointsList)) {

                    foreach ($checkpointsList as $checkpointName) {

                        if ($checkpointName === 'throttle') {

                            $orderedCheckpoints[] = $throttleCheckpoint;

                        } elseif ($checkpointName === 'activation') {

                            $orderedCheckpoints[] = $activationCheckpoint;
                        }
                    }

                } else {

                    $orderedCheckpoints[] = $throttleCheckpoint;
                    $orderedCheckpoints[] = $activationCheckpoint;
                }

                break;

            default:

                throw new \InvalidArgumentException('Unsupported adapter: ' . $adapterName);
        }

        /*
         * 2) Hasher
         */
        $hasherRaw      = $configuration['hasher'] ?? 'native';
        $passwordHasher = NativePasswordHasher::resolveHasher($hasherRaw);

        /*
         * 3) Logger (optional) – built via LogManager
         */
        $loggerInstance = LogManager::build($configuration['logger'] ?? null);

        /*
         * 4) Services
         */
        $roleManager = new RoleManager(
            $rolesRepository,
            $loggerInstance,
            $automaticallyCreateMissingRoles
        );

        // PermissionManager is ALWAYS combined; boolean controls auto-create
        $permissionManager = new PermissionManager(
            $permissionsRepository,
            $rolesRepository,
            $loggerInstance,
            $automaticallyCreateMissingPermissions
        );

        $authManager = new AuthManager(
            $usersRepository,
            $activationsRepository,
            $passwordHasher,
            $credentialsRepository,
            $persistencesRepository,
            $loggerInstance
        );

        // ✅ Wiring-hint: give AuthManager the security components (ordered checkpoints + instances + policy)
        $authManager->configureSecurity(
            $orderedCheckpoints,
            $throttleCheckpoint,
            $activationCheckpoint,
            $activationPolicy
        );

        /*
         * 5) Canonical structure (repositories + hasher + optional logger + services)
         */
        $canonical = [
            'repositories' => [
                'users'        => $usersRepository,
                'activations'  => $activationsRepository,
                'credentials'  => $credentialsRepository,
                'persistences' => $persistencesRepository,
                'roles'        => $rolesRepository,
                'permissions'  => $permissionsRepository,
                'throttle'     => $throttleRepository,
            ],
            'hasher'   => $passwordHasher,
            'services' => [
                'auth'        => $authManager,
                'roles'       => $roleManager,
                'permissions' => $permissionManager,
                'security'    => [
                    'throttle'          => $throttleCheckpoint,
                    'activation'        => $activationCheckpoint,
                    'activation_policy' => $activationPolicy,
                    'checkpoints'       => $orderedCheckpoints,
                ],
            ],
        ];

        if ($loggerInstance !== null) {

            $canonical['logger'] = $loggerInstance;
        }

        return $canonical;
    }

    /**
     * Extract array from PHP/YAML configuration.
     *
     * @param array $input
     *
     * @return array
     */
    private static function extractArray(array $input): array {

        if (!isset($input['file'])) {

            return $input;
        }

        $path = (string) $input['file'];

        if (!is_file($path)) {

            throw new \InvalidArgumentException('Config file not found: ' . $path);
        }

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if ($extension === 'php') {

            $data = require $path;

            if (!is_array($data)) {

                throw new \InvalidArgumentException('PHP config must return an array: ' . $path);
            }

            return $data;
        }

        if ($extension === 'yml' || $extension === 'yaml') {

            if (!class_exists(\Symfony\Component\Yaml\Yaml::class)) {

                throw new \RuntimeException('YAML requires symfony/yaml. Install it or use PHP config.');
            }

            $parsed = \Symfony\Component\Yaml\Yaml::parseFile($path);

            if (!is_array($parsed)) {

                throw new \InvalidArgumentException('YAML config must return an array: ' . $path);
            }

            return $parsed;
        }

        throw new \InvalidArgumentException('Unsupported config extension: ' . $extension);
    }
}
