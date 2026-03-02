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
    ActivationManager,
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
     * @return array
     */
    public static function normalize(array $inputConfiguration): array {

        $rawConfiguration = self::extractArray($inputConfiguration);

        // Preferred wrap-key: "sentinel".
        $configuration = (isset($rawConfiguration['sentinel']) && is_array($rawConfiguration['sentinel'])) ? $rawConfiguration['sentinel'] : ((isset($rawConfiguration['auth']) && is_array($rawConfiguration['auth'])) ? $rawConfiguration['auth'] : $rawConfiguration);

        /*
         * Select adapter
         */
        $adapterName = isset($configuration['adapter']) ? strtolower((string) $configuration['adapter']) : 'eloquent';

        switch ($adapterName) {

            case 'eloquent':

                /*
                 * A) Build password hasher FIRST
                 */
                $hasherRaw              = $configuration['hasher'] ?? 'native';
                $passwordHasher         = NativePasswordHasher::resolveHasher($hasherRaw);

                /*
                 * B) Remember‑me cookie config
                 */
                $cookieName             = isset($configuration['cookie']) ? (string) $configuration['cookie'] : 'element_sentinel';

                $rememberSection        = (isset($configuration['remember']) && is_array($configuration['remember'])) ? $configuration['remember'] : [];

                $lifetimeSeconds        = isset($rememberSection['lifetime_seconds']) ? (int) $rememberSection['lifetime_seconds'] : (60 * 60 * 24 * 30);

                $cookiePath             = isset($rememberSection['path']) ? (string) $rememberSection['path'] : '/';
                $cookieDomain           = isset($rememberSection['domain']) ? (string) $rememberSection['domain'] : null;
                $cookieSecure           = array_key_exists('secure', $rememberSection) ? (bool)$rememberSection['secure'] : null;
                $cookieHttpOnly         = !array_key_exists('http_only', $rememberSection) || (bool) $rememberSection['http_only'];
                $cookieSameSite         = isset($rememberSection['same_site']) ? (string) $rememberSection['same_site'] : 'Lax';

                /*
                 * C) User model
                 */
                $userModelClass         = (isset($configuration['models']['users']['class']) && is_string($configuration['models']['users']['class'])) ? $configuration['models']['users']['class'] : EloquentUser::class;

                Validator::validateUserModel($userModelClass);

                $defaultEagerRelations  = [];
                $honorRuntimeRelations  = ($userModelClass === EloquentUser::class);

                /*
                 * D) Persistence repository (remember-me)
                 */
                $persistencesRepository = new EloquentPersistenceRepository(
                    $cookieName,
                    $lifetimeSeconds,
                    $cookiePath,
                    $cookieDomain,
                    $cookieSecure,
                    $cookieHttpOnly,
                    $cookieSameSite
                );

                /*
                 * E) Activation repository
                 */
                $activationsRepository = new EloquentActivationRepository();

                /*
                 * F) User repository — MUST match constructor:
                 *
                 * __construct(
                 *   string $userModelClass,
                 *   ?ActivationRepositoryInterface $activationsRepository,
                 *   ?PersistenceRepositoryInterface $persistenceRepository,
                 *   PasswordHasherInterface $passwordHasher,
                 *   array $defaultEagerRelations,
                 *   bool $honorRuntimeRelations
                 * )
                 */
                $usersRepository = new EloquentUserRepository(
                    $userModelClass,
                    $activationsRepository,
                    $persistencesRepository,
                    $passwordHasher,
                    $defaultEagerRelations,
                    $honorRuntimeRelations
                );

                /*
                 * G) Credentials repository
                 */
                $credentialsRepository = new EloquentCredentialsRepository(
                    $userModelClass,
                    [] // default eager-relations (none)
                );

                /*
                 * H) Roles
                 */
                $rolesConfiguration = (isset($configuration['models']['roles']) && is_array($configuration['models']['roles'])) ? $configuration['models']['roles'] : [];

                $roleModelClass     = (isset($rolesConfiguration['class']) && is_string($rolesConfiguration['class'])) ? $rolesConfiguration['class'] : EloquentRole::class;

                Validator::validateRoleModel($roleModelClass);

                $rolePivotTable     = isset($rolesConfiguration['pivot']) ? (string) $rolesConfiguration['pivot'] : 'users_roles';

                $roleUserKey        = isset($rolesConfiguration['user_key']) ? (string) $rolesConfiguration['user_key'] : 'user_id';

                $roleRoleKey        = isset($rolesConfiguration['role_key']) ? (string) $rolesConfiguration['role_key'] : 'role_id';

                $rolesRepository = new EloquentRoleRepository(
                    $roleModelClass,
                    $userModelClass,
                    $rolePivotTable,
                    $roleUserKey,
                    $roleRoleKey
                );

                $automaticallyCreateMissingRoles = !isset($configuration['roles']['auto_create']) || (bool)$configuration['roles']['auto_create'];

                /*
                 * I) Permissions
                 */
                $permissionsConfiguration   = (isset($configuration['models']['permissions']) && is_array($configuration['models']['permissions'])) ? $configuration['models']['permissions'] : [];

                $permissionModelClass       = (isset($permissionsConfiguration['class']) && is_string($permissionsConfiguration['class'])) ? $permissionsConfiguration['class'] : EloquentPermission::class;

                Validator::validatePermissionModel($permissionModelClass);

                $permissionRolePivotTable   = isset($permissionsConfiguration['role_pivot']) ? (string) $permissionsConfiguration['role_pivot'] : 'permission_role';

                $roleUserPivotTable         = isset($rolesConfiguration['pivot']) ? (string) $rolesConfiguration['pivot'] : 'users_roles';

                $permissionUserForeignKey   = isset($permissionsConfiguration['user_key']) ? (string) $permissionsConfiguration['user_key'] : 'user';

                $permissionRoleForeignKey   = isset($permissionsConfiguration['role_key']) ? (string) $permissionsConfiguration['role_key'] : 'role_id';

                $permissionForeignKey       = isset($permissionsConfiguration['permission_key']) ? (string) $permissionsConfiguration['permission_key'] : 'permission_id';

                $permissionsRepository = new EloquentPermissionRepository(
                    $permissionModelClass,
                    $userModelClass,
                    $permissionRolePivotTable,
                    $roleUserPivotTable,
                    $permissionUserForeignKey,
                    $permissionRoleForeignKey,
                    $permissionForeignKey
                );

                $automaticallyCreateMissingPermissions = !isset($configuration['permissions']['auto_create'])  || (bool)$configuration['permissions']['auto_create'];

                /*
                 * J) Throttling
                 */
                $throttlingConfig = (isset($configuration['throttling']) && is_array($configuration['throttling'])) ? $configuration['throttling'] : [];

                $buildPolicy = function (array $cfg, $scope, $defaultInterval, $defaultThresholds, $defaultSuspensionSeconds) {

                    $scopeCfg   = isset($cfg[$scope]) && is_array($cfg[$scope]) ? $cfg[$scope] : [];
                    $interval   = isset($scopeCfg['interval']) ? (int)$scopeCfg['interval'] : $defaultInterval;
                    $thresholds = $scopeCfg['thresholds'] ?? $defaultThresholds;

                    $suspension = isset($scopeCfg['suspension_seconds']) ? (int)$scopeCfg['suspension_seconds'] : $defaultSuspensionSeconds;

                    return new ThrottlePolicy($interval, $thresholds, $suspension);
                };

                $globalPolicy = $buildPolicy($throttlingConfig, 'global', 900, [], 60);
                $ipPolicy     = $buildPolicy($throttlingConfig, 'ip',     900, 5,  60);
                $userPolicy   = $buildPolicy($throttlingConfig, 'user',   900, 5,  60);

                $throttleRepository = new EloquentThrottleRepository(
                    'throttle',
                    $globalPolicy,
                    $ipPolicy,
                    $userPolicy
                );

                /*
                 * K) Checkpoints
                 */
                $checkpointsList = [];

                if (isset($configuration['checkpoints']) && is_array($configuration['checkpoints'])) {

                    foreach ($configuration['checkpoints'] as $cpName) {

                        if (is_string($cpName) && trim($cpName) !== '') {

                            $checkpointsList[] = strtolower(trim($cpName));
                        }
                    }
                }

                $throttleCheckpointEnabled      = empty($checkpointsList) || in_array('throttle', $checkpointsList, true);

                $activationCheckpointEnabled    = empty($checkpointsList) || in_array('activation', $checkpointsList, true);

                $throttleCheckpoint = new ThrottleCheckpoint($throttleRepository, $throttleCheckpointEnabled);

                /*
                 * Activation policy (expires + lottery)
                 */
                $activationsCfg = (isset($configuration['activations']) && is_array($configuration['activations'])) ? $configuration['activations'] : [];

                $activationExpires = isset($activationsCfg['expires']) ? (int)$activationsCfg['expires'] : 0;

                $lotteryArr = isset($activationsCfg['lottery']) && is_array($activationsCfg['lottery']) ? $activationsCfg['lottery'] : [0, 0];

                $lotNum = isset($lotteryArr[0]) ? (int)$lotteryArr[0] : 0;
                $lotDen = isset($lotteryArr[1]) ? (int)$lotteryArr[1] : 0;

                $activationPolicy = new class($activationExpires, $lotNum, $lotDen) {

                    private $exp, $ln, $ld;

                    public function __construct($exp, $ln, $ld) {

                        $this->exp = $exp;
                        $this->ln  = $ln;
                        $this->ld  = $ld;
                    }

                    public function expirationSeconds() { return $this->exp; }
                    public function lotteryNumerator()  { return $this->ln; }
                    public function lotteryDenominator(){ return $this->ld; }

                    public function shouldRunLottery(): bool {

                        if ($this->ld <= 0 || $this->ln <= 0) {

                            return false;
                        }

                        return mt_rand(1, $this->ld) <= $this->ln;
                    }
                };

                $activationCheckpoint = new ActivationCheckpoint($activationCheckpointEnabled);

                /*
                 * Ordered checkpoints
                 */
                $orderedCheckpoints = [];

                if (!empty($checkpointsList)) {

                    foreach ($checkpointsList as $cpName) {

                        if ($cpName === 'throttle') {

                            $orderedCheckpoints[] = $throttleCheckpoint;

                        } elseif ($cpName === 'activation') {

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
         * 3) Logger
         */
        $loggerInstance = LogManager::build($configuration['logger'] ?? null);

        /*
         * 4) Services
         */
        $activationManager = new ActivationManager(
            $usersRepository,
            $activationsRepository,
            $persistencesRepository,
            $loggerInstance
        );

        $roleManager = new RoleManager(
            $rolesRepository,
            $loggerInstance,
            $automaticallyCreateMissingRoles
        );

        $permissionManager = new PermissionManager(
            $permissionsRepository,
            $rolesRepository,
            $loggerInstance,
            $automaticallyCreateMissingPermissions
        );

        /*
         * AuthManager — final assembly
         */
        $authManager = new AuthManager(
            $usersRepository,
            $activationsRepository,
            $passwordHasher,
            $credentialsRepository,
            $persistencesRepository,
            $loggerInstance
        );

        $authManager->configureSecurity(
            $orderedCheckpoints,
            $throttleCheckpoint,
            $activationCheckpoint,
            $activationPolicy
        );

        /*
         * Canonical structure returned to Sentinel::deploy()
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
            'hasher' => $passwordHasher,
            'services' => [
                'activation'  => $activationManager,
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
