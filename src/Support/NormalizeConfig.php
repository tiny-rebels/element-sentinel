<?php

namespace Element\Sentinel\Support;

use Element\Sentinel\Contracts\PasswordHasherInterface;

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

use Element\Sentinel\Services\Security\ThrottleCheckpoint;

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

        // Preferred top-level section is "sentinel".
        // Backward compatibility: fall back to "auth" or to root array.
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

                Validator::validateUserModel($userModelClass);

                // No YAML relations → empty by design
                $defaultEagerRelations = [];

                // Allow runtime withRelations only for the standard EloquentUser
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
                $credentialsRepository = new EloquentCredentialsRepository($userModelClass, []);

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
                $permissionsConfiguration = (isset($configuration['models']['permissions']) && is_array($configuration['models']['permissions'])) ? $configuration['models']['permissions'] : [];

                $permissionModelClass = (isset($permissionsConfiguration['class']) && is_string($permissionsConfiguration['class'])) ? $permissionsConfiguration['class'] : EloquentPermission::class;

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
                 * Throttling (global/ip/user) via Infrastructure/Policies\ThrottlePolicy
                 * YAML example expected under: sentinel.throttling
                 */
                $throttlingConfig = isset($configuration['throttling']) && is_array($configuration['throttling']) ? $configuration['throttling'] : [];

                // Helper to build a ThrottlePolicy per scope
                $buildPolicy = function (array $cfg, string $scope, int $defaultInterval, $defaultThresholds, int $defaultSuspensionSeconds) {
                    $scopeCfg   = isset($cfg[$scope]) && is_array($cfg[$scope]) ? $cfg[$scope] : [];
                    $interval   = isset($scopeCfg['interval']) ? (int) $scopeCfg['interval'] : $defaultInterval;
                    $thresholds = $scopeCfg['thresholds'] ?? $defaultThresholds;

                    // If you later add "suspension_seconds" per scope in YAML:
                    // $suspension = isset($scopeCfg['suspension_seconds']) ? (int) $scopeCfg['suspension_seconds'] : $defaultSuspensionSeconds;
                    $suspension = $defaultSuspensionSeconds;

                    return new ThrottlePolicy($interval, $thresholds, $suspension);
                };

                // Your YAML: global has a map (attempts => minutes), ip/user are integers.
                $globalPolicy = $buildPolicy($throttlingConfig, 'global', 900, [], 60);
                $ipPolicy     = $buildPolicy($throttlingConfig, 'ip',     900, 5,  60);
                $userPolicy   = $buildPolicy($throttlingConfig, 'user',   900, 5,  60);

                $throttleRepository = new EloquentThrottleRepository(
                    'throttle_entries',
                    $globalPolicy,
                    $ipPolicy,
                    $userPolicy
                );

                // Optionally allow disabling checkpoint via config later; keep it enabled for now.
                $throttleEnabled    = true;

                $throttleCheckpoint = new ThrottleCheckpoint($throttleRepository, $throttleEnabled);

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

        // PermissionManager is ALWAYS combined; boolean sets auto-create
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
            'hasher' => $passwordHasher,
            'services' => [
                'auth'        => $authManager,
                'roles'       => $roleManager,
                'permissions' => $permissionManager,
                'security'    => [
                    'throttle' => $throttleCheckpoint,
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
