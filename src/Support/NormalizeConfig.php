<?php

namespace Element\Sentinel\Support;

use Element\Sentinel\Contracts\PasswordHasherInterface;

use Element\Sentinel\Infrastructure\Eloquent\{
    EloquentActivationRepository,
    EloquentCredentialsRepository,
    EloquentPersistenceRepository,
    EloquentUser,
    EloquentUserRepository
};

use Element\Sentinel\Services\AuthManager;

use Element\Sentinel\Support\NativePasswordHasher;

use Psr\Log\{
    LoggerInterface,
    NullLogger
};

/**
 * NormalizeConfig
 *
 * Turns various user-friendly configuration inputs into the canonical
 * deploy array expected by Sentinel::deploy().
 *
 * Supported inputs:
 *  - ['file' => '/path/auth.php']          // PHP file returning array
 *  - ['file' => '/path/auth.yaml']         // YAML file (requires symfony/yaml)
 *  - ['auth' => [...]]                     // "auth-style" array like your YAML
 *  - ['adapter' => 'eloquent', ...]        // direct symbolic options
 *  - canonical deploy array (repositories/hasher[, logger])
 *
 * Canonical repositories:
 *  'repositories' => [
 *      'users'        => UserRepositoryInterface,
 *      'activations'  => ActivationRepositoryInterface,
 *      'credentials'  => CredentialsRepositoryInterface,
 *      'persistences' => PersistenceRepositoryInterface,
 *  ]
 *
 * Services:
 *  'services' => [
 *      'auth' => AuthManager
 *  ]
 */
final class NormalizeConfig {

    /**
     * Normalize any supported input into the canonical deploy array.
     *
     * @param array $inputConfig
     *
     * @return array
     */
    public static function normalize(array $inputConfig): array {

        $rawConfig = self::extractArray($inputConfig);

        // Accept either a top-level "auth" section or direct canonical/symbolic keys
        $auth = isset($rawConfig['auth']) && is_array($rawConfig['auth']) ? $rawConfig['auth'] : $rawConfig;

        // 1) Adapter -> repositories (currently supporting 'eloquent')
        $adapterName = isset($auth['adapter']) ? strtolower((string) $auth['adapter']) : 'eloquent';

        switch ($adapterName) {

            case 'eloquent':

                // Remember-me and cookie settings
                $cookieName   = isset($auth['cookie']) ? (string) $auth['cookie'] : 'element_sentinel';

                // Optional remember section, e.g. auth.remember.lifetime_seconds
                $remember     = isset($auth['remember']) && is_array($auth['remember']) ? $auth['remember'] : [];
                $lifetimeSecs = isset($remember['lifetime_seconds']) ? (int) $remember['lifetime_seconds'] : (60 * 60 * 24 * 30); // 30 days default

                $cookiePath   = isset($remember['path']) ? (string) $remember['path'] : '/';
                $cookieDomain = isset($remember['domain']) ? (string) $remember['domain'] : null;
                $cookieSecure = array_key_exists('secure', $remember) ? (bool) $remember['secure'] : null;
                $cookieHttp   = !array_key_exists('http_only', $remember) || (bool)$remember['http_only'];
                $cookieSame   = isset($remember['same_site']) ? (string) $remember['same_site'] : 'Lax';

                // Build persistences repository
                $persistencesRepository = new EloquentPersistenceRepository(
                    $cookieName,
                    $lifetimeSecs,
                    $cookiePath,
                    $cookieDomain,
                    $cookieSecure,
                    $cookieHttp,
                    $cookieSame
                );

                // Users repository (inject persistences so check() can hydrate from remember cookie)
                $usersRepository       = new EloquentUserRepository($persistencesRepository);

                // Activations
                $activationsRepository = new EloquentActivationRepository();

                // Email-only credentials repository
                $credentialsRepository = new EloquentCredentialsRepository(
                    EloquentUser::class
                );

                break;

            default:
                throw new \InvalidArgumentException('Unsupported adapter: ' . $adapterName);
        }

        // 2) Hasher
        $hasherRaw      = $auth['hasher'] ?? 'native';
        $passwordHasher = self::buildHasher($hasherRaw);

        // 3) Logger (optional)
        $loggerInstance = self::buildLogger($auth['logger'] ?? null);

        // 4) Build AuthManager service (email-only). Logger is optional and not part of the interface.
        $authManager = new AuthManager(
            $usersRepository,
            $activationsRepository,
            $passwordHasher,
            $credentialsRepository,
            $persistencesRepository,
            $loggerInstance
        );

        // 5) Canonical shape (repositories + hasher + optional logger + services.auth)
        $canonical = [

            'repositories' => [

                'users'        => $usersRepository,
                'activations'  => $activationsRepository,
                'credentials'  => $credentialsRepository,
                'persistences' => $persistencesRepository,
            ],

            'hasher'   => $passwordHasher,

            'services' => [

                'auth' => $authManager,
            ],
        ];

        if ($loggerInstance !== null) {

            $canonical['logger'] = $loggerInstance;
        }

        return $canonical;
    }

    /**
     * Extract a PHP array from supported sources.
     *
     * Rules:
     *  - If ['file' => '/path/...'] is present, parse that file.
     *    * .php  must return an array.
     *    * .yml/.yaml requires symfony/yaml.
     *  - Otherwise, the input itself is considered the array config.
     *
     * @param array $input
     *
     * @return array
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private static function extractArray(array $input): array {

        if (!isset($input['file'])) {

            return $input; // Already an array payload
        }

        $path = (string) $input['file'];

        if (!is_file($path)) {

            throw new \InvalidArgumentException('Config file not found: ' . $path);
        }

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if ($extension === 'php') {

            /** @var mixed $data */
            $data = require $path;

            if (!is_array($data)) {

                throw new \InvalidArgumentException('PHP config must return an array: ' . $path);
            }

            return $data;
        }

        if ($extension === 'yml' || $extension === 'yaml') {

            if (!class_exists(\Symfony\Component\Yaml\Yaml::class)) {

                throw new \RuntimeException(
                    'YAML config requires symfony/yaml. Install it or convert your YAML to a PHP array file.'
                );
            }

            /** @var mixed $parsed */
            $parsed = \Symfony\Component\Yaml\Yaml::parseFile($path);

            if (!is_array($parsed)) {

                throw new \InvalidArgumentException('YAML config must parse to an array: ' . $path);
            }

            return $parsed;
        }

        throw new \InvalidArgumentException('Unsupported config file extension: ' . $extension);
    }

    /**
     * Build a PasswordHasherInterface from a symbolic value or an instance.
     *
     * @param mixed $hasherRaw
     *
     * @return PasswordHasherInterface
     *
     * @throws \InvalidArgumentException
     */
    private static function buildHasher($hasherRaw): PasswordHasherInterface {

        if ($hasherRaw instanceof PasswordHasherInterface) {

            return $hasherRaw;
        }

        if ($hasherRaw === 'native' || $hasherRaw === null) {

            return new NativePasswordHasher();
        }

        throw new \InvalidArgumentException('Unsupported hasher value. Use "native" or provide an instance.');
    }

    /**
     * Build a logger instance from symbolic config, an instance, or a factory.
     *
     * Accepted inputs:
     *  - LoggerInterface instance (returned as-is)
     *  - callable returning LoggerInterface
     *  - string "monolog"      -> build a default Monolog logger
     *  - string "null"/"none"  -> NullLogger
     *  - array with keys:
     *      driver:      "monolog" (required for array form)
     *      channel:     string                       (default: "sentinel")
     *      path:        string (file path)           (default: "<base>/logs/sentinel.log")
     *      level:       string level name            (default: "debug")
     *      bubble:      bool                         (optional)
     *      permission:  int (octal like 0775)        (optional)
     *      format:      string Monolog line format   (optional)
     *      date_format: string date format           (optional)
     *
     * @param mixed $loggerRaw
     *
     * @return LoggerInterface|null
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private static function buildLogger($loggerRaw): ?LoggerInterface {

        if ($loggerRaw === null) {

            return null;
        }

        if (is_callable($loggerRaw)) {

            $loggerRaw = $loggerRaw();
        }

        if ($loggerRaw instanceof LoggerInterface) {

            return $loggerRaw;
        }

        if (is_string($loggerRaw)) {

            $symbol = strtolower($loggerRaw);

            if ($symbol === 'null' || $symbol === 'none') {

                return new NullLogger();
            }

            if ($symbol === 'monolog') {

                return self::buildDefaultMonolog();
            }

            throw new \InvalidArgumentException('Unsupported logger string: ' . $loggerRaw);
        }

        if (is_array($loggerRaw)) {

            $driver = isset($loggerRaw['driver']) ? strtolower((string) $loggerRaw['driver']) : '';

            if ($driver !== 'monolog') {

                throw new \InvalidArgumentException('Unsupported logger driver in array config: ' . $driver);
            }

            return self::buildMonologFromArray($loggerRaw);
        }

        throw new \InvalidArgumentException(
            'logger must be LoggerInterface, callable, "monolog", "null"/"none", or an array.'
        );
    }

    /**
     * Create a default Monolog logger writing to "<base>/logs/sentinel.log" @ DEBUG.
     *
     * @return LoggerInterface
     */
    private static function buildDefaultMonolog(): LoggerInterface {

        self::assertMonologAvailable();

        $baseDir = self::detectBaseDir();
        $logsDir = $baseDir . DIRECTORY_SEPARATOR . 'logs';

        if (!is_dir($logsDir)) {

            @mkdir($logsDir, 0775, true);
        }

        $filePath = $logsDir . DIRECTORY_SEPARATOR . 'sentinel.log';

        $logger = new \Monolog\Logger('sentinel');
        $handler = new \Monolog\Handler\StreamHandler($filePath, \Monolog\Logger::DEBUG);

        $formatter = new \Monolog\Formatter\LineFormatter(
            "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
            'c',
            true,
            true
        );
        $handler->setFormatter($formatter);

        $logger->pushHandler($handler);

        return $logger;
    }

    /**
     * Create a Monolog logger from array config.
     *
     * @param array $config
     *
     * @return LoggerInterface
     */
    private static function buildMonologFromArray(array $config): LoggerInterface {

        self::assertMonologAvailable();

        $channelName = isset($config['channel']) ? (string) $config['channel'] : 'sentinel';

        $baseDir = self::detectBaseDir();

        // Allow %BASE_DIR% placeholder in path
        $rawPath = isset($config['path']) ? (string) $config['path'] : ($baseDir . '/logs/sentinel.log');
        $logPath = str_replace('%BASE_DIR%', $baseDir, $rawPath);

        // Ensure directory exists
        $logDir = dirname($logPath);

        if (!is_dir($logDir)) {
            $permission = isset($config['permission']) ? (int) $config['permission'] : 0775;
            @mkdir($logDir, $permission, true);
        }

        $levelName = isset($config['level']) ? strtolower((string) $config['level']) : 'debug';

        $levelMap = [

            'emergency' => \Monolog\Logger::EMERGENCY,
            'alert'     => \Monolog\Logger::ALERT,
            'critical'  => \Monolog\Logger::CRITICAL,
            'error'     => \Monolog\Logger::ERROR,
            'warning'   => \Monolog\Logger::WARNING,
            'notice'    => \Monolog\Logger::NOTICE,
            'info'      => \Monolog\Logger::INFO,
            'debug'     => \Monolog\Logger::DEBUG,
        ];

        $level      = isset($levelMap[$levelName]) ? $levelMap[$levelName] : \Monolog\Logger::DEBUG;
        $bubble     = isset($config['bubble']) ? (bool) $config['bubble'] : true;

        $logger     = new \Monolog\Logger($channelName);
        $handler    = new \Monolog\Handler\StreamHandler($logPath, $level, $bubble);

        // Optional formatter
        $format     = isset($config['format']) ? (string) $config['format'] : "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n";
        $dateFormat = isset($config['date_format']) ? (string) $config['date_format'] : 'c';

        $formatter  = new \Monolog\Formatter\LineFormatter($format, $dateFormat, true, true);

        $handler->setFormatter($formatter);

        $logger->pushHandler($handler);

        return $logger;
    }

    /**
     * Detect a reasonable base directory for default paths.
     *
     * @return string
     */
    private static function detectBaseDir(): string {

        // Detect package root (…/vendor/element/sentinel) and go up to project root when possible.
        $root = dirname(__DIR__, 3);

        return is_dir($root) ? $root : getcwd();
    }

    /**
     * Ensure Monolog is installed before building it.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function assertMonologAvailable(): void {

        if (!class_exists(\Monolog\Logger::class) || !class_exists(\Monolog\Handler\StreamHandler::class)) {

            throw new \RuntimeException(
                'Monolog is required for logger "monolog". Run: composer require monolog/monolog'
            );
        }
    }
}
