<?php

namespace Element\Sentinel\Services;

use Psr\Log\{
    LoggerInterface,
    NullLogger
};

/**
 * LogManager
 *
 * Central factory for building a PSR-3 logger from normalized config.
 * Supports:
 *  - LoggerInterface instance (returned as-is)
 *  - callable returning LoggerInterface
 *  - string "null"/"none"     -> NullLogger
 *  - string "monolog"         -> default Monolog logger (<base>/logs/sentinel.log, DEBUG)
 *  - array { driver: "monolog", ... } -> Monolog with custom options
 *
 * NOTE:
 *  - If you pass "monolog" (string) or a monolog array, Monolog must be installed:
 *      composer require monolog/monolog
 */
final class LogManager {

    /**
     * Build a logger instance from user-friendly config.
     *
     * @param mixed $raw
     *
     * @return LoggerInterface|null
     */
    public static function build($raw): ?LoggerInterface {

        if ($raw === null) {

            return null;
        }

        // Callable factory
        if (is_callable($raw)) {

            $raw = $raw();
        }

        // Already a PSR-3 instance
        if ($raw instanceof LoggerInterface) {

            return $raw;
        }

        // Shorthand strings
        if (is_string($raw)) {

            $symbol = strtolower($raw);

            if ($symbol === 'null' || $symbol === 'none') {

                return new NullLogger();
            }

            if ($symbol === 'monolog') {

                return self::buildDefaultMonolog();
            }

            throw new \InvalidArgumentException('Unsupported logger string: ' . $raw);
        }

        // Array config (driver-based)
        if (is_array($raw)) {

            $driver = isset($raw['driver']) ? strtolower((string) $raw['driver']) : '';

            if ($driver !== 'monolog') {

                throw new \InvalidArgumentException('Unsupported logger driver in array config: ' . $driver);
            }

            return self::buildMonologFromArray($raw);
        }

        throw new \InvalidArgumentException(
            'Logger must be LoggerInterface, callable, "null"/"none", "monolog", or a monolog array config.'
        );
    }

    /**
     * Default Monolog logger writing to "<base>/logs/sentinel.log" @ DEBUG.
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

        $logger  = new \Monolog\Logger('sentinel');
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
     * Monolog logger from array config.
     *
     * Supported keys:
     *  - driver: "monolog" (required)
     *  - channel:     string (default: "sentinel")
     *  - path:        string (default: "<base>/logs/sentinel.log", supports %BASE_DIR%)
     *  - level:       string name (debug|info|notice|warning|error|critical|alert|emergency)
     *  - bubble:      bool
     *  - permission:  int (octal like 0775) for directory creation
     *  - format:      string line format for LineFormatter
     *  - date_format: string date format for LineFormatter
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

        $level  = $levelMap[$levelName] ?? \Monolog\Logger::DEBUG;
        $bubble = !isset($config['bubble']) || (bool)$config['bubble'];

        $logger  = new \Monolog\Logger($channelName);
        $handler = new \Monolog\Handler\StreamHandler($logPath, $level, $bubble);

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
        $root = dirname(__DIR__, 2); // Services/ -> src/

        $project = dirname($root, 1);
        return is_dir($project) ? $project : getcwd();
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
