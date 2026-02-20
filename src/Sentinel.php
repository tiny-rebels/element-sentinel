<?php

namespace Element\Sentinel;

use Element\Sentinel\{
    Contracts\ActivationRepositoryInterface,
    Contracts\PasswordHasherInterface,
    Contracts\UserInterface,
    Contracts\UserRepositoryInterface,
    Support\NativePasswordHasher
};

use Psr\Log\LoggerInterface;

/**
 * Core Sentinel entry point.
 *
 * Responsibilities:
 * - Activation workflow (ensureActivationCode / activateByCode)
 * - Password hashing helpers (hash/verify/needsRehash)
 * - Accessors to repositories (users / activations)
 * - Static deploy() that wires the instance from a simple config array
 * - Optional PSR-3 logger support
 * - Static facade-style shortcuts to repos and hasher
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

    /** @var self|null Global instance set by deploy() for static facade calls */
    private static $instance = null;

    /**
     * Construct a Sentinel instance from concrete dependencies.
     *
     * @param UserRepositoryInterface       $userRepository
     * @param ActivationRepositoryInterface $activationRepository
     * @param PasswordHasherInterface       $passwordHasher
     * @param LoggerInterface|null          $logger
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        ActivationRepositoryInterface $activationRepository,
        PasswordHasherInterface $passwordHasher,
        LoggerInterface $logger = null
    ) {
        $this->userRepository       = $userRepository;
        $this->activationRepository = $activationRepository;
        $this->passwordHasher       = $passwordHasher;
        $this->logger               = $logger;
    }

    /**
     * ------------------------------------------------------------
     *  STATIC DEPLOY FACTORY
     * ------------------------------------------------------------
     *
     * Bootstrap a fully configured Sentinel instance from a config array.
     *
     * Expected $config structure:
     *
     * $config = [
     *   'repositories' => [
     *       'users'       => UserRepositoryInterface|callable,        // required
     *       'activations' => ActivationRepositoryInterface|callable,  // required
     *   ],
     *   'hasher' => PasswordHasherInterface|callable|'native'|null,   // optional (default 'native')
     *   'logger' => Psr\Log\LoggerInterface|callable,                 // optional
     * ];
     *
     * Notes:
     * - Repositories and hasher can be provided as concrete instances
     *   or as callables/factories returning those instances.
     * - No database credentials or connection setup is handled here.
     *
     * Returns the built instance AND stores it in a static property,
     * making facade-style calls (Sentinel::users(), etc.) available.
     *
     * @param array $config
     *
     * @return self
     */
    public static function deploy(array $config) {

        if (!isset($config['repositories']['users']) || !isset($config['repositories']['activations'])) {

            throw new \InvalidArgumentException(
                'Missing repositories.users or repositories.activations in config.'
            );
        }

        // Resolve repositories (instance or factory)
        $userRepository         = self::resolveValue($config['repositories']['users']);
        $activationRepository   = self::resolveValue($config['repositories']['activations']);

        if (!($userRepository instanceof UserRepositoryInterface)) {

            throw new \InvalidArgumentException(
                'repositories.users must implement UserRepositoryInterface.'
            );
        }

        if (!($activationRepository instanceof ActivationRepositoryInterface)) {

            throw new \InvalidArgumentException(
                'repositories.activations must implement ActivationRepositoryInterface.'
            );
        }

        // Resolve password hasher
        if (!isset($config['hasher']) || $config['hasher'] === 'native' || $config['hasher'] === null) {

            $passwordHasher = new NativePasswordHasher();

        } else {

            $passwordHasher = self::resolveValue($config['hasher']);
        }

        if (!($passwordHasher instanceof PasswordHasherInterface)) {

            throw new \InvalidArgumentException(
                'hasher must implement PasswordHasherInterface or be "native".'
            );
        }

        // Resolve optional logger
        $logger = null;

        if (isset($config['logger'])) {

            $resolvedLogger = self::resolveValue($config['logger']);

            if ($resolvedLogger instanceof LoggerInterface) {

                $logger = $resolvedLogger;

            } else {

                throw new \InvalidArgumentException('logger must implement Psr\Log\LoggerInterface.');
            }
        }


        // Build via existing builder
        $builder = Builder::create()
            ->withUserRepository($userRepository)
            ->withActivationRepository($activationRepository)
            ->withPasswordHasher($passwordHasher);

        // Tilføj kun logger hvis en faktisk instans blev givet
        if ($logger !== null) {

            $builder->withLogger($logger);
        }

        $instance = $builder->build();

        // Expose a global instance for static facade-style calls
        self::$instance = $instance;

        return $instance;
    }

    /**
     * Resolve a direct instance or execute a factory callable.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    private static function resolveValue($value) {

        if (is_callable($value)) {

            return $value();
        }

        return $value;
    }

    /**
     * ------------------------------------------------------------
     *  FACADE-STYLE STATIC SHORTCUTS
     * ------------------------------------------------------------
     */

    /**
     * Get the global Sentinel instance previously set by deploy().
     *
     * @return self
     */
    public static function instance() {

        if (!self::$instance) {

            throw new \RuntimeException('Sentinel::deploy() has not been called yet.');
        }

        return self::$instance;
    }

    /**
     * Repository shortcut (singular): user() → users repository.
     *
     * @return UserRepositoryInterface
     */
    public static function user() {

        return self::instance()->userRepository;
    }

    /**
     * Repository shortcut (plural): users() → users repository.
     *
     * @return UserRepositoryInterface
     */
    public static function users() {

        return self::instance()->userRepository;
    }

    /**
     * Repository shortcut (singular): activation() → activations repository.
     *
     * @return ActivationRepositoryInterface
     */
    public static function activation() {

        return self::instance()->activationRepository;
    }

    /**
     * Repository shortcut (plural): activations() → activations repository.
     *
     * @return ActivationRepositoryInterface
     */
    public static function activations() {

        return self::instance()->activationRepository;
    }

    /**
     * Shortcut to the configured password hasher.
     *
     * @return PasswordHasherInterface
     */
    public static function hasher() {

        return self::instance()->passwordHasher;
    }

    /**
     * ------------------------------------------------------------
     *  ACTIVATION METHODS (instance API)
     * ------------------------------------------------------------
     */

    /**
     * Ensure an activation record exists for a user and return its code.
     *
     * @param UserInterface $user
     *
     * @return string
     */
    public function ensureActivationCode(UserInterface $user) {

        $openActivation = $this->activationRepository->findOpenByUser($user);

        if ($openActivation) {

            if ($this->logger) {

                $this->logger->info('Sentinel: reused existing activation code for user', [
                    'user_id' => $user->getId(),
                ]);
            }

            return $openActivation->getCode();
        }

        // Create new activation
        $createdActivation = $this->activationRepository->create($user);

        if ($this->logger) {

            $this->logger->info('Sentinel: created activation code for user', [
                'user_id' => $user->getId(),
            ]);
        }

        return $createdActivation->getCode();
    }

    /**
     * Complete activation by code. Returns false if invalid or already completed.
     *
     * @param string $activationCode
     *
     * @return bool
     */
    public function activateByCode($activationCode) {

        $activationRecord = $this->activationRepository->findByCode($activationCode);

        if (!$activationRecord) {

            if ($this->logger) {

                $this->logger->warning('Sentinel: activation code not found', [
                    'code' => $activationCode,
                ]);
            }

            return false;
        }

        if ($activationRecord->isCompleted()) {

            if ($this->logger) {

                $this->logger->notice('Sentinel: activation code already used', [
                    'code' => $activationCode,
                ]);
            }

            return false;
        }

        $user = $this->userRepository->findById($activationRecord->getUserId());

        if (!$user) {

            if ($this->logger) {

                $this->logger->error('Sentinel: activation found but user missing', [
                    'code'    => $activationCode,
                    'user_id' => $activationRecord->getUserId(),
                ]);
            }

            return false;
        }

        $completed = $this->activationRepository->complete($user, $activationCode);

        if ($this->logger) {

            $this->logger->info('Sentinel: activation completed', [
                'code'    => $activationCode,
                'user_id' => $user->getId(),
                'result'  => $completed,
            ]);
        }

        return $completed;
    }

    /**
     * ------------------------------------------------------------
     *  PASSWORD HELPERS (instance API)
     * ------------------------------------------------------------
     */

    /**
     * @param string $plainPassword
     *
     * @return string
     */
    public function hashPassword($plainPassword) {

        return $this->passwordHasher->hash($plainPassword);
    }

    /**
     * @param string $plainPassword
     * @param string $storedHash
     *
     * @return bool
     */
    public function verifyPassword($plainPassword, $storedHash) {

        return $this->passwordHasher->verify($plainPassword, $storedHash);
    }

    /**
     * @param string $storedHash
     *
     * @return bool
     */
    public function passwordNeedsRehash($storedHash) {

        return $this->passwordHasher->needsRehash($storedHash);
    }

    /**
     * ------------------------------------------------------------
     *  ACCESSORS (instance API)
     * ------------------------------------------------------------
     */

    /**
     * @return UserRepositoryInterface
     */
//    public function users() {
//
//        return $this->userRepository;
//    }

    /**
     * @return ActivationRepositoryInterface
     */
//    public function activations() {
//
//        return $this->activationRepository;
//    }

    /**
     * Optional: expose logger if needed elsewhere.
     *
     * @return LoggerInterface|null
     */
    public function logger() {

        return $this->logger;
    }
}