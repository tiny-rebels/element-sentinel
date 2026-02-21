<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    PasswordHasherInterface,
    PersistenceRepositoryInterface,
    UserRepositoryInterface,
    CredentialsRepositoryInterface
};

use Psr\Log\LoggerInterface;

/**
 * Builder
 *
 * Fluent builder for constructing a fully configured Sentinel instance
 * from concrete dependencies. All parameters are framework-agnostic.
 */
final class Builder {

    /** @var UserRepositoryInterface|null */
    private $userRepository;

    /** @var ActivationRepositoryInterface|null */
    private $activationRepository;

    /** @var PersistenceRepositoryInterface|null */
    private $persistenceRepository;

    /** @var PasswordHasherInterface|null */
    private $passwordHasher;

    /** @var LoggerInterface|null */
    private $logger;

    /** @var CredentialsRepositoryInterface|null */
    private $credentialsRepository;

    /**
     * Create a new builder instance.
     *
     * @return self
     */
    public static function create(): Builder {

        return new self();
    }

    /**
     * Provide a user repository (required).
     *
     * @param UserRepositoryInterface $repository
     * @return self
     */
    public function withUserRepository(UserRepositoryInterface $repository): Builder {

        $this->userRepository = $repository;

        return $this;
    }

    /**
     * Provide an activation repository (required).
     *
     * @param ActivationRepositoryInterface $repository
     *
     * @return self
     */
    public function withActivationRepository(ActivationRepositoryInterface $repository): Builder {

        $this->activationRepository = $repository;

        return $this;
    }

    /**
     * Provide an persistence repository (required).
     *
     * @param PersistenceRepositoryInterface $repository
     *
     * @return self
     */
    public function withPersistenceRepository(PersistenceRepositoryInterface $repository): Builder {

        $this->persistenceRepository = $repository;

        return $this;
    }

    /**
     * Provide a password hasher (required).
     *
     * @param PasswordHasherInterface $hasher
     *
     * @return self
     */
    public function withPasswordHasher(PasswordHasherInterface $hasher): Builder {

        $this->passwordHasher = $hasher;

        return $this;
    }

    /**
     * Provide an optional PSR-3 logger.
     *
     * @param LoggerInterface $logger
     *
     * @return self
     */
    public function withLogger(LoggerInterface $logger): Builder {

        $this->logger = $logger;

        return $this;
    }

    /**
     * Provide an optional credentials repository for login lookup and password hash access.
     *
     * If omitted and the provided UserRepository also implements CredentialsRepositoryInterface,
     * the Sentinel constructor will automatically use that instance.
     *
     * @param CredentialsRepositoryInterface $repository
     *
     * @return self
     */
    public function withCredentialsRepository(CredentialsRepositoryInterface $repository): Builder {

        $this->credentialsRepository = $repository;

        return $this;
    }

    /**
     * Build the Sentinel instance.
     *
     * @return Sentinel
     *
     * @throws \LogicException if required dependencies are missing.
     */
    public function build(): Sentinel {

        if (!$this->userRepository || !$this->activationRepository || !$this->passwordHasher) {

            throw new \LogicException(
                'Builder: users, activations and hasher must be provided before build().'
            );
        }

        return new Sentinel(
            $this->userRepository,
            $this->activationRepository,
            $this->persistenceRepository,
            $this->passwordHasher,
            $this->logger,
            $this->credentialsRepository
        );
    }
}
