<?php

namespace Element\Sentinel;

use Element\Sentinel\Contracts\{
    ActivationRepositoryInterface,
    PasswordHasherInterface,
    UserRepositoryInterface
};

use Psr\Log\LoggerInterface;

/**
 * Fluent builder for constructing a Sentinel instance from concrete dependencies.
 */
final class Builder {

    /** @var UserRepositoryInterface|null */
    private $users;

    /** @var ActivationRepositoryInterface|null */
    private $activations;

    /** @var PasswordHasherInterface|null */
    private $hasher;

    /** @var LoggerInterface|null */
    private $logger;

    /**
     * @return self
     */
    public static function create() {

        return new self();
    }

    /**
     * @param UserRepositoryInterface $repo
     *
     * @return self
     */
    public function withUserRepository(UserRepositoryInterface $repo) {

        $this->users = $repo;

        return $this;
    }

    /**
     * @param ActivationRepositoryInterface $repo
     *
     * @return self
     */
    public function withActivationRepository(ActivationRepositoryInterface $repo) {

        $this->activations = $repo;

        return $this;
    }

    /**
     * @param PasswordHasherInterface $hasher
     *
     * @return self
     */
    public function withPasswordHasher(PasswordHasherInterface $hasher) {

        $this->hasher = $hasher;

        return $this;
    }

    /**
     * Optional PSR-3 logger.
     *
     * @param LoggerInterface $logger
     *
     * @return self
     */
    public function withLogger(LoggerInterface $logger) {

        $this->logger = $logger;

        return $this;
    }

    /**
     * @return Sentinel
     */
    public function build() {

        if (!$this->users || !$this->activations || !$this->hasher) {

            throw new \LogicException('Builder: users, activations and hasher must be provided before build().');
        }

        return new Sentinel($this->users, $this->activations, $this->hasher, $this->logger);
    }
}