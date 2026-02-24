<?php

namespace Element\Sentinel\Services\Security;

use Element\Sentinel\Contracts\ThrottleRepositoryInterface;

/**
 * ThrottleCheckpoint
 *
 * A login-flow checkpoint that enforces throttling across the following scopes:
 *  - "global": shared across the entire system
 *  - "ip":     per caller IP address
 *  - "user":   per identified user identifier (string)
 *
 * The checkpoint may be globally enabled/disabled via the constructor.
 */
final class ThrottleCheckpoint {

    /** @var ThrottleRepositoryInterface */
    private $throttleRepository;

    /** @var bool */
    private $enabled;

    /**
     * @param ThrottleRepositoryInterface $throttleRepository
     * @param bool                        $enabled
     */
    public function __construct(ThrottleRepositoryInterface $throttleRepository, bool $enabled = true) {

        $this->throttleRepository = $throttleRepository;
        $this->enabled = $enabled;
    }

    /**
     * Guard the login flow by throwing when any scope is currently suspended.
     *
     * @param string|null $userIdentifier  If known, pass the user id or another stable identifier. Otherwise null.
     * @param string      $ipAddress       Caller IP address, e.g. from $_SERVER['REMOTE_ADDR'].
     *
     * @throws \RuntimeException           When suspended at any scope (global, ip, user).
     *
     * @return void
     */
    public function check(?string $userIdentifier, string $ipAddress): void {

        if (!$this->enabled) {

            return;
        }

        // Global scope
        if ($this->throttleRepository->isSuspended('global', '*')) {

            $seconds = $this->throttleRepository->availableIn('global', '*');

            throw new \RuntimeException('Too many attempts (global). Try again in ' . $seconds . ' seconds.');
        }

        // IP scope
        if ($this->throttleRepository->isSuspended('ip', $ipAddress)) {

            $seconds = $this->throttleRepository->availableIn('ip', $ipAddress);

            throw new \RuntimeException('Too many attempts (ip). Try again in ' . $seconds . ' seconds.');
        }

        // User scope (when known)
        if ($userIdentifier !== null && $this->throttleRepository->isSuspended('user', $userIdentifier)) {

            $seconds = $this->throttleRepository->availableIn('user', $userIdentifier);

            throw new \RuntimeException('Too many attempts (user). Try again in ' . $seconds . ' seconds.');
        }
    }

    /**
     * Record a failed login attempt across global/ip and, when provided, user scopes.
     *
     * @param string|null $userIdentifier
     * @param string      $ipAddress
     *
     * @return void
     */
    public function hit(?string $userIdentifier, string $ipAddress): void {

        if (!$this->enabled) {

            return;
        }

        $this->throttleRepository->hit('global', '*');
        $this->throttleRepository->hit('ip', $ipAddress);

        if ($userIdentifier !== null) {

            $this->throttleRepository->hit('user', $userIdentifier);
        }
    }

    /**
     * Clear counters and suspensions after a successful login (ip and user scopes).
     *
     * @param string|null $userIdentifier
     * @param string      $ipAddress
     *
     * @return void
     */
    public function clear(?string $userIdentifier, string $ipAddress): void {

        if (!$this->enabled) {

            return;
        }

        // Typically clear IP and user scopes. Global can be left to decay or cleared via maintenance.
        $this->throttleRepository->clear('ip', $ipAddress);

        if ($userIdentifier !== null) {

            $this->throttleRepository->clear('user', $userIdentifier);
        }
    }
}
