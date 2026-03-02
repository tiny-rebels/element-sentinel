<?php

namespace Element\Sentinel\Contracts;

interface ThrottleRepositoryInterface {

    /**
     * Record a failed attempt for the given scope+key.
     * Returns seconds remaining until next allowed attempt (0 if allowed right now).
     *
     * @param string $scope   'global'|'ip'|'user'
     * @param string $key     normalized key (e.g., '*' for global, IP string, or user id as string)
     *
     * @return int  Seconds to free (0 means not throttled right now)
     */
    public function hit(string $scope, string $key): int;

    /**
     * Return true if the given scope+key is currently suspended.
     */
    public function isSuspended(string $scope, string $key): bool;

    /**
     * Return the seconds remaining until next allowed attempt for scope+key.
     */
    public function availableIn(string $scope, string $key): int;

    /**
     * Reset counters or suspension for the given scope+key (on successful login).
     */
    public function clear(string $scope, string $key): void;
}
