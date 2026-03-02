<?php

namespace Element\Sentinel\Services\Exceptions\Throttle;

/**
 * ThrottlingSuspendedException
 *
 * Thrown when a subject (IP or user) is currently suspended by the throttle policy.
 * Provides the remaining suspension time (in seconds) when available.
 */
class ThrottlingSuspendedException extends BaseException {

    /**
     * @return int|null Remaining suspension seconds, if available.
     */
    public function getRemainingSuspensionSeconds(): ?int {

        $context = $this->getContext();

        return isset($context['remaining_seconds']) ? (int)$context['remaining_seconds'] : null;
    }
}
