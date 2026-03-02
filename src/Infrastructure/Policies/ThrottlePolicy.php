<?php

namespace Element\Sentinel\Infrastructure\Policies;

/**
 * ThrottlePolicy
 *
 * Immutable value object describing how throttling behaves for a scope.
 *
 * Fields:
 *  - intervalSeconds: rolling window in seconds.
 *  - thresholds: either:
 *      a) integer (max attempts in window → fixed suspensionSeconds),
 *      b) associative array [attempts => suspensionMinutes] for escalated backoff.
 *  - suspensionSecondsDefault: used when thresholds is integer (fixed suspension for exceeding max).
 */
final class ThrottlePolicy {

    /** @var int */
    private $intervalSeconds;

    /** @var int|array<int,int>  Map: attempts => suspensionMinutes (if array), or integer maxAttempts */
    private $thresholds;

    /** @var int */
    private $suspensionSecondsDefault;

    /**
     * @param int                $intervalSeconds
     * @param int|array<int,int> $thresholds
     * @param int                $suspensionSecondsDefault
     */
    public function __construct(int $intervalSeconds, $thresholds, int $suspensionSecondsDefault = 60) {

        $this->intervalSeconds = $intervalSeconds;
        $this->thresholds = $thresholds;
        $this->suspensionSecondsDefault = $suspensionSecondsDefault;
    }

    /**
     * Rolling window in seconds.
     *
     * @return int
     */
    public function intervalSeconds(): int {

        return $this->intervalSeconds;
    }

    /**
     * Either integer (max attempts) or map [attempts => minutes].
     *
     * @return int|array<int,int>
     */
    public function thresholds() {

        return $this->thresholds;
    }

    /**
     * Default suspension length (seconds) for integer thresholds.
     *
     * @return int
     */
    public function suspensionSecondsDefault(): int {

        return $this->suspensionSecondsDefault;
    }

    /**
     * Resolve suspension seconds for a given attempts count.
     *
     * Rules:
     *  - If thresholds is int and attempts > max → return default suspension seconds; else 0.
     *  - If thresholds is map (attempts=>minutes): pick the highest key <= attempts and return minutes*60; else 0.
     *
     * @param int $attempts
     *
     * @return int
     */
    public function resolveSuspensionSecondsForAttempts(int $attempts): int {

        if (is_int($this->thresholds)) {

            return ($attempts > $this->thresholds) ? $this->suspensionSecondsDefault : 0;
        }

        $matchedMinutes = 0;

        foreach ($this->thresholds as $minAttempts => $minutes) {

            if ($attempts >= (int) $minAttempts) {

                $matchedMinutes = (int) $minutes;
            }
        }

        return $matchedMinutes > 0 ? $matchedMinutes * 60 : 0;
    }
}
