<?php

namespace Element\Sentinel\Services\Exceptions\Throttle;

/**
 * ThrottlingException
 *
 * Base exception for throttling-related errors (suspensions, lockouts, rate limits).
 * Concrete subclasses capture specific scenarios and may expose additional context
 * such as remaining suspension seconds.
 */
class BaseException extends \RuntimeException {

    /**
     * @var array
     */
    protected $context = [];

    /**
     * @param string $message
     * @param int $code
     * @param \Throwable|null $previous
     * @param array $context
     */
    public function __construct($message = '', $code = 0, \Throwable $previous = null, array $context = []) {

        parent::__construct($message, $code, $previous);

        $this->context = $context;
    }

    /**
     * @return array
     */
    public function getContext(): array {

        return $this->context;
    }
}
