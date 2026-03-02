<?php

namespace Element\Sentinel\Services\Exceptions\Auth;

/**
 * Base class for authentication-related exceptions.
 *
 * Carries an optional context array for structured logging / responses.
 */
class BaseException extends \RuntimeException {

    /** @var array<string,mixed> */
    protected $context = [];

    /**
     * @param string              $message
     * @param int                 $code
     * @param \Throwable|null     $previous
     * @param array<string,mixed> $context
     */
    public function __construct(string $message = '', int $code = 0, \Throwable $previous = null, array $context = []) {

        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /**
     * Structured context for logging / error responses.
     *
     * @return array<string,mixed>
     */
    public function getContext(): array {

        return $this->context;
    }
}
