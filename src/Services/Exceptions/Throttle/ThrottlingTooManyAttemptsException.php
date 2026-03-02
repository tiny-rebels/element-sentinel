<?php

namespace Element\Sentinel\Services\Exceptions\Throttle;

/**
 * ThrottlingTooManyAttemptsException
 *
 * Thrown when a subject has exceeded the allowed number of attempts in the configured interval.
 * This may immediately translate into a suspension depending on your throttle policy.
 */
class ThrottlingTooManyAttemptsException extends BaseException {

    //...
}
