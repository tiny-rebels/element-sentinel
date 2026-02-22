<?php

namespace Element\Sentinel\Contracts;

/**
 * AuthManagerInterface
 *
 * Authentication service contract. Framework-agnostic orchestration of:
 * - credentials lookup (email-only in our current setup)
 * - activation checks
 * - password verification + rehash
 * - session hydration and remember-me tokens
 */
interface AuthManagerInterface {

    /**
     * Authenticate a user by email and password.
     *
     * Expected input:
     * [
     *   'email'    => 'user@example.com',
     *   'password' => 'PlainTextOrInput',
     * ]
     *
     * @param array{email:string,password:string} $credentials
     *
     * @param bool $remember         If true, create a remember-me token and cookie.
     *
     * @param bool $requireActivated If true, the user must be activated to log in.
     *
     * @return UserInterface|null
     */
    public function authenticate(array $credentials, bool $remember = false, bool $requireActivated = true): ?UserInterface;

    /**
     * Log out the current user: clear session and remember-me data.
     *
     * @return void
     */
    public function logout(): void;
}
