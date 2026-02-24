<?php

namespace Element\Sentinel\Contracts;

interface PasswordHasherInterface {

    /**
     * @param string $password
     *
     * @return string
     */
    public function hash(string $password): string;

    /**
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public function verify(string $password, string $hash): bool;

    /**
     * @param string $hash
     *
     * @return bool
     */
    public function needsRehash(string $hash): bool;

}
