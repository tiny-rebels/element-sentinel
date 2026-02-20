<?php

namespace Element\Sentinel\Contracts;

interface ActivationInterface {

    /**
     * @return int|string
     */
    public function getUserId();

    /**
     * @return string
     */
    public function getCode();

    /**
     * @return bool
     */
    public function isCompleted();

}