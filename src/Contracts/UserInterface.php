<?php

namespace Element\Sentinel\Contracts;

interface UserInterface {

    /**
     * @return int|string
     */
    public function getId();

    /**
     * @return bool
     */
    public function isActivated();

    /**
     * @return void
     */
    public function markActivated();

}