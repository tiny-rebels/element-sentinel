<?php

namespace Element\Sentinel\Contracts;

interface ActivationRepositoryInterface {

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface
     */
    public function create(UserInterface $user);

    /**
     * @param UserInterface $user
     *
     * @return bool
     */
    public function exists(UserInterface $user);

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface|null
     */
    public function findOpenByUser(UserInterface $user);

    /**
     * @param string $code
     *
     * @return ActivationInterface|null
     */
    public function findByCode($code);

    /**
     * @param UserInterface $user
     * @param string $code
     *
     * @return bool
     */
    public function complete(UserInterface $user, $code);

}