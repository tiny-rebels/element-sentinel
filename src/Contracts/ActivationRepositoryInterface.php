<?php

namespace Element\Sentinel\Contracts;

interface ActivationRepositoryInterface {

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface
     */
    public function create(UserInterface $user): ActivationInterface;

    /**
     * @param UserInterface $user
     *
     * @return bool
     */
    public function exists(UserInterface $user): bool;

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface|null
     */
    public function findOpenByUser(UserInterface $user): ?ActivationInterface;

    /**
     * @param string $code
     *
     * @return ActivationInterface|null
     */
    public function findByCode(string $code): ?ActivationInterface;

    /**
     * @param UserInterface $user
     * @param string $code
     *
     * @return bool
     */
    public function complete(UserInterface $user, string $code): bool;

}
