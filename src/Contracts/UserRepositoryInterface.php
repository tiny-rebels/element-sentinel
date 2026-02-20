<?php

namespace Element\Sentinel\Contracts;

interface UserRepositoryInterface {

    /**
     * @param int|string $id
     *
     * @return UserInterface|null
     */
    public function findById($id);

    /**
     * @param UserInterface $user
     *
     * @return void
     */
    public function save(UserInterface $user);

}