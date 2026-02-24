<?php

namespace Element\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * Validator
 *
 * Centralized validators for pluggable model classes used by the library.
 * Each method throws an InvalidArgumentException with a clear message
 * when the provided class name does not satisfy the expected constraints.
 */
final class Validator {

    /**
     * Ensure a configured User model is an Eloquent Model and implements the required UserInterface.
     *
     * @param string $userModelClass
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function validateUserModel(string $userModelClass): void {

        if (!class_exists($userModelClass)) {

            throw new \InvalidArgumentException('Configured user model class not found: ' . $userModelClass);
        }

        if (!is_subclass_of($userModelClass, Model::class)) {

            throw new \InvalidArgumentException('Configured user model must extend Illuminate\Database\Eloquent\Model: ' . $userModelClass);
        }

        if (!in_array(\Element\Sentinel\Contracts\UserInterface::class, class_implements($userModelClass), true)) {

            throw new \InvalidArgumentException(
                'Configured user model must implement Element\Sentinel\Contracts\UserInterface: ' . $userModelClass
            );
        }
    }

    /**
     * Ensure a configured Role model is an Eloquent Model and implements the required RoleInterface.
     *
     * @param string $roleModelClass
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function validateRoleModel(string $roleModelClass): void {

        if (!class_exists($roleModelClass)) {

            throw new \InvalidArgumentException('Configured role model class not found: ' . $roleModelClass);
        }

        if (!is_subclass_of($roleModelClass, Model::class)) {

            throw new \InvalidArgumentException('Configured role model must extend Illuminate\Database\Eloquent\Model: ' . $roleModelClass);
        }

        if (!in_array(\Element\Sentinel\Contracts\RoleInterface::class, class_implements($roleModelClass), true)) {

            throw new \InvalidArgumentException(
                'Configured role model must implement Element\Sentinel\Contracts\RoleInterface: ' . $roleModelClass
            );
        }
    }

    /**
     * Ensure a configured Permission model is an Eloquent Model and implements the required PermissionInterface.
     *
     * @param string $permissionModelClass
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function validatePermissionModel(string $permissionModelClass): void {

        if (!class_exists($permissionModelClass)) {

            throw new \InvalidArgumentException('Configured permission model class not found: ' . $permissionModelClass);
        }

        if (!is_subclass_of($permissionModelClass, Model::class)) {

            throw new \InvalidArgumentException('Configured permission model must extend Illuminate\Database\Eloquent\Model: ' . $permissionModelClass);
        }

        if (!in_array(\Element\Sentinel\Contracts\PermissionInterface::class, class_implements($permissionModelClass), true)) {

            throw new \InvalidArgumentException(
                'Configured permission model must implement Element\Sentinel\Contracts\PermissionInterface: ' . $permissionModelClass
            );
        }
    }
}
