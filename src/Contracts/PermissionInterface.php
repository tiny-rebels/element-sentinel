<?php

namespace Element\Sentinel\Contracts;

/**
 * PermissionInterface
 *
 * Minimal contract for a Permission entity.
 */
interface PermissionInterface {

    /**
     * Primary key.
     *
     * @return int|string
     */
    public function getId();

    /**
     * Machine-friendly identifier (e.g., "orders.view").
     *
     * @return string
     */
    public function getSlug(): string;

    /**
     * Human-friendly display name.
     *
     * @return string
     */
    public function getName(): string;
}
