<?php

namespace Element\Sentinel\Contracts;

/**
 * RoleInterface
 *
 * Minimal contract for a Role entity.
 */
interface RoleInterface {

    /**
     * Primary key.
     *
     * @return int|string
     */
    public function getId();

    /**
     * Machine-friendly slug (e.g., "owner", "sales-man").
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
