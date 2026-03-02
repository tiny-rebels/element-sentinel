<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\RoleInterface;

use Illuminate\Database\Eloquent\Model;

use Illuminate\Database\Eloquent\Relations\{
    BelongsToMany,
    HasMany
};

class EloquentRole extends Model implements RoleInterface {

    /** @var string */
    protected $table = 'roles';

    /** @var string[] */
    protected $fillable = ['slug', 'name'];

    /** @var bool */
    public $timestamps = true;

    public function getId() {

        return $this->getKey();
    }

    public function getSlug(): string {

        return (string) $this->slug;
    }

    public function getName(): string {

        return (string) $this->name;
    }

    /**
     * One-to-many: permissions owned directly by this role (role-based).
     *
     * NOTE: The foreign key column on "permissions" is named "role".
     *
     * @return HasMany
     */
    public function permissions(): HasMany {

        return $this->hasMany(\Element\Sentinel\Infrastructure\Eloquent\EloquentPermission::class, 'role');
    }
}
