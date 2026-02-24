<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\UserInterface;

use Illuminate\Database\Eloquent\Model;

use Illuminate\Database\Eloquent\Relations\{
    BelongsToMany,
    HasMany
};

/**
 * Eloquent model implementation for User records.
 */
class EloquentUser extends Model implements UserInterface {

    /** @var string */
    protected $table = 'users';

    /** @var string[] */
    protected $fillable = [

        'email',
        'password',
        'is_activated',
    ];

    /** @var bool */
    public $timestamps = true;

    /** @return int|string|null */
    public function getId() {

        return $this->getKey();
    }

    /** @return bool */
    public function isActivated() {

        return (bool) $this->is_activated;
    }

    /** @return void */
    public function markActivated() {

        $this->is_activated = 1;
    }


    /**
     * Many-to-many: roles for this user.
     *
     * @return BelongsToMany
     */
    public function roles(): BelongsToMany {

        return $this->belongsToMany(\Element\Sentinel\Infrastructure\Eloquent\EloquentRole::class, 'users_roles', 'user_id', 'role_id');
    }

    /**
     * One-to-many: permissions owned directly by this user (user-based).
     *
     * NOTE: The foreign key column on "permissions" is named "user".
     *
     * @return HasMany
     */
    public function permissions(): HasMany {

        return $this->hasMany(\Element\Sentinel\Infrastructure\Eloquent\EloquentPermission::class, 'user');
    }
}
