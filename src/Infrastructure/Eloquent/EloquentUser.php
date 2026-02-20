<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\UserInterface;

use Illuminate\Database\Eloquent\Model;

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
}