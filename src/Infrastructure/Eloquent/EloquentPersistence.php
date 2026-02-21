<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Illuminate\Database\Eloquent\Model;

/**
 * EloquentPersistence
 *
 * Eloquent model for remember-me tokens.
 */
class EloquentPersistence extends Model {

    /** @var string */
    protected $table = 'persistences';

    /** @var bool */
    public $timestamps = false;

    /** @var string[] */
    protected $fillable = [

        'user_id',
        'code',
        'created_at',
        'last_used',
    ];

    /** @var array<string,string> */
    protected $casts = [

        'created_at' => 'datetime',
        'last_used'  => 'datetime',
    ];
}
