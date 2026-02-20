<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\ActivationInterface;

use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent model implementation for Activation records.
 */
class EloquentActivation extends Model implements ActivationInterface {

    /** @var string */
    protected $table = 'activations';

    /** @var bool */
    public $timestamps = false;

    /** @var string[] */
    protected $fillable = [

        'user_id',
        'code',
        'completed',
        'completed_at',
        'created_at',
    ];

    /** @var string[] */
    protected $casts = [

        'completed'     => 'boolean',
        'completed_at'  => 'datetime',
        'created_at'    => 'datetime',
    ];

    /** @return int|string */
    public function getUserId() {

        return $this->user_id;
    }

    /** @return string */
    public function getCode(){

        return $this->code;
    }

    /** @return bool */
    public function isCompleted() {

        return !is_null($this->completed_at);
    }
}