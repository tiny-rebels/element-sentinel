<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * EloquentPermissionItem
 *
 * Eloquent model representing a single row in the "permissions_items" table.
 */
class EloquentPermissionItem extends Model {

    /** @var string */
    protected $table = 'permissions_items';

    /**
     * Specify which columns are mass-assignable.
     *
     * @var string[]
     */
    protected $fillable = [

        'permission_id',
        'permission_type',
        'name',
        'view',
        'create',
        'update',
        'delete',
    ];

    /**
     * Hide selected attributes when array/JSON casting.
     *
     * @var string[]
     */
    protected $hidden = [

        'created_at',
        // add fields here if you want to hide more
    ];

    /** @var bool */
    public $timestamps = true;

    /**
     * Optionally cast boolean-like columns, if these are stored as tinyint(1).
     *
     * @var array<string,string>
     */
    protected $casts = [

        'view'   => 'boolean',
        'create' => 'boolean',
        'update' => 'boolean',
        'delete' => 'boolean',
    ];

    /**
     * Inverse relation: the parent Permission this item belongs to.
     *
     * @return BelongsTo
     */
    public function permission(): BelongsTo {

        // FK on this table: permission_id
        // Owner key on permissions table: id
        return $this->belongsTo(EloquentPermission::class, 'permission_id', 'id');
    }
}
