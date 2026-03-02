<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use app\models\auth\PermissionItems;
use Element\Sentinel\Contracts\PermissionInterface;
use Element\Sentinel\In;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * EloquentPermission
 *
 * Eloquent model for "permissions" table.
 */
class EloquentPermission extends Model implements PermissionInterface {

    /** @var string */
    protected $table = 'permissions';

    /** @var string[] */
    protected $fillable = ['slug', 'name'];

    /** @var bool */
    public $timestamps = true;

    /**
     * {@inheritdoc}
     */
    public function getId() {

        return $this->getKey();
    }

    /**
     * {@inheritdoc}
     */
    public function getSlug(): string {

        return (string) $this->slug;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string {

        return (string) $this->name;
    }


    /**
     * One-to-many: child items belonging to this permission.
     *
     * @return HasMany
     */
    public function items(): HasMany {

        return $this->hasMany(EloquentPermissionItem::class, 'permission_id', 'id')->orderBy('name', 'asc');
    }

}
