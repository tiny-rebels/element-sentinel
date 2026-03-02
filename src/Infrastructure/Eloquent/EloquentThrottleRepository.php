<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\ThrottleRepositoryInterface;
use Element\Sentinel\Infrastructure\Policies\ThrottlePolicy;

use Illuminate\Database\Capsule\Manager as DB;

class EloquentThrottleRepository implements ThrottleRepositoryInterface {

    /** @var string */
    private $throttleTableName;

    /** @var ThrottlePolicy */
    private $globalPolicy;

    /** @var ThrottlePolicy */
    private $ipPolicy;

    /** @var ThrottlePolicy */
    private $userPolicy;

    public function __construct(
        string $throttleTableName,
        ThrottlePolicy $globalPolicy,
        ThrottlePolicy $ipPolicy,
        ThrottlePolicy $userPolicy
    ) {
        $this->throttleTableName = $throttleTableName;
        $this->globalPolicy      = $globalPolicy;
        $this->ipPolicy          = $ipPolicy;
        $this->userPolicy        = $userPolicy;
    }

    /**
     * @param string $scope
     * @param string $key
     *
     * @return int
     */
    public function hit(string $scope, string $key): int {

        $policy = $this->policyForScope($scope);
        $nowDateTime = date('Y-m-d H:i:s');
        $nowUnix = time();

        $row = DB::table($this->throttleTableName)->where('scope', '=', $scope)->where('key_hash', '=', $key)->first();

        if (!$row) {

            DB::table($this->throttleTableName)->insert([
                'scope'           => $scope,
                'key_hash'        => $key,
                'attempts'        => 1,
                'last_attempt_at' => $nowDateTime,
                'suspended_until' => null,
            ]);

            return 0;
        }

        if ($row->suspended_until && strtotime((string) $row->suspended_until) > $nowUnix) {

            return max(1, strtotime((string) $row->suspended_until) - $nowUnix);
        }

        $lastAttemptUnix = $row->last_attempt_at ? strtotime((string) $row->last_attempt_at) : null;
        $attempts = (int) $row->attempts;

        if ($lastAttemptUnix === null || ($nowUnix - $lastAttemptUnix) > $policy->intervalSeconds()) {

            $attempts = 0;
        }

        $attempts++;
        $suspensionSeconds = $policy->resolveSuspensionSecondsForAttempts($attempts);

        $updateData = [

            'attempts'        => $attempts,
            'last_attempt_at' => $nowDateTime,
            'suspended_until' => $suspensionSeconds > 0 ? date('Y-m-d H:i:s', $nowUnix + $suspensionSeconds) : null,
        ];

        DB::table($this->throttleTableName)->where('id', '=', $row->id)->update($updateData);

        return $suspensionSeconds;
    }

    /**
     * @param string $scope
     * @param string $key
     *
     * @return bool
     */
    public function isSuspended(string $scope, string $key): bool {

        $until = DB::table($this->throttleTableName)->where('scope', '=', $scope)->where('key_hash', '=', $key)->value('suspended_until');

        return $until !== null && strtotime((string) $until) > time();
    }

    /**
     * @param string $scope
     * @param string $key
     *
     * @return int
     */
    public function availableIn(string $scope, string $key): int {

        $until = DB::table($this->throttleTableName)->where('scope', '=', $scope)->where('key_hash', '=', $key)->value('suspended_until');

        if ($until === null) {

            return 0;
        }

        $remaining = strtotime((string) $until) - time();

        return max($remaining, 0);
    }

    /**
     * @param string $scope
     * @param string $key
     *
     * @return void
     */
    public function clear(string $scope, string $key): void {

        $row = DB::table($this->throttleTableName)->where('scope', '=', $scope)->where('key_hash', '=', $key)->first();

        if ($row) {

            DB::table($this->throttleTableName)->where('id', '=', $row->id)->update([
                'attempts'        => 0,
                'last_attempt_at' => null,
                'suspended_until' => null,
            ]);
        }
    }

    /**
     * @param string $scope
     *
     * @return ThrottlePolicy
     */
    private function policyForScope(string $scope): ThrottlePolicy {

        switch ($scope) {

            case 'global': return $this->globalPolicy;
            case 'ip':     return $this->ipPolicy;
            case 'user':   return $this->userPolicy;
        }

        return $this->globalPolicy;
    }
}
