<?php

namespace Element\Sentinel\Infrastructure\Eloquent;

use Element\Sentinel\Contracts\PersistenceRepositoryInterface;
use Element\Sentinel\Support\CodeGenerator;

/**
 * EloquentPersistenceRepository
 *
 * Stores a random token per "remember-me" and sets a cookie for framework-agnostic usage.
 */
class EloquentPersistenceRepository implements PersistenceRepositoryInterface {

    /** @var string */
    private $cookieName;

    /** @var int */
    private $cookieLifetimeSeconds;

    /** @var string */
    private $cookiePath;

    /** @var string|null */
    private $cookieDomain;

    /** @var bool */
    private $cookieSecure;

    /** @var bool */
    private $cookieHttpOnly;

    /** @var string|null Lax|Strict|None */
    private $cookieSameSite;

    /**
     * @param string $cookieName
     * @param int $cookieLifetimeSeconds
     * @param string $cookiePath
     * @param string|null $cookieDomain
     * @param bool|null $cookieSecure
     * @param bool $cookieHttpOnly
     * @param string|null $cookieSameSite
     */
    public function __construct(string $cookieName = 'element_sentinel', int $cookieLifetimeSeconds = 2592000, string $cookiePath = '/', string $cookieDomain = null, bool   $cookieSecure = null, bool   $cookieHttpOnly = true, ?string $cookieSameSite = 'Lax') {

        $this->cookieName            = (string) $cookieName;
        $this->cookieLifetimeSeconds = (int) $cookieLifetimeSeconds;
        $this->cookiePath            = (string) $cookiePath;
        $this->cookieDomain          = $cookieDomain !== null ? (string) $cookieDomain : null;
        $this->cookieSecure          = ($cookieSecure !== null) ? (bool) $cookieSecure : (!empty($_SERVER['HTTPS']));
        $this->cookieHttpOnly        = (bool) $cookieHttpOnly;
        $this->cookieSameSite        = $cookieSameSite !== null ? (string) $cookieSameSite : null;
    }

    /**
     * {@inheritdoc}
     */
    public function remember($userId): void {

        $token = CodeGenerator::random(32); // or 64

        EloquentPersistence::query()->create([

            'user_id'   => $userId,
            'code'      => $token,
            'last_used' => date('Y-m-d H:i:s'),
        ]);

        $this->setCookie($token, time() + $this->cookieLifetimeSeconds);
    }

    /**
     * {@inheritdoc}
     */
    public function userIdFromRememberCookie() {

        $token = $_COOKIE[$this->cookieName] ?? null;

        if (!$token || !is_string($token)) {

            return null;
        }

        $row = EloquentPersistence::query()->where('code', '=', $token)->first();

        if (!$row) {

            // Stale cookie -> clear it
            $this->setCookie('', time() - 3600);

            return null;
        }

        // Touch last_used
        $row->last_used = date('Y-m-d H:i:s');
        $row->save();

        return $row->user_id;
    }

    /**
     * {@inheritdoc}
     */
    public function forgetCurrent(): void {

        $token = $_COOKIE[$this->cookieName] ?? null;

        if ($token && is_string($token)) {

            EloquentPersistence::query()->where('code', '=', $token)->delete();
        }

        $this->setCookie('', time() - 3600);
    }

    /**
     * {@inheritdoc}
     */
    public function forgetUser($userId): void {

        EloquentPersistence::query()->where('user_id', '=', $userId)->delete();

        // Also clear current browser cookie if present
        $this->setCookie('', time() - 3600);
    }

    /**
     * Set or clear the remember cookie.
     *
     * @param string $value
     * @param int    $expires
     *
     * @return void
     */
    private function setCookie($value, $expires): void {

        $params = [

            'expires'  => $expires,
            'path'     => $this->cookiePath,
            'domain'   => $this->cookieDomain,
            'secure'   => $this->cookieSecure,
            'httponly' => $this->cookieHttpOnly,
            'samesite' => $this->cookieSameSite ?: 'Lax',
        ];

        setcookie($this->cookieName, $value, $params);
    }

    /**
     * {@inheritdoc}
     */
    public function forgetCookie(): void {

        // Idempotent cookie clear – delete regardless of presence
        // If you need SameSite=None for cross-site contexts, change 'Lax' accordingly
        setcookie($this->cookieName, '', [

            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => !empty($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
