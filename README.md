# Element Sentinel
A framework‑agnostic authentication & activation library for PHP 7+


<!-- Badges -->
![Packagist Version](https://img.shields.io/packagist/v/element/sentinel?style=flat-square)
![Total Downloads](https://img.shields.io/packagist/dt/element/sentinel?style=flat-square)
![PHP Version](https://img.shields.io/packagist/php-v/element/sentinel?style=flat-square)
![License](https://img.shields.io/github/license/element3php/sentinel?style=flat-square)


Element Sentinel is a simple, stable and flexible authentication component designed to work in **any PHP 7.x project** — including custom frameworks such as *Element3*.

The library provides:
- User activation through activation codes
- Repository implementations for **PDO** and **Eloquent**
- A clean and minimal **Sentinel core** for activation, hashing, and storage
- Plain SQL migration files (no dependency on Laravel migrations)
- A fully framework‑agnostic architecture (no routing, middleware, etc.)

The goal is to deliver a **minimalistic** yet **robust** authentication component that is easy to integrate without forcing any particular structure or framework.

---

## 🚀 Installation

Install via Composer:

```bash
composer require element/sentinel
```

## 🧩 Instantiating Sentinel

Element Sentinel is instantiated through a fluent builder, allowing you to plug in your preferred storage layer (PDO or Eloquent) as well as the password hasher.
This makes Sentinel fully flexible and framework‑agnostic.
Below are two recommended setups.

### 🔌 Using PDO

```bash
use PDO;
use Element\Sentinel\SentinelBuilder;
use Element\Sentinel\Support\NativePasswordHasher;
use Element\Sentinel\Infrastructure\PDO\PdoUserRepository;
use Element\Sentinel\Infrastructure\PDO\PdoActivationRepository;

$pdoConnection = new PDO(
    'mysql:host=localhost;dbname=myapp;charset=utf8mb4',
    'username',
    'password',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]
);

$sentinel = Builder::create()
    ->withUserRepository(new PdoUserRepository($pdoConnection))
    ->withActivationRepository(new PdoActivationRepository($pdoConnection))
    ->withPasswordHasher(new NativePasswordHasher())
    ->build();
```

or by

### 🏗 Using Eloquent (Capsule)

```bash
use Illuminate\Database\Capsule\Manager as Capsule;
use Element\Sentinel\SentinelBuilder;
use Element\Sentinel\Support\NativePasswordHasher;
use Element\Sentinel\Infrastructure\Eloquent\EloquentUserRepository;
use Element\Sentinel\Infrastructure\Eloquent\EloquentActivationRepository;

$capsule = new Capsule();
$capsule->addConnection([
    'driver'    => 'mysql',
    'host'      => 'localhost',
    'database'  => 'myapp',
    'username'  => 'username',
    'password'  => 'password',
]);

$capsule->setAsGlobal();
$capsule->bootEloquent();

$sentinel = Builder::create()
    ->withUserRepository(new EloquentUserRepository())
    ->withActivationRepository(new EloquentActivationRepository())
    ->withPasswordHasher(new NativePasswordHasher())
    ->build();
```