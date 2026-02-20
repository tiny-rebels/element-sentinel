<?php
namespace Element\Sentinel\Infrastructure\PDO;

use PDO;
use PDOException;

use Element\Sentinel\Contracts\{
    UserInterface,
    UserRepositoryInterface
};

/**
 * PDO-baseret UserRepository.
 *
 * Antager en "users" tabel med kolonner:
 *   id, email, password, activated, created_at, updated_at
 */
class PdoUserRepository implements UserRepositoryInterface {

    /** @var PDO */
    private $pdo;

    /** @var string */
    private $table;

    /**
     * @param PDO    $pdo
     * @param string $table  Navn på users-tabellen (default: "users")
     */
    public function __construct(PDO $pdo, $table = 'users') {

        $this->pdo   = $pdo;
        $this->table = $table;
    }

    /**
     * @param int|string $id
     *
     * @return UserInterface|null
     */
    public function findById($id) {

        $sql = "SELECT id, email, password, activated, created_at, updated_at
                FROM {$this->table}
                WHERE id = :id
                LIMIT 1";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':id', $id);

        if (!$stmt->execute()) {

            return null;
        }

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {

            return null;
        }

        return PdoUser::fromRow($row, $this->pdo, $this->table);
    }

    /**
     * Gemmer/Opdaterer en bruger.
     *
     * @param UserInterface $user
     *
     * @return void
     */
    public function save(UserInterface $user) {

        if (!($user instanceof PdoUser)) {

            // Tillad evt. andre implementationer ved at mappe felter.
            // Her understøtter vi kun PdoUser out-of-the-box for simpelhed.
            $this->upsertGenericUser($user);

            return;
        }

        if ($user->getId() === null) {

            $this->insertUser($user);

        } else {

            $this->updateUser($user);
        }
    }

    /**
     * @param UserInterface $user
     *
     * @return void
     */
    private function upsertGenericUser(UserInterface $user) {

        // Vi antager kun, at vi kan opdatere activated-flaget for generiske brugere.
        // Hvis du vil have fuld kontrol, så brug PdoUser som model i dit kald.
        $sql = "UPDATE {$this->table}
                SET activated = :activated, updated_at = :updated_at
                WHERE id = :id";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':activated', $user->isActivated() ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
        $stmt->bindValue(':id', $user->getId());

        $stmt->execute();
    }

    /**
     * @param PdoUser $user
     *
     * @return void
     */
    private function insertUser(PdoUser $user) {

        $now = date('Y-m-d H:i:s');
        $sql = "INSERT INTO {$this->table} (email, password, activated, created_at, updated_at)
                VALUES (:email, :password, :activated, :created_at, :updated_at)";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':email', $user->email);
        $stmt->bindValue(':password', $user->password);
        $stmt->bindValue(':activated', $user->activated ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(':created_at', $now);
        $stmt->bindValue(':updated_at', $now);

        $stmt->execute();

        $user->id = $this->pdo->lastInsertId();
    }

    /**
     * @param PdoUser $user
     *
     * @return void
     */
    private function updateUser(PdoUser $user) {

        $sql = "UPDATE {$this->table}
                SET email = :email,
                    password = :password,
                    activated = :activated,
                    updated_at = :updated_at
                WHERE id = :id";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':email', $user->email);
        $stmt->bindValue(':password', $user->password);
        $stmt->bindValue(':activated', $user->activated ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
        $stmt->bindValue(':id', $user->id);

        $stmt->execute();
    }
}

/**
 * Simpel PDO-baseret User-model der implementerer UserInterface.
 * Du kan erstatte denne med din egen domain-model hvis ønsket.
 */
class PdoUser implements UserInterface {

    /** @var mixed|null */
    public $id;

    /** @var string|null */
    public $email;

    /** @var string */
    public $password;

    /** @var bool */
    public $activated = false;

    /** @var string|null */
    public $created_at;

    /** @var string|null */
    public $updated_at;

    /** @var PDO */
    private $pdo;

    /** @var string */
    private $table;

    /**
     * @param PDO    $pdo
     * @param string $table
     */
    public function __construct(PDO $pdo, $table = 'users') {

        $this->pdo   = $pdo;
        $this->table = $table;
    }

    /**
     * @param array $row
     * @param PDO   $pdo
     * @param string $table
     *
     * @return static
     */
    public static function fromRow(array $row, PDO $pdo, $table) {

        $userObject                 = new static($pdo, $table);

        $userObject->id             = isset($row['id']) ? $row['id'] : null;
        $userObject->email          = isset($row['email']) ? $row['email'] : null;
        $userObject->password       = isset($row['password']) ? $row['password'] : '';
        $userObject->activated      = isset($row['activated']) ? (bool)$row['activated'] : false;
        $userObject->created_at     = isset($row['created_at']) ? $row['created_at'] : null;
        $userObject->updated_at     = isset($row['updated_at']) ? $row['updated_at'] : null;

        return $userObject;
    }

    /** @return int|string|null */
    public function getId() {

        return $this->id;
    }

    /** @return bool */
    public function isActivated() {

        return $this->activated;
    }

    /** @return void */
    public function markActivated() {

        $this->activated = true;
    }
}