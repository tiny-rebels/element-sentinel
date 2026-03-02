<?php

namespace Element\Sentinel\Infrastructure\PDO;

use PDO;
use PDOException;

use Element\Sentinel\Contracts\{
    ActivationInterface,
    ActivationRepositoryInterface,
    UserInterface
};

use Element\Sentinel\Support\CodeGenerator;

/**
 * PDO-baseret ActivationRepository.
 *
 * Antager en "activations" tabel med kolonner:
 *   id, user_id, code, completed_at, created_at
 */
class PdoActivationRepository implements ActivationRepositoryInterface {

    /** @var PDO */
    private $pdo;

    /** @var string */
    private $table;

    /**
     * @param PDO    $pdo
     * @param string $table Navn på activations-tabellen (default: "activations")
     */
    public function __construct(PDO $pdo, string $table = 'activations') {

        $this->pdo   = $pdo;
        $this->table = $table;
    }

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface
     *
     * @throws \Exception
     */
    public function create(UserInterface $user): ?ActivationInterface {

        try {

            $activationCode = CodeGenerator::random(32); // or 64

        } catch (\Exception $exception) {

            // random_bytes kan kaste en generisk Exception i PHP 7.x
            throw $exception; // eller håndter som du ønsker
        }

        $now  = date('Y-m-d H:i:s');

        $sql = "INSERT INTO {$this->table} (user_id, code, completed_at, created_at)
                VALUES (:user_id, :code, NULL, :created_at)";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':user_id', $user->getId());
        $stmt->bindValue(':code', $activationCode);
        $stmt->bindValue(':created_at', $now);

        $stmt->execute();

        // Hent række tilbage (for at få id mv.)
        return $this->findByCode($activationCode);
    }

    /**
     * @param UserInterface $user
     *
     * @return bool
     */
    public function exists(UserInterface $user): bool {

        $sql = "SELECT 1 FROM {$this->table}
                WHERE user_id = :user_id AND completed_at IS NULL
                LIMIT 1";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':user_id', $user->getId());

        $stmt->execute();

        return (bool)$stmt->fetchColumn();
    }

    /**
     * @param UserInterface $user
     *
     * @return ActivationInterface|null
     */
    public function findOpenByUser(UserInterface $user): ?ActivationInterface {

        $sql = "SELECT id, user_id, code, completed_at, created_at
                FROM {$this->table}
                WHERE user_id = :user_id AND completed_at IS NULL
                ORDER BY created_at DESC
                LIMIT 1";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':user_id', $user->getId());

        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {

            return null;
        }

        return PdoActivation::fromRow($row);
    }

    /**
     * @param string $code
     *
     * @return ActivationInterface|null
     */
    public function findByCode(string $code): ?ActivationInterface {

        $sql = "SELECT id, user_id, code, completed_at, created_at
                FROM {$this->table}
                WHERE code = :code
                LIMIT 1";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':code', $code);

        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {

            return null;
        }

        return PdoActivation::fromRow($row);
    }

    /**
     * Fuldfør aktivering for bruger+kode. Idempotent-ish:
     * returnerer false, hvis der ikke findes en åben activation.
     *
     * @param UserInterface $user
     * @param string $code
     *
     * @return bool
     */
    public function complete(UserInterface $user, string $code): bool {

        // En simpel og sikker måde er at opdatere med en single UPDATE ... WHERE user_id, code AND completed_at IS NULL
        $sql = "UPDATE {$this->table}
                SET completed = :completed,
                    completed_at = :completed_at
                WHERE user_id = :user_id
                  AND code = :code
                  AND completed_at IS NULL";

        $stmt = $this->pdo->prepare($sql);

        $stmt->bindValue(':completed', 1, \PDO::PARAM_INT);
        $stmt->bindValue(':completed_at', date('Y-m-d H:i:s'));
        $stmt->bindValue(':user_id', $user->getId());
        $stmt->bindValue(':code', $code);

        $stmt->execute();

        if ($stmt->rowCount() < 1) {

            return false; // ingen åben record matchede
        }

        // Marker brugeren som aktiveret (lad repoen, der gemmer users, tage sig af persistence)
        if (method_exists($user, 'markActivated')) {

            $user->markActivated();
        }

        // Hvis det er en PdoUser, kan vi gemme direkte:
        if ($user instanceof PdoUser) {

            // Gem via users-tabellen
            $sqlU   = "UPDATE users SET activated = :activated, updated_at = :updated_at WHERE id = :id";
            $stmtU  = $this->pdo->prepare($sqlU);

            $stmtU->bindValue(':activated', 1, PDO::PARAM_INT);
            $stmtU->bindValue(':updated_at', date('Y-m-d H:i:s'));
            $stmtU->bindValue(':id', $user->getId());

            $stmtU->execute();
        }

        return true;
    }
}

/**
 * Simpel PDO-baseret Activation-model der implementerer ActivationInterface.
 */
class PdoActivation implements ActivationInterface {

    /** @var mixed */
    public $id;

    /** @var mixed */
    public $user_id;

    /** @var string */
    public $code;

    /** @var string|null */
    public $completed_at;

    /** @var string */
    public $created_at;

    /**
     * @param array $row
     * @return static
     */
    public static function fromRow(array $row) {

        $activationObject               = new static();

        $activationObject->id           = isset($row['id']) ? $row['id'] : null;
        $activationObject->user_id      = isset($row['user_id']) ? $row['user_id'] : null;
        $activationObject->code         = isset($row['code']) ? $row['code'] : '';
        $activationObject->completed_at = isset($row['completed_at']) ? $row['completed_at'] : null;
        $activationObject->created_at   = isset($row['created_at']) ? $row['created_at'] : date('Y-m-d H:i:s');

        return $activationObject;
    }

    /** @return int|string */
    public function getUserId() {

        return $this->user_id;
    }

    /** @return string */
    public function getCode() {

        return $this->code;
    }

    /** @return bool */
    public function isCompleted() {

        return $this->completed_at !== null;
    }
}
