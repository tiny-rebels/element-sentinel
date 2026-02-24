<?php

namespace Element\Sentinel\Support;

class CodeGenerator {

    /**
     * Generate a cryptographically secure random code, choosing characters from a given alphabet.
     *
     * Default alphabet: {@see self::alphabetSymbolRich()} (letters, digits, and a moderate set of symbols).
     *
     * @param int         $length    Desired length of the code (number of characters).
     * @param string|null $alphabet  Custom alphabet to pick characters from. If null, uses alphabetSymbolRich().
     *
     * @return string
     *
     * @throws \InvalidArgumentException If the provided alphabet has fewer than 2 characters.
     * @throws \Exception                If a secure random integer cannot be generated (random_int failure).
     */
    public static function random($length = 32, $alphabet = null) {

        if ($alphabet === null) {

            $alphabet = self::alphabetSymbolRich();
        }

        $alphabetLength = strlen($alphabet);

        if ($alphabetLength < 2) {

            throw new \InvalidArgumentException('Alphabet must contain at least 2 characters.');
        }

        $code = '';

        for ($i = 0; $i < $length; $i++) {

            // random_int() provides cryptographically secure randomness in PHP 7+
            $index = random_int(0, $alphabetLength - 1);
            $code .= $alphabet[$index];
        }

        return $code;
    }

    /**
     * Alphanumeric alphabet: A–Z, a–z, 0–9 (62 characters).
     *
     * Suitable when you need a clean code consisting only of letters and digits.
     *
     * @return string
     */
    public static function alphabetAlnum() {

        return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }

    /**
     * URL-safe alphabet (Base64 URL variant without padding): A–Z, a–z, 0–9, '-' and '_'.
     *
     * Very transport-friendly for URLs and filenames. Even so, always URL-encode codes
     * when placing them into query string parameters.
     *
     * @return string
     */
    public static function alphabetUrlSafe() {

        return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    }

    /**
     * Symbol-rich alphabet: Alnum plus a moderate set of symbols that usually behave well in emails and UIs.
     *
     * Included symbols: - _ . ~ ! * $ @
     * Note: If you embed codes in URLs, always URL-encode them regardless of the alphabet you use.
     *
     * @return string
     */
    public static function alphabetSymbolRich() {

        return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!*$@';
    }

    /**
     * You can always define your own alphabet in the application code and pass it to random(), e.g.:
     *
     *   $alphabet = 'ABC...xyz0123...!#%&+?=@*_-.';  // your custom set
     *   $code = \Element\Sentinel\Support\CodeGenerator::random(64, $alphabet);
     *
     * Keep in mind:
     * - Use URL-encoding when placing codes in query parameters.
     * - Ensure your schemas column length (e.g., CHAR(64)) matches the code length you generate.
     */
}
