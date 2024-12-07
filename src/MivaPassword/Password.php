<?php

/*
 * This file is part of the MivaPassword package.
 *
 * (c) Brandon Kahre <brandon@kahre.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace MivaPassword;

/**
 * Password utility class.
 *
 * Does all the things you'll need.
 */
class Password
{
    /**
     * Miva's default length for a password salt.
     *
     * @var int
     */
    protected static $salt_length = 8;

    /**
     * Create a Miva Merchant compatible password hash. Follows the following format:
     *     PBKDF:hash-algorithm:iterations:salt-base64:ciphertext-base64
     *
     * @see http://extranet.mivamerchant.com/forums/showthread.php?110099-Miva-Merchant-5-Production-Release-8-Update-7-Customer-Password-Encryption-Info
     *
     * @param string $password           The plain-text password to hash
     * @param string $salt               The plain-text salt to use in the hash
     * @param string $pbkdf_version      The PBKDF version to use; PBKDF1 by default
     * @param string $hash_algo          The hashing algorithim to use; sha1 by default
     * @param int    $iterations         The number of times to run the hashing algorithim; 1000 by default
     * @param int    $derived_key_length The maximum string length enforced on the derived key; 20 by default
     *
     * @return string A secure password hash string
     */
    public static function create_hash(
        $password,
        $salt = '',
        $pbkdf_version = 'PBKDF1',
        $hash_algo = 'sha1',
        $iterations = 1000,
        $derived_key_length = 20,
    ) {
        if ('' === $salt) {
            $salt = self::create_salt();
        }

        $pbkdf_version = strtoupper($pbkdf_version);

        switch ($pbkdf_version) {
            case 'PBKDF1':
                $derived_key = self::pbkdf1($password, $salt, $hash_algo, $iterations, $derived_key_length);
                break;

            case 'PBKDF2':
                $derived_key = self::pbkdf2($password, $salt, $hash_algo, $iterations, $derived_key_length);
                break;

            case 'SHA1':
            default:
                throw new \InvalidArgumentException($pbkdf_version.' not supported');
        }

        if (!$derived_key) {
            return false;
        }

        return strtoupper($pbkdf_version).':'.strtolower($hash_algo).':'.$iterations.':'.base64_encode($salt).':'.base64_encode($derived_key);
    }

    /**
     * Generate a unique and secure password. This password will be returned as plain
     * text and is NOT TO BE STORED ANYWHERE!
     *
     * @param int $pw_min_len The minimum length required for the new password.
     *                        Quick note: Specifying a minimum does not guarantee that the
     *                        password will be exactly that length, it could be longer based on
     *                        the $pw_complex parameter.
     * @param int $pw_complex The password complexity level
     *                        0 = No requirements
     *                        1 = Requires a letter and either a digit or special character
     *                        2 = Requires an upper case letter, a lower case letter, and either a
     *                        digit or special character
     *
     * @return string
     */
    public static function generate($pw_min_len = 6, $pw_complex = 0)
    {
        if ($pw_min_len < 6) {
            $pw_min_len = 6;
        }

        if ($pw_complex < 0) {
            $pw_complex = 0;
        }

        $uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $lowers = 'abcdefghijklmnopqrstuvwxyz';
        $digits = '0123456789';
        $others = '!@$%&*=';
        $character_set = $uppers.$lowers.$digits.$others;
        $has_upper = $has_lower = $has_digit = $has_other = false;

        $password = '';
        for ($i = 0; $i < $pw_min_len; ++$i) {
            $char = $character_set[mt_rand(0, \strlen($character_set) - 1)];
            $password .= $char;

            if (str_contains($uppers, $char)) {
                $has_upper = true;
            } elseif (str_contains($lowers, $char)) {
                $has_lower = true;
            } elseif (str_contains($digits, $char)) {
                $has_digit = true;
            } elseif (str_contains($others, $char)) {
                $has_other = true;
            }
        }

        // check password requirements
        switch ($pw_complex) {
            case 0:
                // no requirements
                break;

            case 1:
                // require either an upper or lower and either a digit or other
                if (false === $has_upper || false === $has_lower) {
                    $password = self::insertrandom($password, $uppers.$lowers);
                }

                if (false === $has_digit || false === $has_other) {
                    $password = self::insertrandom($password, $digits.$others);
                }

                break;

            case 2:
                // require an upper, lower, and either a digit or other
                if (false === $has_upper) {
                    $password = self::insertrandom($password, $uppers);
                }

                if (false === $has_lower) {
                    $password = self::insertrandom($password, $lowers);
                }

                if (false === $has_digit || false === $has_other) {
                    $password = self::insertrandom($password, $digits.$others);
                }

                break;
        }

        return $password;
    }

    /**
     * Verify that a given password matches the given password hash.
     *
     * @param string $password  The plain-text password to check
     * @param string $good_hash The hash string we are checking against
     *
     * @return bool True if the two strings contain the same password
     */
    public static function verify($password, $good_hash)
    {
        // first get all the settings and details used in the creation of the good hash
        $algorithm_info = self::extract_algorithm_info($good_hash);
        if (empty($algorithm_info)) {
            return false;
        }

        // generate a hash from the given password using the settings from good hash
        $unknown_hash = self::create_hash($password, $algorithm_info['salt'], $algorithm_info['PBKDF_version'], $algorithm_info['hash_algorithm'], $algorithm_info['iterations'], $algorithm_info['derived_key_length']);

        return $unknown_hash === $good_hash;
    }

    /**
     * Create a unique salt string using the best source of random we can find.
     *
     * @return string MIME base64
     */
    protected static function create_salt()
    {
        $length = self::$salt_length;

        // mcrypt is our first choice
        if (\function_exists('mcrypt_create_iv')) {
            $salt = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if (\strlen($salt) >= $length) {
                return substr($salt, 0, $length);
            }
        }

        // else let's try /dev/urandom (doesn't work with Windows)
        if (is_readable('/dev/urandom') && ($fh = fopen('/dev/urandom', 'r'))) {
            $salt = fread($fh, $length);
            fclose($fh);
            if (\strlen($salt) >= $length) {
                return substr($salt, 0, $length);
            }
        }

        // worst case scenario we'll use a binary md5 hash pasted together
        $salt = '';
        for ($i = 0; $i < $length; $i += 16) { // 16 is the length of a raw md5 hash
            $salt .= md5(microtime(), true);
        }

        return substr($salt, 0, $length);
    }

    /**
     * Extract the algorithm details from the given hash such as:
     *     PBKDF version
     *     Hashing algorithm used
     *     Number of iterations used in hashing
     *     Salt
     *     Derived key
     *
     * @param string $good_hash A PBKDF hash; separated by colons
     * @param string $option='' The key of the specific detail you want returned
     *
     * @return array|string|null returns an array unless an option param is passed
     */
    protected static function extract_algorithm_info($good_hash, $option = '')
    {
        // make sure we have the proper formatted hash
        $good_hash_info = explode(':', $good_hash);
        if (\count($good_hash_info) < 5) {
            return null;
        }

        list($pbkdf_version, $hash_algorithm, $iterations, $salt, $derived_key) = $good_hash_info;
        $salt = base64_decode($salt);
        $derived_key = base64_decode($derived_key);

        $algo_info = [
            'PBKDF_version' => $pbkdf_version,
            'hash_algorithm' => $hash_algorithm,
            'iterations' => $iterations,
            'salt' => (string) $salt,
            'derived_key' => (string) $derived_key,
            'derived_key_length' => \strlen((string) $derived_key),
        ];

        if ('' !== $option) {
            if (isset($algo_info[$option])) {
                return $algo_info[$option];
            }

            return null;
        }

        return $algo_info;
    }

    /**
     * Insert a random character from the given character set in to the given password.
     *
     * @param string $password
     * @param string $character_set
     *
     * @return string
     */
    protected static function insertrandom($password, $character_set)
    {
        $random_position = mt_rand(0, \strlen($password) - 1);
        $random_char = $character_set[mt_rand(0, \strlen($character_set) - 1)];

        return substr($password, 0, $random_position).$random_char.substr($password, $random_position);
    }

    /**
     * Standard implementation of PBKDF1.
     *
     * @param string $password           The plain-text password to hash
     * @param string $salt               The plain-text salt to use in the hash
     * @param string $hash_algo          MD2, MD5 or SHA1; SHA1 by default
     * @param int    $iterations         The number of iterations to run the hashing algorithm; 1000 by default
     * @param int    $derived_key_length The maximum length of the resulting key; 20 by default
     *
     * @return string A PBKDF1 password hash string
     */
    protected static function pbkdf1($password, $salt, $hash_algo, $iterations, $derived_key_length)
    {
        $hash_algo = strtolower($hash_algo);
        $iterations = (int) $iterations;
        $derived_key_length = (int) $derived_key_length;

        // supported hash algorithms
        if (!\in_array($hash_algo, ['md2', 'md5', 'sha1'])) {
            throw new \InvalidArgumentException($hash_algo.' hash algorithm not supported');
        }

        // iterations and derived key length must be positive
        if ($iterations <= 0) {
            throw new \InvalidArgumentException('Iterations must be a positive integer');
        }

        if ($derived_key_length <= 0) {
            throw new \InvalidArgumentException('Derived key must be a positive integer');
        }

        // derived key length is enforced for PBKDF1 based on hash algorithm
        if ('md5' === $hash_algo && $derived_key_length > 16) {
            // throw new Exception('derived key too long');
            return false;
        }

        if ('sha1' === $hash_algo && $derived_key_length > 20) {
            // throw new Exception('derived key too long');
            return false;
        }

        // hash password and salt
        $derived_key = $password.$salt;
        for ($i = 0; $i < $iterations; ++$i) {
            $derived_key = hash($hash_algo, $derived_key, true);
        }

        // truncate derived key based on given key length
        return substr($derived_key, 0, $derived_key_length);
    }

    /**
     * Standard implementation of PBKDF2.
     *
     * @param string $password           The plain-text password to hash
     * @param string $salt               The plain-text salt to use in the hash
     * @param string $hash_algo          Hashing algorithm to use; SHA1 by default
     * @param int    $iterations         The number of iterations to run the hashing algorithm; 1000 by default
     * @param int    $derived_key_length The maximum length of the resulting key; 20 by default
     *
     * @return string A PBKDF2 password hash string
     */
    protected static function pbkdf2($password, $salt, $hash_algo, $iterations, $derived_key_length)
    {
        $hash_algo = strtolower($hash_algo);
        $iterations = (int) $iterations;
        $derived_key_length = (int) $derived_key_length;

        // supported hash algorithms
        if (!\in_array($hash_algo, hash_algos())) {
            throw new \InvalidArgumentException($hash_algo.' hash algorithm not supported');
        }

        // iterations and derived key length must be positive
        if ($iterations <= 0) {
            throw new \InvalidArgumentException('Iterations must be a positive integer');
        }

        if ($derived_key_length <= 0) {
            throw new \InvalidArgumentException('Derived key must be a positive integer');
        }

        // This is straight from https://defuse.ca/php-pbkdf2.htm
        // get the hash string length of the algorithm being used
        $hash_length = \strlen(hash($hash_algo, '', true));
        $block_count = ceil($derived_key_length / $hash_length);
        $derived_key = '';
        for ($i = 1; $i <= $block_count; ++$i) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt.pack('N', $i);
            // first iteration
            $last = $xorsum = hash_hmac($hash_algo, $last, $password, true);
            // perform the other $iterations - 1 iterations
            for ($j = 1; $j < $iterations; ++$j) {
                $xorsum ^= ($last = hash_hmac($hash_algo, $last, $password, true));
            }

            $derived_key .= $xorsum;
        }

        // truncate derived key based on given key length
        return substr($derived_key, 0, $derived_key_length);
    }
}
