<?php
/**
 * Project password-helper
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 09/22/2021
 * Time: 18:52
 */

namespace nguyenanhung\Libraries\Password;

use nguyenanhung\Libraries\Math\Random;

if (!class_exists('nguyenanhung\Libraries\Password\Password')) {
    /**
     * Class Password
     *
     * @package   nguyenanhung\Libraries\Password
     * @author    713uk13m <dev@nguyenanhung.com>
     * @copyright 713uk13m <dev@nguyenanhung.com>
     */
    class Password
    {
        /** @var string Password Prefix */
        public static $passwordPrefix = '|';

        /** @var int Password Algorithm */
        public static $passwordAlgorithm = PASSWORD_DEFAULT;

        /** @var array Password Options */
        public static $passwordOptions = array('cost' => 10);

        /**
         * Function randomString
         *
         * @param string $type
         * @param int    $len
         *
         * @return int|string
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 08/08/2023 17:40
         */
        public static function randomString(string $type = 'alnum', int $len = 8)
        {
            switch ($type) {
                case 'basic':
                    return mt_rand();
                case 'alnum':
                case 'numeric':
                case 'nozero':
                case 'alpha':
                    switch ($type) {
                        case 'alpha':
                            $pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                            break;
                        case 'numeric':
                            $pool = '0123456789';
                            break;
                        case 'nozero':
                            $pool = '123456789';
                            break;
                        default:
                            $pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                            break;
                    }

                    return mb_substr(str_shuffle(str_repeat($pool, ceil($len / mb_strlen($pool)))), 0, $len);
                case 'unique': // todo: remove in 3.1+
                case 'md5':
                    return md5(uniqid(mt_rand(), true));
                case 'encrypt': // todo: remove in 3.1+
                case 'sha1':
                    return sha1(uniqid(mt_rand(), true));
                default:
                    return md5(mt_rand());
            }
        }

        /**
         * Function generateRandomPassword
         *
         * @return string
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 10/30/19 46:04
         */
        public static function generateRandomPassword()
        {
            return static::randomString('alnum', 10);
        }

        /**
         * Function generateRandomSalt
         *
         * @return string
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 10/30/19 07:36
         */
        public static function generateRandomSalt()
        {
            return static::randomString('alnum', 16);

        }

        /**
         * Function createSaltWithMcrypt
         *
         * @return array|string|string[]
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 09/21/2021 02:49
         */
        public static function createSaltWithMcrypt()
        {
            $salt = Random::getBytes(32);
            $salt = base64_encode($salt);

            return str_replace('+', '.', $salt);
        }

        /**
         * Function generateStrongPassword
         *
         * @param int    $length
         * @param false  $add_dashes
         * @param string $available_sets
         *
         * @return string
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 07/28/2021 49:04
         */
        public static function generateStrongPassword(int $length = 20, bool $add_dashes = false, string $available_sets = 'hung'): string
        {
            $sets = [];
            if (mb_strpos($available_sets, 'h') !== false) {
                $sets[] = 'abcdefghjkmnpqrstuvwxyz';
            }
            if (mb_strpos($available_sets, 'u') !== false) {
                $sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
            }
            if (mb_strpos($available_sets, 'n') !== false) {
                $sets[] = '0123456789';
            }
            if (mb_strpos($available_sets, 'g') !== false) {
                $sets[] = '!@#$%&*?';
            }
            $all      = '';
            $password = '';
            foreach ($sets as $set) {
                $password .= $set[array_rand(str_split($set))];
                $all      .= $set;
            }
            $all = str_split($all);
            for ($i = 0; $i < $length - count($sets); $i++) {
                $password .= $all[array_rand($all)];
            }
            $password = str_shuffle($password);
            if (!$add_dashes) {
                return $password;
            }
            $dash_len = floor(sqrt($length));
            $dash_str = '';
            while (mb_strlen($password) > $dash_len) {
                $dash_str .= mb_substr($password, 0, $dash_len) . '-';
                $password = mb_substr($password, $dash_len);
            }
            $dash_str .= $password;

            return $dash_str;
        }

        /**
         * Function validStrongPassword
         *
         * @param string $password
         *
         * @return bool
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 10/30/19 04:14
         */
        public static function validStrongPassword(string $password = ''): bool
        {
            $containsSmallLetter = preg_match('/[a-z]/', $password); // Yêu cầu có ít nhất 1 ký tự viết thường
            $containsCapsLetter  = preg_match('/[A-Z]/', $password); // Yêu cầu có ít nhất 1 ký tự viết hoa
            $containsDigit       = preg_match('/\d/', $password); // Yêu cầu có ít nhất 1 số
            $containsSpecial     = preg_match('/[^a-zA-Z\d]/', $password); // Yêu cầu có ít nhất 1 ký tự đặc biệt

            return ($containsSmallLetter && $containsCapsLetter && $containsDigit && $containsSpecial);
        }

        /**
         * Function hashPassword
         *
         * @param string $password
         *
         * @return false|string
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 10/30/19 46:50
         */
        public static function hashPassword(string $password = '')
        {
            return password_hash($password, PASSWORD_DEFAULT);
        }

        /**
         * Function reHashPassword
         *
         * @param string $hash
         *
         * @return bool
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 07/28/2021 45:45
         */
        public static function reHashPassword(string $hash = ''): bool
        {
            return password_needs_rehash($hash, PASSWORD_DEFAULT);
        }

        /**
         * Function passwordGetInfo
         *
         * @param string $hash
         *
         * @return array|null
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 07/28/2021 45:29
         */
        public static function passwordGetInfo(string $hash = '')
        {
            return password_get_info($hash);
        }

        /**
         * Function verifyPassword
         *
         * @param string $password
         * @param string $hash
         *
         * @return bool
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 10/30/19 02:54
         */
        public static function verifyPassword(string $password = '', string $hash = ''): bool
        {
            return password_verify($password, $hash);
        }

        /**
         * Function changeHashPassword
         *
         * @param string $password
         * @param string $hash
         *
         * @return false|string|null
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 07/28/2021 45:19
         */
        public static function changeHashPassword(string $password = '', string $hash = '')
        {
            // Check if a newer hashing algorithm is available
            // or the cost has changed
            if (password_verify($password, $hash) && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
                // If so, create a new hash, and replace the old one
                return password_hash($password, PASSWORD_DEFAULT);
            }

            return false;
        }

        /**
         * Function hashUserPassword
         *
         * @param string $password
         * @param string $salt
         *
         * @return false|string|null
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 08/18/2021 50:16
         */
        public static function hashUserPassword(string $password = '', string $salt = '')
        {
            $passwordString = $password . self::$passwordPrefix . $salt;

            return password_hash($passwordString, self::$passwordAlgorithm, self::$passwordOptions);
        }

        /**
         * Function hashUserPasswordGetInfo
         *
         * @param string $hash
         *
         * @return array|null
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 08/18/2021 50:20
         */
        public static function hashUserPasswordGetInfo(string $hash = '')
        {
            return password_get_info($hash);
        }

        /**
         * Function userPasswordNeedSReHash
         *
         * @param string $hash
         *
         * @return bool
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 08/18/2021 50:23
         */
        public static function userPasswordNeedSReHash(string $hash = ''): bool
        {
            return password_needs_rehash($hash, self::$passwordAlgorithm, self::$passwordOptions);
        }

        /**
         * Function passwordVerify
         *
         * @param string $password
         * @param string $hash
         *
         * @return bool
         * @author   : 713uk13m <dev@nguyenanhung.com>
         * @copyright: 713uk13m <dev@nguyenanhung.com>
         * @time     : 08/18/2021 50:26
         */
        public static function passwordVerify(string $password = '', string $hash = ''): bool
        {
            return password_verify($password, $hash);
        }
    }
}