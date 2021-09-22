<?php
/**
 * Project password-helper
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 09/22/2021
 * Time: 18:59
 */

namespace nguyenanhung\Libraries\Password;

use DateTime;
use DateTimeZone;

if (!class_exists('nguyenanhung\Libraries\Password\Hash')) {
    /**
     * Class Hash
     *
     * @package   nguyenanhung\Libraries\Password
     * @author    713uk13m <dev@nguyenanhung.com>
     * @copyright 713uk13m <dev@nguyenanhung.com>
     */
    class Hash
    {
        const HASH_ALGORITHM                 = 'md5';
        const REQUEST_METHOD                 = 'POST';
        const USER_PASSWORD_RANDOM_LENGTH    = 16;
        const USER_PASSWORD_RANDOM_ALGORITHM = 'numeric';
        const USER_TOKEN_ALGORITHM           = 'md5';
        const USER_SALT_ALGORITHM            = 'md5';

        /**
         * Function generateHashValue
         *
         * @param string $str
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/18/18 03:04
         *
         */
        public static function generateHashValue($str = '')
        {
            return hash(self::HASH_ALGORITHM, $str);
        }

        /**
         * Function generateUserPasswordRandom
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/19/18 10:08
         *
         */
        public static function generateUserPasswordRandom()
        {
            return Password::randomString(self::USER_PASSWORD_RANDOM_ALGORITHM, self::USER_PASSWORD_RANDOM_LENGTH);
        }

        /**
         * Function generateUserToken
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/19/18 10:08
         *
         */
        public static function generateUserToken()
        {
            return Password::randomString(self::USER_TOKEN_ALGORITHM);
        }

        /**
         * Function generateUserSaltKey
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/19/18 10:08
         *
         */
        public static function generateUserSaltKey()
        {
            return Password::randomString(self::USER_SALT_ALGORITHM);
        }

        /**
         * Function generateRequestId
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/23/18 17:15
         *
         */
        public static function generateRequestId()
        {
            return date('YmdHis') . Password::randomString('numeric', 10);
        }

        /**
         * Function generateVinaRequestId
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 2018-12-06 22:04
         *
         */
        public static function generateVinaRequestId()
        {
            return date('YmdHis') . ceil(microtime(true) * 1000);
        }

        /**
         * Function generateOTPCode
         *
         * @param int $length
         *
         * @return string
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 11/23/18 17:16
         *
         */
        public static function generateOTPCode($length = 6)
        {
            return Password::randomString('numeric', $length);
        }

        /**
         * Function generateOTPExpireTime
         *
         * @param int $hour
         *
         * @return string
         * @throws \Exception
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 2018-12-06 16:03
         *
         */
        public static function generateOTPExpireTime($hour = 4)
        {
            $time = new DateTime('+' . $hour . ' days');

            return $time->format('Y-m-d H:i:s');
        }
    }
}
