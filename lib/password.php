<?php

defined('PASSWORD_BCRYPT') or define('PASSWORD_BCRYPT', '2y');
defined('PASSWORD_MD5') or define('PASSWORD_MD5', '1');
defined('PASSWORD_SHA256') or define('PASSWORD_SHA256', '5');
defined('PASSWORD_SHA512') or define('PASSWORD_SHA512', '6');

defined('PASSWORD_DEFAULT') or define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);

define('PASSWORD_BCRYPT_DEFAULT_COST', 11);
define('PASSWORD_SHA_DEFAULT_ROUNDS', 5000);

if (!function_exists('password_create')) {
	function password_create($password, $algo = PASSWORD_DEFAULT, $options = array()) {
		if (!function_exists('crypt')) {
			trigger_error("Crypt must be loaded for password_create to function", E_USER_WARNING);
			return false;
		}
		if (!is_string($password)) {
			trigger_error("Password must be a string", E_USER_WARNING);
			return false;
		}
		if (!$algo) {
			$algo = PASSWORD_DEFAULT;
		}
		switch ($algo) {
			case PASSWORD_BCRYPT:
				$cost = PASSWORD_BCRYPT_DEFAULT_COST;
				if (isset($options['cost'])) {
					$cost = $options['cost'];
					if ($cost < 4 || $cost > 31) {
						trigger_error(sprintf("Invalid bcrypt cost parameter specified: %d", $cost), E_USER_WARNING);
						return false;
					}
				}
				$required_salt_len = 22;
				$hash_format = sprintf("$2y$%02d$", $cost);
				break;
			case PASSWORD_MD5:
				$hash_format = "$1$";
				$required_salt_len = 12;
				break;
			case PASSWORD_SHA256:
			case PASSWORD_SHA512:
				$rounds = PASSWORD_SHA_DEFAULT_ROUNDS;
				if (isset($options['rounds'])) {
					$rounds = $options['rounds'];
					if ($rounds < 1000 || $rounds > 999999999) {
						trigger_error(sprintf("Invalid SHA rounds parameter specified: %d", $rounds), E_USER_WARNING);
						return false;
					}
				}
				$required_salt_len = 16;
				$hash_format = sprintf("$%s$rounds=%d$", $algo, $rounds);
				break;
			default:
				trigger_error(sprintf("Unknown password hashing algorithm: %s", $algo), E_USER_WARNING);
				return false;
		}
		if (isset($options['salt'])) {
			if (is_string($options['salt'])) {
				$salt = $options['salt'];
			} else {
				trigger_error('Non-string salt parameter supplied', E_USER_WARNING);
				return false;
			}
			if (strlen($salt) < $required_salt_len) {
				trigger_error(sprintf("Provided salt is too short: %d expecting %d", strlen($salt), $required_salt_len), E_USER_WARNING);
				return false;
			} elseif (0 == preg_match('#^[a-zA-Z0-9./]+$#', $salt)) {
				$salt = str_replace('+', '.', base64_encode($salt));
			}
		} else {
			$salt = password_make_salt($required_salt_len);
		}
		$salt = substr($salt, 0, $required_salt_len);

		$hash = $hash_format . $salt;

		$ret = crypt($password, $hash);

		if (!is_string($ret) || strlen($ret) < 13) {
			return false;
		}

		return $ret;
	}
}



if (!function_exists('password_verify')) {
    function password_verify($password, $hash) {
		if (!function_exists('crypt')) {
			trigger_error("Crypt must be loaded for password_create to function", E_USER_WARNING);
			return false;
		}
		$ret = crypt($password, $hash);
		if (!is_string($ret) || strlen($ret) != strlen($hash)) {
			return false;
		}

		$status = 0;
		for ($i = 0; $i < strlen($ret); $i++) {
			$status |= (ord($ret[$i]) ^ ord($hash[$i]));
		}

		return $status === 0;
	}
}

if (!function_exists('password_make_salt')) {
	function password_make_salt($length, $raw_output = false) {
		if ($length <= 0) {
			trigger_error(sprintf("Length cannot be less than or equal zero: %d", $length), E_USER_WARNING);
			return false;
		}

		if ($raw) {
			$raw_length = $length;
		} else {
			$raw_length = (int) ($length * 3 / 4 + 1);
		}

		$buffer_valid = false;

		if (function_exists('mcrypt_create_iv')) {
			$buffer = mcrypt_create_iv($raw_length, MCRYPT_DEV_URANDOM);
			if ($buffer) {
				$buffer_valid = true;
			}
		}
		if (!$buffer_valid && function_exists('openssl_random_pseudo_bytes')) {
			$buffer = openssl_random_pseudo_bytes($raw_length);
			if ($buffer) {
				$buffer_valid = true;
			}
		}
		if (!$buffer_valid) {
			for ($i = 0; $i < $raw_length; $i++) {
				$buffer .= chr(mt_rand(0, 255));
			}
		}

		if (!$raw) {
			$buffer = str_replace('+', '.', base64_encode($buffer));
		}
		return substr($buffer, 0, $length);
	}
}