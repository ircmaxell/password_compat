<?php

if (version_compare(PHP_VERSION, '5.3.7', '<')) {
	trigger_error("The Password Compatibility Library requires PHP >= 5.3.7", E_USER_WARNING);
	// Prevent defining the functions
	return;
}

if (!defined('PASSWORD_BCRYPT'))
{
	require __DIR__ . '/password_compat.php';

	define('PASSWORD_BCRYPT', 1);
	define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);

	function password_hash($password, $algo, array $options = array()) {
		return password_compat::hash($password, $algo, $options);
	}

	function password_get_info($hash) {
		return password_compat::get_info($hash);
	}

	function password_needs_rehash($hash, $algo, array $options = array()) {
		return password_compat::needs_rehash($hash, $algo, $options);
	}

	function password_verify($password, $hash) {
		return password_compat::verify($password, $hash);
	}
}
