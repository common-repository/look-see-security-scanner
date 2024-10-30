<?php
/**
 * Scan your web server for modified WordPress files, backdoors, or other irregularities.
 *
 * @package look-see-security-scanner
 * @version 22.0.0
 *
 * @wordpress-plugin
 * Plugin Name: Look-See Security Scanner
 * Version: 22.0.0
 * Plugin URI: https://wordpress.org/plugins/look-see-security-scanner/
 * Description: Scan your web server for modified WordPress files, backdoors, or other irregularities.
 * Text Domain: look-see-security-scanner
 * Domain Path: /languages/
 * Author: Blobfolio, LLC
 * Author URI: https://blobfolio.com/
 * License: WTFPL
 * License URI: http://www.wtfpl.net
 */

/**
 * Do not execute this file directly.
 */
if (!defined('ABSPATH')) {
	exit;
}

// ---------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------

// This plugin has no frontend application, so we can avoid loading it
// at all if the shoe doesn't fit.
if (
	(!defined('WP_CLI') || !WP_CLI) &&
	(!defined('DOING_CRON') || !DOING_CRON) &&
	// The is_admin() function doesn't exist yet. This is close enough.
	(!isset($_SERVER['REQUEST_URI']) || (false === strpos($_SERVER['REQUEST_URI'], 'wp-admin')))
) {
	return;
}

// Constants.
define('LOOKSEE_PLUGIN_DIR', dirname(__FILE__) . '/');
define('LOOKSEE_INDEX', __FILE__);
define('LOOKSEE_BASE_CLASS', 'blobfolio\\wp\\looksee\\');
define('LOOKSEE_URL', 'https://blobfolio.com/plugin/look-see-security-scanner/');
define('LOOKSEE_EMAIL', 'orders@blobfolio.com');
define('LOOKSEE_L10N', 'look-see-security-scanner');
define('LOOKSEE_VERSION', '22.0.0');

// Is this installed as a Must-Use plugin?
$looksee_must_use = (
	defined('WPMU_PLUGIN_DIR') &&
	@is_dir(WPMU_PLUGIN_DIR) &&
	(0 === strpos(LOOKSEE_PLUGIN_DIR, WPMU_PLUGIN_DIR))
);
define('LOOKSEE_MUST_USE', $looksee_must_use);

// Now the URL root.
if (!LOOKSEE_MUST_USE) {
	define('LOOKSEE_PLUGIN_URL', preg_replace('/^https?:/i', '', trailingslashit(plugins_url('/', LOOKSEE_INDEX))));
}
else {
	define('LOOKSEE_PLUGIN_URL', preg_replace('/^https?:/i', '', trailingslashit(str_replace(WPMU_PLUGIN_DIR, WPMU_PLUGIN_URL, LOOKSEE_PLUGIN_DIR))));
}

// --------------------------------------------------------------------- end setup



// ---------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------

// If the server doesn't meet the requirements, load the fallback
// instead.
if (
	version_compare(PHP_VERSION, '5.6.0') < 0 ||
	(function_exists('is_multisite') && is_multisite()) ||
	(!function_exists('hash_algos') || !in_array('sha512', hash_algos(), true)) ||
	!extension_loaded('date') ||
	!extension_loaded('filter') ||
	!extension_loaded('json') ||
	!extension_loaded('pcre') ||
	!extension_loaded('spl')
) {
	require(LOOKSEE_PLUGIN_DIR . 'bootstrap-fallback.php');
	return;
}

// --------------------------------------------------------------------- end requirements



// Otherwise we can continue as normal.
require(LOOKSEE_PLUGIN_DIR . 'bootstrap.php');
