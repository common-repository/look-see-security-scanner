<?php
/**
 * Look-See Security Scanner - Bootstrap
 *
 * Set up the environment.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

/**
 * Do not execute this file directly.
 */
if (!defined('ABSPATH')) {
	exit;
}



// Bootstrap.
// phpab -e "./node_modules/*" -o ./lib/autoload.php .
require(LOOKSEE_PLUGIN_DIR . 'lib/autoload.php');

// Actions!
add_action('admin_enqueue_scripts', array(LOOKSEE_BASE_CLASS . 'admin', 'enqueue_scripts'));
add_action('admin_notices', array(LOOKSEE_BASE_CLASS . 'admin', 'update_notice'));
add_action('admin_notices', array(LOOKSEE_BASE_CLASS . 'admin', 'warnings'));
add_action('init', array(LOOKSEE_BASE_CLASS . 'ajax', 'init'));
add_action('plugins_loaded', array(LOOKSEE_BASE_CLASS . 'admin', 'localize'));
add_action('plugins_loaded', array(LOOKSEE_BASE_CLASS . 'admin', 'server_name'));
add_action('plugins_loaded', array(LOOKSEE_BASE_CLASS . 'db', 'check'));

// Registration!
register_activation_hook(LOOKSEE_INDEX, array(LOOKSEE_BASE_CLASS . 'db', 'check'));

// And a few bits that don't need to wait.
\blobfolio\wp\looksee\admin::register_menus();
\blobfolio\wp\looksee\files::init();

// WP-CLI functions.
if (defined('WP_CLI') && WP_CLI) {
	require(LOOKSEE_PLUGIN_DIR . 'lib/blobfolio/wp/looksee/cli.php');
}

// --------------------------------------------------------------------- end setup

