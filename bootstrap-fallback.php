<?php
/**
 * Look-See Security Scanner - Fallback Bootstrap
 *
 * This is run on environments that do not meet the main plugin
 * requirements. It will either deactivate the plugin (if it has never
 * been active) or provide a semi-functional fallback environment to
 * keep the site from breaking, and suggest downgrading to the legacy
 * version.
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



// ---------------------------------------------------------------------
// Compatibility Checking
// ---------------------------------------------------------------------

// There will be errors. What are they?
$looksee_errors = array();

if (version_compare(PHP_VERSION, '5.6.0') < 0) {
	$looksee_errors['version'] = __('PHP 5.6.0 or newer is required.', LOOKSEE_L10N);
}

if (function_exists('is_multisite') && is_multisite()) {
	$looksee_errors['multisite'] = __('This plugin cannot be used on Multi-Site.', LOOKSEE_L10N);
}

// Miscellaneous extensions.
foreach (array('date', 'filter', 'json', 'pcre', 'spl') as $v) {
	if (!extension_loaded($v)) {
		$looksee_errors[$v] = sprintf(
			__('This plugin requires the PHP extension %s.', LOOKSEE_L10N),
			$v
		);
	}
}

if (!function_exists('hash_algos') || !in_array('sha512', hash_algos(), true)) {
	$looksee_errors['hash'] = __('PHP must support basic hashing algorithms like SHA512.', LOOKSEE_L10N);
}

// Will downgrading to the legacy version help?
$looksee_downgrade = (
	!LOOKSEE_MUST_USE &&
	(1 === count($looksee_errors)) &&
	isset($looksee_errors['version']) &&
	version_compare(PHP_VERSION, '5.4.0') >= 0
);

// --------------------------------------------------------------------- end compatibility



// ---------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------

/**
 * Admin Notice
 *
 * @return bool True/false.
 */
function looksee_admin_notice() {
	global $looksee_errors;
	global $looksee_downgrade;

	if (!is_array($looksee_errors) || !count($looksee_errors)) {
		return false;
	}
	?>
	<div class="notice notice-error">
		<p><?php
		echo sprintf(
			__('Your server does not meet the requirements for running %s. You or your system administrator should take a look at the following:', LOOKSEE_L10N),
			'<strong>Look-See Security Scanner</strong>'
		);
		?></p>

		<?php
		foreach ($looksee_errors as $error) {
			echo '<p>&nbsp;&nbsp;&mdash; ' . esc_html($error) . '</p>';
		}

		// Can we recommend the old version?
		if (isset($looksee_errors['disabled'])) {
			unset($looksee_errors['disabled']);
		}

		if ($looksee_downgrade) {
			echo '<p>' .
			sprintf(
				__('As a *stopgap*, you can %s the Look-See Security Scanner plugin to the legacy *20.x* series. The legacy series *will not* receive updates or development support, so please ultimately plan to remove the plugin or upgrade your server environment.', LOOKSEE_L10N),
				'<a href="' . admin_url('update-core.php') . '">' . __('downgrade', LOOKSEE_L10N) . '</a>'
			) . '</p>';
		}
		?>
	</div>
	<?php
	return true;
}
add_action('admin_notices', 'looksee_admin_notice');

/**
 * Self-Deactivate
 *
 * If the environment can't support the plugin and the environment never
 * supported the plugin, simply remove it.
 *
 * @return bool True/false.
 */
function looksee_deactivate() {
	// Can't deactivate an MU plugin.
	if (LOOKSEE_MUST_USE) {
		return false;
	}

	require_once(trailingslashit(ABSPATH) . 'wp-admin/includes/plugin.php');
	deactivate_plugins(LOOKSEE_INDEX);

	global $looksee_errors;
	global $looksee_downgrade;
	$looksee_downgrade = false;
	$looksee_errors['disabled'] = __('The plugin has been automatically disabled.', LOOKSEE_L10N);

	if (isset($_GET['activate'])) {
		unset($_GET['activate']);
	}

	return true;
}
add_action('admin_init', 'looksee_deactivate');

/**
 * Downgrade Update
 *
 * Pretend the legacy version is newer to make it easier for people to
 * downgrade. :)
 *
 * @param StdClass $option Plugin lookup info.
 * @return StdClass Option.
 */
function looksee_fake_version($option) {
	global $looksee_downgrade;

	// Argument must make sense.
	if (!is_object($option) || !$looksee_downgrade) {
		return $option;
	}

	// Set up the entry.
	$path = 'look-see-security-scanner/index.php';
	if (!array_key_exists($path, $option->response)) {
		$option->response[$path] = new stdClass();
	}

	// Steal some information from the installed plugin.
	require_once(trailingslashit(ABSPATH) . 'wp-admin/includes/plugin.php');
	$info = get_plugin_data(LOOKSEE_INDEX);

	$option->response[$path]->id = 0;
	$option->response[$path]->slug = LOOKSEE_L10N;
	$option->response[$path]->plugin = $path;
	$option->response[$path]->new_version = '2020-legacy';
	$option->response[$path]->url = $info['PluginURI'];
	$option->response[$path]->package = 'https://downloads.wordpress.org/plugin/look-see-security-scanner.20.2.0.zip';
	$option->response[$path]->upgrade_notice = __('This will downgrade to the legacy 20.2.0 release, which is compatible with PHP 5.4. Do not upgrade from the legacy version until your server meets the requirements of the current release.', LOOKSEE_L10N);

	// And done.
	return $option;
}
add_filter('transient_update_plugins', 'looksee_fake_version');
add_filter('site_transient_update_plugins', 'looksee_fake_version');

/**
 * Localize
 *
 * @return void Nothing.
 */
function looksee_localize() {
	if (LOOKSEE_MUST_USE) {
		load_muplugin_textdomain(LOOKSEE_L10N, basename(LOOKSEE_PLUGIN_DIR) . '/languages');
	}
	else {
		load_plugin_textdomain(LOOKSEE_L10N, false, basename(LOOKSEE_PLUGIN_DIR) . '/languages');
	}
}
add_action('plugins_loaded', 'looksee_localize');

// --------------------------------------------------------------------- end functions
