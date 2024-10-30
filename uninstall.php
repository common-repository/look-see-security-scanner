<?php
/**
 * Look-See Security Scanner - Uninstall
 *
 * Parting is such sweet sorrow.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

/**
 * Do not execute this file directly.
 */
if (!defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}

// Get rid of the options we've been saving.
$options = array(
	'looksee_db_version',
	'looksee_options',
	'looksee_remote_sync',
);
foreach ($options as $v) {
	delete_option($v);
}

// Try to remove the database tables.
global $wpdb;
$tables = array(
	"{$wpdb->prefix}looksee3_core",
	"{$wpdb->prefix}looksee3_scan_files",
	"{$wpdb->prefix}looksee3_scan_warnings",
	"{$wpdb->prefix}looksee3_scans",
);
foreach ($tables as $v) {
	$wpdb->query("DROP TABLE IF EXISTS `$v`");
}

// Remove CRON jobs.
$actions = array(
	'looksee_cron_expired_transients',
	'looksee_cron_scan',
);
foreach ($actions as $v) {
	if (false !== ($timestamp = wp_next_scheduled($v))) {
		wp_unschedule_event($timestamp, $v);
	}
}

// Try to remove our temporary directory.
$uploads_dir = wp_upload_dir();
$uploads_dir = trailingslashit($uploads_dir['basedir']);
if (@is_dir("{$uploads_dir}_look-see")) {
	@rmdir("{$uploads_dir}_look-see");
}
