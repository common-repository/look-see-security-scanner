<?php
/**
 * Look-See Security Scanner AJAX handlers.
 *
 * All AJAX methods point back to here.
 *
 * Program error: 500
 * Bad request: 400
 * Invalid/missing authorization: 401
 * Authorized but not allowed: 403
 * Rate limiting: 429
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee;

use \blobfolio\wp\looksee\vendor\common;

class ajax {

	// The true action name matches the callback, but is prefixed.
	const ACTIONS = array(
		'file_delete',
		'file_fix',
		'file_ignore',
		'file_view',
		'pro',
		'scan',
		'scan_abort',
		'scan_history',
		'settings',
	);

	// All responses are JSON, with these parts.
	const RESPONSE = array(
		'data'=>array(),
		'errors'=>array(),
		'msg'=>'',
		'status'=>200,
	);

	// Action for Nonces.
	const NONCE = 'looksee-nonce';



	// -----------------------------------------------------------------
	// Init/Setup
	// -----------------------------------------------------------------

	protected static $_init = false;

	/**
	 * Register Actions
	 *
	 * @return bool True/false.
	 */
	public static function init() {
		// Only need to do this once.
		if (static::$_init) {
			return true;
		}
		static::$_init = true;

		$class = get_called_class();
		foreach (static::ACTIONS as $action) {
			add_action("wp_ajax_looksee_ajax_$action", array($class, $action));
		}

		return true;
	}

	/**
	 * Generate Nonce
	 *
	 * @return string Nonce.
	 */
	public static function get_nonce() {
		return wp_create_nonce(static::NONCE);
	}

	/**
	 * Parse Request
	 *
	 * A generic action to sanitize $_POST and do some global error
	 * checking.
	 *
	 * @param array $data Data.
	 * @param bool $nonce Check Nonce.
	 * @param bool $pro Require pro.
	 * @return array Response.
	 */
	protected static function parse(&$data, $nonce=true, $pro=false) {
		common\ref\cast::to_array($data);
		$data = stripslashes_deep($data);
		$out = static::RESPONSE;

		// Check Nonce?
		if ($nonce) {
			if (!isset($data['n']) || !wp_verify_nonce($data['n'], static::NONCE)) {
				$out['errors']['other'] = __('The form had expired. Please try again.', LOOKSEE_L10N);
				$out['status'] = 400;
			}
		}

		// There are no non-admin AJAX calls.
		if (!is_user_logged_in()) {
			$out['errors']['other'] = __('You must be logged in to complete this action.', LOOKSEE_L10N);
			$out['status'] = 401;
		}
		elseif (!current_user_can('manage_options')) {
			$out['errors']['other'] = __('You are not authorized to complete this action.', LOOKSEE_L10N);
			$out['status'] = 403;
		}

		// Require pro?
		if ($pro && !options::is_pro()) {
			$out['errors']['pro'] = __('A premium license is required.', LOOKSEE_L10N);
			$out['status'] = 403;
		}

		return $out;
	}

	/**
	 * Send Response
	 *
	 * AJAX responses are JSON formatted. Status codes indicate yay/nay.
	 *
	 * @param array $data Data.
	 * @return void Nothing.
	 */
	protected static function send(&$data) {
		$out = common\data::parse_args($data, static::RESPONSE);

		// Errors should indicate an errory response, while the lack of
		// errors should mean success.
		if (count($out['errors']) && common\data::in_range($out['status'], 200, 399)) {
			$out['status'] = 400;
		}
		elseif (!count($out['errors']) && !common\data::in_range($out['status'], 200, 399)) {
			$out['status'] = 200;
		}

		// Pass it on!
		common\ref\sanitize::utf8($out);
		wp_send_json($out, $out['status']);
	}

	// ----------------------------------------------------------------- end init



	// -----------------------------------------------------------------
	// Handlers
	// -----------------------------------------------------------------

	/**
	 * File by Action
	 *
	 * Only certain scans and certain files are actionable, and then the
	 * possible actions vary. This will return information about a file
	 * if the conditions match.
	 *
	 * @param int $scan_id Scan ID.
	 * @param string $file_hash File hash.
	 * @param string $action Action.
	 * @return bool|array File or false.
	 */
	protected static function file_by_action($scan_id, $file_hash, $action) {
		common\ref\cast::to_int($scan_id, true);
		common\ref\cast::to_string($file_hash, true);
		common\ref\cast::to_string($action, true);

		if (
			!$scan_id ||
			!$file_hash ||
			!$action ||
			!files::can_write()
		) {
			return false;
		}

		$scan = new scan($scan_id);
		if (false !== ($results = $scan->get_results())) {
			// Look for the file.
			foreach ($results['details']['warnings'] as $v) {
				if ($v['hash'] === $file_hash) {
					if (in_array($action, $v['actions'], true)) {
						return $v;
					}
				}
			}
		}

		return false;
	}

	/**
	 * File: Delete
	 *
	 * Remove a troublesome file. This will remove corresponding
	 * attachments if needed, etc.
	 *
	 * @return void Nothing.
	 */
	public static function file_delete() {
		global $wpdb;

		$out = static::parse($_POST, true, true);
		$out['data'] = array('success'=>false);

		if (!count($out['errors'])) {
			$default = array(
				'scan_id'=>0,
				'file_hash'=>'',
			);
			$data = common\data::parse_args($_POST, $default);

			if (false === ($file = static::file_by_action($data['scan_id'], $data['file_hash'], 'delete'))) {
				$out['errors']['scan'] = __('The file could not be deleted. Please use FTP or SSH instead.', LOOKSEE_L10N);
			}
			else {
				$path = files::get_base_dir() . $file['file'];
				$upload_dir = files::get_uploads_dir();

				// Is this an attachment?
				$attachment_id = 0;
				$length_uploads = common\mb::strlen($upload_dir);
				if (common\mb::substr($file['file'], 0, $length_uploads) === $upload_dir) {
					$chunk = esc_sql(common\mb::substr($file['file'], $length_uploads));
					$out['data']['debug'][] = $chunk;
					$attachment_id = (int) $wpdb->get_var("
						SELECT `post_id`
						FROM
							`{$wpdb->postmeta}` AS m LEFT JOIN
							`{$wpdb->posts}` AS p ON p.ID=m.post_id
						WHERE
							m.meta_key='_wp_attached_file' AND
							m.meta_value='$chunk' AND
							p.post_type='attachment'
					");
				}

				// Delete an attachment.
				if ($attachment_id) {
					wp_delete_attachment($attachment_id, true);
				}
				// Delete a regular file.
				else {
					@unlink($path);
				}

				if (!@file_exists($path)) {
					$out['data']['success'] = true;
					$wpdb->delete(
						"{$wpdb->prefix}looksee3_scan_warnings",
						array(
							'scan_id'=>$data['scan_id'],
							'file_hash'=>$data['file_hash'],
						),
						array('%d', '%s')
					);
				}
				else {
					$out['errors']['scan'] = __('The file could not be deleted. Please use FTP or SSH instead.', LOOKSEE_L10N);
				}
			}
		}

		static::send($out);
	}

	/**
	 * File: Fix
	 *
	 * Fix ownership and file permissions automatically, if possible.
	 *
	 * @return void Nothing.
	 */
	public static function file_fix() {
		global $wpdb;

		$out = static::parse($_POST, true, true);
		$out['data'] = array('success'=>false);

		if (!count($out['errors'])) {
			$default = array(
				'scan_id'=>0,
				'file_hash'=>'',
			);
			$data = common\data::parse_args($_POST, $default);

			if (false === ($file = static::file_by_action($data['scan_id'], $data['file_hash'], 'fix'))) {
				$out['errors']['scan'] = __('The file could not be automatically fixed.', LOOKSEE_L10N);
			}
			else {
				$chmod = files::chmod();
				list($chown, $chgrp) = explode(':', files::chown());
				$file = files::get_base_dir() . $file['file'];

				// We need to convert our "nice" permissions back to
				// the appropriate octal equivalent before adjusting.
				$chmod_octal = intval(str_pad(strval($chmod), 4, '0', STR_PAD_LEFT), 8);
				@chmod($file, $chmod_octal);
				@chown($file, $chown);
				@chgrp($file, $chgrp);

				if (
					(files::get_chmod($file) === $chmod) &&
					(files::get_owner($file) === $chown) &&
					(files::get_group($file) === $chgrp)
				) {
					$out['data']['success'] = true;
					$wpdb->query("
						DELETE FROM `{$wpdb->prefix}looksee3_scan_warnings`
						WHERE
							`scan_id`={$data['scan_id']} AND
							`file_hash`='" . esc_sql($data['file_hash']) . "' AND
							`warning` IN ('chmod','chown')
					");
				}
				else {
					$out['errors']['scan'] = __('The file could not be automatically fixed.', LOOKSEE_L10N);
				}
			}
		}

		static::send($out);
	}

	/**
	 * File: Ignore
	 *
	 * Add a file to the ignore list.
	 *
	 * @return void Nothing.
	 */
	public static function file_ignore() {
		global $wpdb;

		$out = static::parse($_POST, true, true);
		$out['data'] = array('success'=>false);

		if (!count($out['errors'])) {
			$default = array(
				'scan_id'=>0,
				'file_hash'=>'',
			);
			$data = common\data::parse_args($_POST, $default);

			if (false === ($file = static::file_by_action($data['scan_id'], $data['file_hash'], 'ignore'))) {
				$out['errors']['scan'] = __('An ignore rule could not be created automatically; please try adding it yourself.', LOOKSEE_L10N);
			}
			else {
				$scan = options::get('scan');
				$scan['blacklist'][] = $file['file'];
				options::save('scan', $scan);

				$out['data']['success'] = true;
				$out['data']['blacklist'] = implode("\n", options::get('scan-blacklist'));

				$wpdb->delete(
					"{$wpdb->prefix}looksee3_scan_warnings",
					array(
						'scan_id'=>$data['scan_id'],
						'file_hash'=>$data['file_hash'],
					),
					array('%d', '%s')
				);
			}
		}

		static::send($out);
	}

	/**
	 * File: View
	 *
	 * @return void Nothing.
	 */
	public static function file_view() {

		$out = static::parse($_POST, true, true);
		$out['data'] = array(
			'success'=>false,
			'file'=>array(
				'content'=>'',
				'language'=>'',
				'path'=>'',
			),
		);

		if (!count($out['errors'])) {
			$default = array(
				'scan_id'=>0,
				'file_hash'=>'',
			);
			$data = common\data::parse_args($_POST, $default);

			if (false === ($file = static::file_by_action($data['scan_id'], $data['file_hash'], 'view'))) {
				$out['errors']['scan'] = __('The requested file cannot be viewed. Please use FTP instead.', LOOKSEE_L10N);
			}
			else {
				$out['data']['file']['content'] = (string) @file_get_contents(files::get_base_dir() . $file['file']);
				if ($out['data']['file']['content']) {
					// Make vertical whitespace consistent.
					$out['data']['file']['content'] = str_replace("\r\n", "\n", $out['data']['file']['content']);
					$out['data']['file']['content'] = preg_replace("/\v/ui", "\n", $out['data']['file']['content']);

					$out['data']['file']['path'] = $file['file'];
					$fileext = strtolower(pathinfo($file['file'], PATHINFO_EXTENSION));

					$languages = array(
						'css'=>'css',
						'htm'=>'markup',
						'html'=>'markup',
						'js'=>'javascript',
						'md'=>'markdown',
						'php'=>'php',
					);
					$out['data']['file']['language'] = isset($languages[$fileext]) ? $languages[$fileext] : 'text';

					$out['data']['success'] = true;
				}
				else {
					$out['errors']['scan'] = __('The requested file cannot be viewed. Please use FTP instead.', LOOKSEE_L10N);
				}
			}
		}

		static::send($out);
	}

	/**
	 * Pro
	 *
	 * Save license changes.
	 *
	 * @return void Nothing.
	 */
	public static function pro() {
		$out = static::parse($_POST);

		if (!isset($_POST['license'])) {
			$_POST['license'] = '';
		}

		if (!count($out['errors'])) {
			// Empty license, just save it.
			if (!$_POST['license']) {
				options::save('license', '');
			}
			// Maybe a real one.
			else {
				$license = license::get($_POST['license']);

				if ($license->is_license()) {
					options::save('license', $license->get_raw());
				}
				else {
					$out['errors']['license'] = __('The license is not valid.', LOOKSEE_L10N);
				}
			}
		}

		// Send back some data.
		if (!count($out['errors'])) {
			$out['data']['license_key'] = options::get('license');
			$license = license::get($out['data']['license_key']);
			$out['data']['license'] = $license->get_license();
		}

		static::send($out);
	}

	/**
	 * File Scan
	 *
	 * This is a gateway of sorts. More specific functions handle each
	 * individual step.
	 *
	 * @return void Nothing.
	 */
	public static function scan() {
		global $wpdb;
		$out = static::parse($_POST);

		$out['data'] = scan::PROGRESS;

		if (!count($out['errors']) && scan::is_locked()) {
			$out['errors']['other'] = __('Someone else is currently running their own scan. Please try again in a couple minutes.', LOOKSEE_L10N);
		}

		if (!count($out['errors'])) {
			$out['data'] = common\data::parse_args($_POST, $out['data']);

			// We have a Scan ID.
			if ($out['data']['scan_id']) {
				$scan = new scan($out['data']['scan_id']);
			}
			// Look for an existing scan.
			elseif (false === ($scan = scan::get_open_scan())) {
				$scan = new scan();
				$scan->save();
			}

			if (!is_object($scan) || !$scan->is_scan()) {
				$out['errors']['other'] = __('Invalid scan.', LOOKSEE_L10N);
				$out['status'] = 404;
			}
			else {
				$scan::set_lock();
				$scan->scan();
				$out['data'] = $scan->get_progress();
				$out['status'] = 200;
			}
		}

		static::send($out);
	}

	/**
	 * File Scan Abort
	 *
	 * We can't interrupt a call that's already been placed, but we can
	 * store a value in the database that'll trigger closure next time
	 * it's called.
	 *
	 * @return void Nothing.
	 */
	public static function scan_abort() {
		global $wpdb;
		$out = static::parse($_POST);
		$out['data']['success'] = false;

		if (!count($out['errors'])) {
			if (false !== ($scan = scan::get_open_scan())) {
				$out['data']['success'] = true;
				set_transient('looksee_scan_abort', 1, 600);
			}
		}

		static::send($out);
	}

	/**
	 * File Scan History
	 *
	 * Pull the results of past file scans.
	 *
	 * @return void Nothing.
	 */
	public static function scan_history() {
		global $wpdb;
		$out = static::parse($_POST);
		$out['data']['results'] = array();

		if (!count($out['errors'])) {
			// Regular warnings still apply to core files matching...
			$warnings = array('core-modified', 'chmod', 'chown', 'timeout');

			$dbResult = $wpdb->get_results("
				SELECT `scan_id`
				FROM `{$wpdb->prefix}looksee3_scans`
				WHERE `status`='finished'
				ORDER BY `date_created` DESC
			", ARRAY_A);
			if (is_array($dbResult) && count($dbResult)) {
				foreach ($dbResult as $Row) {
					$scan = new scan($Row['scan_id']);
					$tmp = $scan->get_results();

					// Let's give Javascript a hand and calculate some
					// of what it would struggle to do.
					$tmp['details']['actionable'] = false;
					$tmp['details']['actionable_core'] = false;
					$tmp['details']['warning_types'] = array();
					$tmp['details']['warnings_core'] = array();
					$tmp['results']['warnings_core'] = 0;

					// Parse the warnings a bit.
					foreach ($tmp['details']['warnings'] as $k=>$v) {
						// This should be a "core" warning.
						if (
							$v['type'] &&
							!in_array($v['warning'], $warnings, true)
						) {
							$tmp['details']['warnings_core'][] = $v;
							unset($tmp['details']['warnings'][$k]);

							if (!$tmp['details']['actionable_core'] && count($v['actions'])) {
								$tmp['details']['actionable_core'] = true;
							}

							continue;
						}

						$tmp['details']['warning_types'][] = $v['warningText'];
						if (!$tmp['details']['actionable'] && count($v['actions'])) {
							$tmp['details']['actionable'] = true;
						}
					}

					// Clean up data.
					$tmp['details']['warnings'] = array_values($tmp['details']['warnings']);
					$tmp['details']['warning_types'] = array_unique($tmp['details']['warning_types']);
					sort($tmp['details']['warning_types']);

					// Rerun totals.
					$tmp['results']['warnings'] = count($tmp['details']['warnings']);
					$tmp['results']['warnings_core'] = count($tmp['details']['warnings_core']);

					$out['data']['results'][] = $tmp;
				}
			}
		}

		static::send($out);
	}

	/**
	 * Settings
	 *
	 * Save the plugin settings, except for license.
	 *
	 * @return void Nothing.
	 */
	public static function settings() {
		$out = static::parse($_POST);

		if (!count($out['errors'])) {
			// Convert the blacklist back to an array.
			if (isset($_POST['scan']['blacklist'])) {
				common\ref\cast::to_string($_POST['scan']['blacklist'], true);
				common\ref\sanitize::whitespace($_POST['scan']['blacklist'], 1);
				$_POST['scan']['blacklist'] = explode("\n", $_POST['scan']['blacklist']);
			}

			// Convert the max size back to bytes.
			if (isset($_POST['scan']['skip_size'])) {
				common\ref\cast::to_float($_POST['scan']['skip_size'], true);
				$_POST['scan']['skip_size'] = ceil($_POST['scan']['skip_size'] * 1024 * 1024);
			}

			// Shove the settings into the mold.
			$original = options::get();
			$data = common\data::parse_args($_POST, $original);

			// Except license, that gets set somewhere else.
			$data['license'] = $original['license'];

			// And save the values. No need to validate; it will
			// sanitize as soon as the values are loaded, which we'll do
			// shortly.
			update_option(options::OPTION_NAME, $data);
			options::load(true);
			$out['data'] = options::get();

			// Almost done. We need to adjust a few formatting details
			// to help out Vue.js.
			unset($out['data']['license']);

			// Convert bools back to ints.
			foreach ($out['data'] as $k=>$v) {
				if (is_array($v)) {
					foreach ($out['data'][$k] as $k2=>$v2) {
						if (is_bool($v2)) {
							common\ref\cast::to_int($out['data'][$k][$k2]);
						}
						elseif (is_array($v2)) {
							foreach ($out['data'][$k][$k2] as $k3=>$v3) {
								if (is_bool($v3)) {
									common\ref\cast::to_int($out['data'][$k][$k2][$k3]);
								}
							}
						}
					}
				}
			}

			$out['data']['scan']['skip_size'] = round($out['data']['scan']['skip_size'] / 1024 / 1024, 1);
			$out['data']['scan']['blacklist'] = implode("\n", $out['data']['scan']['blacklist']);

			$out['status'] = 200;
		}

		static::send($out);
	}

	// ----------------------------------------------------------------- end handlers


}
