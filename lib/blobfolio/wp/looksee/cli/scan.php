<?php
/**
 * CLI: File Scanning.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee\cli;

use \blobfolio\wp\looksee\files;
use \blobfolio\wp\looksee\options;
use \blobfolio\wp\looksee\scan as file_scan;
use \blobfolio\wp\looksee\vendor\common;
use \WP_CLI;
use \WP_CLI\Formatter;
use \WP_CLI\Utils;

// Add the main command.
if (!class_exists('WP_CLI') || !class_exists('WP_CLI_Command')) {
	return;
}

WP_CLI::add_command(
	'look-see scan',
	LOOKSEE_BASE_CLASS . 'cli\\scan',
	array(
		'before_invoke'=>function() {
			if (is_multisite()) {
				WP_CLI::error(__('This plugin cannot be used on Multi-Site.', LOOKSEE_L10N));
			}

			if (!options::is_pro()) {
				WP_CLI::error(__('A premium license is required.', LOOKSEE_L10N));
			}
		},
	)
);

/**
 * Look-See Security Scanner
 *
 * Scan the file system, looking for new, modified, or deleted files,
 * and check for other types of irregularities like suspicious code,
 * incorrect file permissions/ownerships, etc.
 */
class scan extends \WP_CLI_Command {

	// Default CLI scan settings.
	const SCAN = array(
		'batch_size'=>500,
		'blacklist'=>array(),
		'skip_cache'=>false,
		'skip_images'=>false,
		'skip_media'=>false,
		'skip_size'=>0,
	);

	/**
	 * Scan Files w/ Site Settings
	 *
	 * Scan the WordPress site for file changes, etc., using the saved
	 * site scan preferences.
	 *
	 * ## OPTIONS
	 *
	 * [--email]
	 * : Email summary to site administrator.
	 *
	 * [--summary]
	 * : Print summary. Use --no-summary to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--warnings]
	 * : Print warnings. Use --no-warnings to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--files]
	 * : Print new, missing, modified files. Use --no-files to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * @param array $args N/A.
	 * @param array $assoc_args Flags.
	 * @return bool True.
	 */
	public function run($args=null, $assoc_args=array()) {
		// Merge runtime arguments and stored settings to pass onto the
		// custom scan function, which will handle the real work.
		$saved = options::get('scan');
		$options = array(
			'email'=>!!Utils\get_flag_value($assoc_args, 'email', false),
			'files'=>!!Utils\get_flag_value($assoc_args, 'files', true),
			'max-size'=>$saved['skip_size'],
			'skip'=>implode(',', $saved['blacklist']),
			'skip-cache'=>$saved['skip_cache'],
			'skip-images'=>$saved['skip_images'],
			'skip-media'=>$saved['skip_media'],
			'summary'=>!!Utils\get_flag_value($assoc_args, 'summary', true),
			'warnings'=>!!Utils\get_flag_value($assoc_args, 'warnings', true),
		);

		return static::custom(array(), $options);
	}

	/**
	 * Scan Files
	 *
	 * Scan the WordPress site for file changes, etc. By default every
	 * file will be scanned, but this behavior can be changed by passing
	 * runtime arguments.
	 *
	 * ## OPTIONS
	 *
	 * [--skip-cache]
	 * : Ignore wp-content/cache.
	 *
	 * [--skip-images]
	 * : Ignore uploaded images.
	 *
	 * [--skip-media]
	 * : Ignore uploaded audio/video.
	 *
	 * [--skip=<ignorepath>...]
	 * : Ignore specific path(s). Separate multiple paths with a comma.
	 *
	 * [--max-size=<size>]
	 * : Max file size to scan in bytes.
	 *
	 * [--email]
	 * : Email summary to site administrator.
	 *
	 * [--summary]
	 * : Print summary. Use --no-summary to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--warnings]
	 * : Print warnings. Use --no-warnings to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--files]
	 * : Print new, missing, modified files. Use --no-files to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * @param array $args N/A.
	 * @param array $assoc_args Flags.
	 * @return bool True.
	 */
	public function custom($args=null, $assoc_args=array()) {
		$session = static::SCAN;

		if (!files::can_write()) {
			WP_CLI::error(
				sprintf(
					__('Several operations require the ability to write changes to the filesystem. This does not seem possible under the current configuration. See %s for possible workarounds.', LOOKSEE_L10N),
					'https://codex.wordpress.org/Editing_wp-config.php#WordPress_Upgrade_Constants'
				)
			);
		}

		// Runtime arguments.
		$options = array(
			'email'=>!!Utils\get_flag_value($assoc_args, 'email', false),
			'files'=>!!Utils\get_flag_value($assoc_args, 'files', true),
			'max-size'=>common\cast::to_int(Utils\get_flag_value($assoc_args, 'max-size', 0)),
			'skip'=>Utils\get_flag_value($assoc_args, 'skip', ''),
			'skip-cache'=>!!Utils\get_flag_value($assoc_args, 'skip-cache', false),
			'skip-images'=>!!Utils\get_flag_value($assoc_args, 'skip-images', false),
			'skip-media'=>!!Utils\get_flag_value($assoc_args, 'skip-media', false),
			'summary'=>!!Utils\get_flag_value($assoc_args, 'summary', true),
			'warnings'=>!!Utils\get_flag_value($assoc_args, 'warnings', true),
		);
		common\ref\sanitize::to_range($options['max-size'], 0);
		$options['skip'] = explode(',', $options['skip']);
		options::sanitize_blacklist($options['skip']);

		// Merge the runtimes into our scan settings.
		$session['blacklist'] = $options['skip'];
		$session['skip_cache'] = $options['skip-cache'];
		$session['skip_images'] = $options['skip-images'];
		$session['skip_media'] = $options['skip-media'];
		$session['skip_size'] = $options['max-size'];

		// Start or resume a scan.
		if (false === ($scan = file_scan::get_open_scan())) {
			$scan = new file_scan();
			if (!$scan->save(array('scan'=>$session))) {
				WP_CLI::error(
					__('A scan could not be started.', LOOKSEE_L10N)
				);
			}
			if ($options['summary']) {
				WP_CLI::success(
					sprintf(
						__('Starting Scan #%d.', LOOKSEE_L10N),
						$scan->get_scan_id()
					)
				);
			}
		}
		elseif ($options['summary']) {
			WP_CLI::success(
				sprintf(
					__('Resuming Scan #%d.', LOOKSEE_L10N),
					$scan->get_scan_id()
				)
			);
		}

		// Print the settings we're rolling with.
		if ($options['summary']) {
			$skipping = array();
			if ($scan->get_option('skip_cache')) {
				$skipping[] = __('cache', LOOKSEE_L10N);
			}
			if ($scan->get_option('skip_media')) {
				$skipping[] = __('audio/video', LOOKSEE_L10N);
			}
			if ($scan->get_option('skip_images')) {
				$skipping[] = __('images', LOOKSEE_L10N);
			}
			if (count($scan->get_option('blacklist'))) {
				$skipping[] = __('other', LOOKSEE_L10N);
			}
			if (count($skipping)) {
				WP_CLI::log(
					__('Skipping:', LOOKSEE_L10N) . ' ' . implode(', ', $skipping)
				);
			}
			$size = $scan->get_option('skip_size');
			if ($size > 0) {
				$size = round($size / 1024 / 1024, 1);
				WP_CLI::log(
					sprintf(
						__('Max File Size: %.1f MB', LOOKSEE_L10N),
						$size
					)
				);
			}
		}

		$scanning = true;
		$last_status = '';
		while ($scanning) {
			if ($options['summary']) {
				$tmp = $scan->get_status(true);
				if ($tmp !== $last_status) {
					$last_status = $tmp;
					WP_CLI::log($last_status);
				}
			}

			$scanning = $scan->scan();
		}

		// Email the results?
		if (!!Utils\get_flag_value($assoc_args, 'email')) {
			$scan->email();
		}

		WP_CLI::success(
			sprintf(
				__('Finished Scan #%d.', LOOKSEE_L10N),
				$scan->get_scan_id()
			)
		);

		$results = $scan->get_results();

		if ($results['error']) {
			WP_CLI::error(
				$results['status']
			);
		}

		if ($options['summary'] || $options['files'] || $options['warnings']) {
			return static::view(
				array($scan->get_scan_id()),
				array(
					'files'=>$options['files'],
					'summary'=>$options['summary'],
					'warnings'=>$options['warnings'],
				)
			);
		}

		return true;
	}

	/**
	 * List Completed File Scans
	 *
	 * View a quick overview of each saved file scans.
	 *
	 * @return bool True.
	 *
	 * @subcommand list
	 */
	public function _list() {
		global $wpdb;

		$dbResult = $wpdb->get_results("
			SELECT `scan_id`
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE `status`='finished'
			ORDER BY `date_finished` DESC
		", ARRAY_A);
		if (!count($dbResult)) {
			WP_CLI::error(
				__('No scans have been completed.', LOOKSEE_L10N)
			);
		}

		$headers = array(
			__('Scan ID', LOOKSEE_L10N),
			__('Finished', LOOKSEE_L10N),
			__('Elapsed', LOOKSEE_L10N),
			__('Status', LOOKSEE_L10N),
			__('Files', LOOKSEE_L10N),
			__('Scanned', LOOKSEE_L10N),
			__('Skipped', LOOKSEE_L10N),
			__('Warnings', LOOKSEE_L10N),
		);
		$data = array();
		foreach ($dbResult as $Row) {
			$scan = new file_scan($Row['scan_id']);
			$results = $scan->get_results();
			$data[] = array(
				'Scan ID'=>$results['scan_id'],
				'Finished'=>$results['date_finished'],
				'Elapsed'=>human_time_diff(strtotime($results['date_created']), strtotime($results['date_finished'])),
				'Status'=>$results['status'],
				'Files'=>$results['results']['total'],
				'Scanned'=>$results['results']['scanned'],
				'Skipped'=>$results['results']['skipped'],
				'Warnings'=>$results['results']['warnings'],
			);
		}

		WP_CLI::log('');
		Utils\format_items('table', $data, $headers);

		WP_CLI::success(
			__('Found scans', LOOKSEE_L10N) . ': ' . count($dbResult)
		);

		return true;
	}

	/**
	 * View File Scan Results
	 *
	 * View the results of a completed file scan.
	 *
	 * ## OPTIONS
	 *
	 * <scan_id>
	 * : The scan ID.
	 *
	 * [--summary]
	 * : Print summary. Use --no-summary to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--warnings]
	 * : Print warnings. Use --no-warnings to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * [--files]
	 * : Print new, missing, modified files. Use --no-files to negate.
	 * ---
	 * default: true
	 * ---
	 *
	 * @param array $args N/A.
	 * @param array $assoc_args Flags.
	 * @return bool True.
	 */
	public function view($args=null, $assoc_args=array()) {
		$scan_id = common\data::array_pop_top($args);
		common\ref\cast::to_int($scan_id);

		$scan = new file_scan($scan_id);
		if (!$scan->is_scan()) {
			WP_CLI::error(
				__('Invalid scan.', LOOKSEE_L10N)
			);
		}
		elseif ('finished' !== $scan->get_status()) {
			WP_CLI::error(
				__('This scan has not yet completed.', LOOKSEE_L10N)
			);
		}

		// Runtime arguments.
		$options = array(
			'files'=>!!Utils\get_flag_value($assoc_args, 'files', true),
			'summary'=>!!Utils\get_flag_value($assoc_args, 'summary', true),
			'warnings'=>!!Utils\get_flag_value($assoc_args, 'warnings', true),
		);

		if (!$options['files'] && !$options['summary'] && !$options['warnings']) {
			WP_CLI::error(
				__('You have disabled all output. Haha.', LOOKSEE_L10N)
			);
		}

		$results = $scan->get_results();

		if ($results['error']) {
			WP_CLI::error(
				$results['status']
			);
		}

		if ($options['summary']) {
			$headers = array(
				__('Finished', LOOKSEE_L10N),
				__('Elapsed', LOOKSEE_L10N),
				__('Status', LOOKSEE_L10N),
				__('Files', LOOKSEE_L10N),
				__('Scanned', LOOKSEE_L10N),
				__('Skipped', LOOKSEE_L10N),
				__('Warnings', LOOKSEE_L10N),
			);
			$data = array(
				array(
					'Finished'=>$results['date_finished'],
					'Elapsed'=>human_time_diff(strtotime($results['date_created']), strtotime($results['date_finished'])),
					'Status'=>$results['status'],
					'Files'=>$results['results']['total'],
					'Scanned'=>$results['results']['scanned'],
					'Skipped'=>$results['results']['skipped'],
					'Warnings'=>$results['results']['warnings'],
				),
			);
			WP_CLI::log('');
			Utils\format_items('table', $data, $headers);
		}

		if ($options['warnings'] && $results['results']['warnings']) {
			$headers = array(
				__('Warning', LOOKSEE_L10N),
				__('Core', LOOKSEE_L10N),
				__('File', LOOKSEE_L10N),
			);
			$data = array();
			foreach ($results['details']['warnings'] as $v) {
				$data[] = array(
					'Warning'=>$v['warningText'],
					'Core'=>($v['type'] ? __('Yes', LOOKSEE_L10N) : ''),
					'File'=>$v['file'],
				);
			}
			WP_CLI::log('');
			Utils\format_items('table', $data, $headers);
		}

		if (
			$options['files'] &&
			(
				count($results['details']['modified']) ||
				count($results['details']['deleted']) ||
				count($results['details']['new'])
			)
		) {
			$headers = array(
				__('Status', LOOKSEE_L10N),
				__('Core', LOOKSEE_L10N),
				__('File', LOOKSEE_L10N),
			);
			$fields = array(
				'modified'=>__('Modified', LOOKSEE_L10N),
				'deleted'=>__('Deleted', LOOKSEE_L10N),
				'new'=>__('New', LOOKSEE_L10N),
			);
			$data = array();
			foreach ($fields as $k=>$v) {
				foreach ($results['details'][$k] as $v2) {
					$data[] = array(
						'Status'=>$v,
						'Core'=>($v2['type'] ? __('Yes', LOOKSEE_L10N) : ''),
						'File'=>$v2['file'],
					);
				}
			}
			WP_CLI::log('');
			Utils\format_items('table', $data, $headers);
		}

		return true;
	}
}
