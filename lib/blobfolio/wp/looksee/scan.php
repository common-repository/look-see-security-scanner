<?php
/**
 * Look-See Security Scanner.
 *
 * Everything you ever wanted to know about scanning but were afraid to
 * ask.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee;

use \blobfolio\wp\looksee\vendor\common;
use \WP_User;

class scan {

	const STATUSES = array(
		'created',
		'building-core',
		'building-plugins',
		'building-themes',
		'building-local',
		'building-history',
		'scanning',
		'finished',
	);

	const PROGRESS = array(
		'progress'=>0.0,
		'scan_id'=>0,
		'status'=>'',
		'tries'=>0,
	);

	// Scan errors.
	const ERRORS = array(
		'timeout',
		'user-abort',
		'other',
	);

	// File warnings.
	const WARNINGS = array(
		'chmod',
		'chown',
		'core-extra',
		'core-missing',
		'core-modified',
		'core-old',
		'dev-file',
		'mime',
		'php-eval',
		'php-gibberish',
		'php-phpinfo',
		'php-system',
		'timeout',
	);

	const TEMPLATE = array(
		'scan_id'=>0,
		'scheduled'=>0,
		'user_id'=>0,
		'date_created'=>'0000-00-00 00:00:00',
		'date_finished'=>'0000-00-00 00:00:00',
		'status'=>'created',
		'tries'=>0,
		'details'=>array(),
		'error'=>'',
	);

	const DETAILS = array(
		'core'=>array(),
		'plugins'=>array(),
		'scan'=>array(),
		'themes'=>array(),
	);

	// The database chunk size.
	const CHUNK = 100;

	const SYSTEM_FUNCTIONS = array(
		'exec',
		'passthru',
		'proc_open',
		'shell_exec',
		'system',
	);

	protected $data;

	// -----------------------------------------------------------------
	// Init/Setup
	// -----------------------------------------------------------------

	/**
	 * Constructor
	 *
	 * @param int $scan_id Scan ID.
	 * @return bool True/false.
	 */
	public function __construct($scan_id=0) {
		global $wpdb;

		common\ref\cast::to_int($scan_id, true);

		$this->data = static::TEMPLATE;
		files::scan_init();

		if ($scan_id <= 0) {
			return false;
		}

		$dbResult = $wpdb->get_results("
			SELECT *
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE `scan_id`=$scan_id
		", ARRAY_A);
		if (!is_array($dbResult) || !count($dbResult)) {
			return false;
		}
		$Row = common\data::array_pop_top($dbResult);

		// Real-quick, de-JSON-ify our details.
		static::sanitize_details($Row['details']);

		// Shove it all into our template.
		$this->data = common\data::parse_args($Row, static::TEMPLATE);

		// Sanitize dates.
		common\ref\sanitize::datetime($this->data['date_created']);
		if ('finished' === $this->data['status']) {
			common\ref\sanitize::datetime($this->data['date_finished']);
		}
		else {
			$this->data['date_finished'] = '0000-00-00 00:00:00';
		}
		if (
			('0000-00-00 00:00:00' !== $this->data['date_finished']) &&
			$this->data['date_created'] > $this->data['date_finished']
		) {
			common\data::switcheroo($this->data['date_created'], $this->data['date_finished']);
		}

		// Make sure we stay positive.
		common\ref\sanitize::to_range($this->data['user_id'], 0);
		common\ref\sanitize::to_range($this->data['tries'], 0);

		// Scheduling has been removed.
		$this->data['scheduled'] = 0;

		// If the status is bad, call it finished.
		if (!in_array($this->data['status'], static::STATUSES, true)) {
			return $this->finish('other');
		}

		// Bad error.
		if ($this->data['error']) {
			if (
				('finished' !== $this->data['status']) ||
				!in_array($this->data['error'], static::ERRORS, true)
			) {
				return $this->save(array('error'=>''));
			}
		}

		files::scan_init($this->data['details']['scan']);

		return true;
	}

	/**
	 * Is Scan
	 *
	 * @return bool True/false.
	 */
	public function is_scan() {
		return (
			is_array($this->data) &&
			isset($this->data['scan_id']) &&
			$this->data['scan_id'] > 0
		);
	}

	// ----------------------------------------------------------------- end init



	// -----------------------------------------------------------------
	// Get Data
	// -----------------------------------------------------------------

	/**
	 * Magic Getter
	 *
	 * @param string $method Method name.
	 * @param mixed $args Arguments.
	 * @return mixed Variable.
	 * @throws \Exception Invalid method.
	 */
	public function __call($method, $args) {
		preg_match_all('/^get_(.+)$/', $method, $matches);
		if (
			count($matches[0]) &&
			(isset($this->data[$matches[1][0]]) || array_key_exists($matches[1][0], static::TEMPLATE))
		) {
			$variable = $matches[1][0];
			$value = isset($this->data[$variable]) ? $this->data[$variable] : static::TEMPLATE[$variable];

			// Dates.
			if (0 === strpos($variable, 'date')) {
				if (is_array($args) && count($args)) {
					$args = common\data::array_pop_top($args);
					common\ref\cast::to_string($args, true);
				}
				else {
					$args = 'Y-m-d H:i:s';
				}
				return date($args, strtotime($value));
			}

			// Everything else.
			return $value;
		}

		throw new \Exception(
			sprintf(
				__('The required method "%s" does not exist for %s', LOOKSEE_L10N),
				$method,
				get_called_class()
			)
		);
	}

	/**
	 * Get Option
	 *
	 * @param string $key Key.
	 * @return mixed Option or false.
	 */
	public function get_option($key=null) {
		if (!$this->is_scan() || !isset($this->data['details']['scan'][$key])) {
			return false;
		}

		return $this->data['details']['scan'][$key];
	}

	/**
	 * Get Progress
	 *
	 * @return array Progress.
	 */
	public function get_progress() {
		global $wpdb;
		$progress = static::PROGRESS;

		if ($this->is_scan()) {
			$progress['scan_id'] = $this->get_scan_id();
			$progress['tries'] = $this->get_tries();
			$progress['status'] = $this->get_status();
			$progress['statusText'] = $this->get_status(true);

			// We don't really need to calculate progress except for
			// the "scanning" status.
			$progress['progress'] = 0.0;
			if ('scanning' === $this->get_status()) {
				$total = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee3_scan_files` WHERE `scan_id`={$progress['scan_id']}");
				$scanned = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee3_scan_files` WHERE `scan_id`={$progress['scan_id']} AND `status` != ''");
				$progress['progress'] = $total > 0 ? round($scanned / $total * 100, 1) : 0.0;
			}
		}

		return $progress;
	}

	/**
	 * Get Results
	 *
	 * @return bool|array Results or false.
	 */
	public function get_results() {
		global $wpdb;

		if (!$this->is_scan() || ('finished' !== $this->get_status())) {
			return false;
		}

		$out = array(
			'scan_id'=>$this->get_scan_id(),
			'status'=>$this->get_status(true),
			'date_created'=>$this->get_date_created(),
			'date_finished'=>$this->get_date_finished(),
			'elapsed'=>strtotime($this->get_date_finished()) - strtotime($this->get_date_created()),
			'env'=>$this->get_details(),
			'error'=>!!$this->get_error(),
			'latest'=>!intval($wpdb->get_var("
				SELECT COUNT(*)
				FROM `{$wpdb->prefix}looksee3_scans`
				WHERE
					`status`='finished' AND
					`date_finished` > '" . $this->get_date_finished() . "'
			")),
			'scheduled'=>!!$this->get_scheduled(),
			'results'=>array(
				'total'=>0,
				'scanned'=>0,
				'skipped'=>0,
				'warnings'=>0,
			),
			'details'=>array(
				'deleted'=>array(),
				'modified'=>array(),
				'new'=>array(),
				'warnings'=>array(),
			),
		);

		$warnings = array(
			'chmod'=>__('File Permissions', LOOKSEE_L10N),
			'chown'=>__('File Owner', LOOKSEE_L10N),
			'core-extra'=>__('Extra Core File', LOOKSEE_L10N),
			'core-missing'=>__('Missing Core File', LOOKSEE_L10N),
			'core-modified'=>__('Modified Core File', LOOKSEE_L10N),
			'core-old'=>__('Deprecated Core File', LOOKSEE_L10N),
			'dev-file'=>__('Developer/System File', LOOKSEE_L10N),
			'mime'=>__('File Type', LOOKSEE_L10N),
			'php-eval'=>__('eval()', LOOKSEE_L10N),
			'php-gibberish'=>__('Unusual Data', LOOKSEE_L10N),
			'php-phpinfo'=>__('phpinfo()', LOOKSEE_L10N),
			'php-system'=>__('Unix System Call', LOOKSEE_L10N),
			'timeout'=>__('Timeout Error', LOOKSEE_L10N),
		);

		if (!$out['error']) {
			$scanned_statuses = array('new', 'modified', 'ok');

			// Get the totals.
			$dbResult = $wpdb->get_results("
				SELECT
					`status`,
					COUNT(*) AS `count`
				FROM `{$wpdb->prefix}looksee3_scan_files`
				WHERE `scan_id`={$out['scan_id']}
				GROUP BY `status`
			", ARRAY_A);
			foreach ($dbResult as $Row) {
				$count = (int) $Row['count'];
				$out['results']['total'] += $count;
				if (in_array($Row['status'], $scanned_statuses, true)) {
					$out['results']['scanned'] += $count;
				}
				else {
					$out['results']['skipped'] += $count;
				}
			}

			$statuses = array('deleted', 'modified');
			if (intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee3_scans` WHERE `status`='finished' AND NOT(LENGTH(`error`))")) > 1) {
				$statuses[] = 'new';
			}
			$statuses = "'" . implode("','", $statuses) . "'";

			// Pull actual examples.
			$dbResult = $wpdb->get_results("
				SELECT
					`status`,
					`file_hash`,
					`file_path`,
					`type`
				FROM `{$wpdb->prefix}looksee3_scan_files`
				WHERE
					`scan_id`={$out['scan_id']} AND
					`status` IN ($statuses)
				ORDER BY `file_path` ASC
			", ARRAY_A);
			if (is_array($dbResult) && count($dbResult)) {
				foreach ($dbResult as $Row) {
					// We don't need to draw attention to modified core Readmes.
					if ($Row['type']) {
						if (preg_match('/^readme\.(html?|md|txt)$/ui', basename($Row['file_path']))) {
							continue;
						}
					}

					$out['details'][$Row['status']][] = array(
						'file'=>$Row['file_path'],
						'hash'=>$Row['file_hash'],
						'type'=>$Row['type'],
					);
				}
			}

			// Actions only apply to the latest scan.
			$has_actions = (
				options::is_pro() &&
				$out['latest']
			);

			// Lastly, pull warnings.
			$dbResult = $wpdb->get_results("
				SELECT
					w.warning,
					w.file_hash,
					f.file_path,
					f.mime,
					f.chmod,
					f.chown,
					f.type,
					f.size
				FROM
					`{$wpdb->prefix}looksee3_scan_warnings` AS w LEFT JOIN
					`{$wpdb->prefix}looksee3_scan_files` AS f ON
						f.scan_id=w.scan_id AND
						f.file_hash=w.file_hash
				WHERE w.scan_id={$out['scan_id']}
				ORDER BY f.file_path ASC
			", ARRAY_A);
			if (is_array($dbResult) && count($dbResult)) {
				foreach ($dbResult as $Row) {
					$tmp = array(
						'warning'=>$Row['warning'],
						'warningText'=>$warnings[$Row['warning']],
						'type'=>$Row['type'],
						'file'=>$Row['file_path'],
						'hash'=>$Row['file_hash'],
						'extra'=>'',
						'actions'=>array('ignore'),
					);

					switch ($Row['warning']) {
						case 'mime':
							$tmp['extra'] = $Row['mime'];
							if (!$Row['type']) {
								$tmp['actions'][] = 'delete';
							}
							break;
						case 'chmod':
							$tmp['extra'] = (int) $Row['chmod'];
							$tmp['actions'][] = 'fix';
							break;
						case 'chown':
							$tmp['extra'] = $Row['chown'];
							$tmp['actions'][] = 'fix';
							break;
						case 'dev-file':
							$tmp['actions'][] = 'delete';
							break;
						case '':
							if ('php' === substr($Row['warning'], 0, 3)) {
								$tmp['actions'][] = 'delete';
							}
							break;
					}

					// We can offer to let them view certain types of
					// text files, but only if the type is valid and the
					// file isn't too big.
					$Row['size'] = (int) $Row['size'];
					$fileext = strtolower(pathinfo($Row['file_path'], PATHINFO_EXTENSION));
					if (
						$fileext &&
						$Row['size'] > 0 &&
						$Row['size'] <= 512000 &&
						preg_match('/\.(css|html?|js|log|md|php|txt)$/ui', $Row['file_path']) &&
						common\mime::check_ext_and_mime($fileext, $Row['mime'])
					) {
						$tmp['actions'][] = 'view';
					}

					// Again, actions are only for the latest scan.
					if (
						$has_actions &&
						@is_file(files::get_base_dir() . $Row['file_path'])
					) {
						$tmp['actions'] = array_unique($tmp['actions']);
						sort($tmp['actions']);
					}
					else {
						$tmp['actions'] = array();
					}

					++$out['results']['warnings'];
					$out['details']['warnings'][] = $tmp;
				}
			}
		}

		return $out;
	}

	/**
	 * Get Status
	 *
	 * @param bool $formatted Nice output.
	 * @return string Status.
	 */
	public function get_status($formatted=false) {
		if (!$this->is_scan()) {
			return $formatted ? __('Invalid scan.', LOOKSEE_L10N) : '';
		}

		if (!$formatted) {
			return $this->data['status'];
		}

		$slug = $this->data['status'];
		if ('finished' === $slug) {
			$error = $this->get_error();
			if ($error) {
				$slug .= "-$error";
			}
		}

		$translated = array(
			'created'=>__('Initializing the scan.', LOOKSEE_L10N),
			'building-core'=>__('Collecting WordPress checksums.', LOOKSEE_L10N),
			'building-plugins'=>__('Collecting plugin checksums.', LOOKSEE_L10N),
			'building-themes'=>__('Collecting theme checksums.', LOOKSEE_L10N),
			'building-local'=>__('Searching the local filesystem.', LOOKSEE_L10N),
			'building-history'=>__('Finishing up the pre-scan.', LOOKSEE_L10N),
			'scanning'=>__('Scanning files.', LOOKSEE_L10N),
			'finished'=>__('The scan has completed.', LOOKSEE_L10N),
			'finished-other'=>__('The scan encountered an error.', LOOKSEE_L10N),
			'finished-timeout'=>__('The scan timed out.', LOOKSEE_L10N),
			'finished-user-abort'=>__('The scan has been aborted.', LOOKSEE_L10N),
		);

		return $translated[$slug];
	}

	/**
	 * Sanitize Details
	 *
	 * @param array|string $details Details.
	 * @return bool True/false.
	 */
	public static function sanitize_details(&$details) {
		if (!is_array($details)) {
			$tmp = json_decode($details, true);
			if (is_array($tmp)) {
				$details = $tmp;
				unset($tmp);
			}
			else {
				$details = array(
					'scan'=>options::get('scan'),
					'core'=>core::get_core(),
					'plugins'=>core::get_plugins(),
					'themes'=>core::get_themes(),
				);
			}
		}

		// Shove everything into the right mold.
		$details = common\data::parse_args($details, static::DETAILS);
		$details['scan'] = common\data::parse_args($details['scan'], options::OPTIONS['scan']);
		$details['core'] = common\data::parse_args($details['core'], core::TEMPLATE);
		foreach (array('plugins', 'themes') as $field) {
			foreach ($details[$field] as $k=>$v) {
				$details[$field][$k] = common\data::parse_args($details[$field][$k], core::TEMPLATE);
			}
		}

		return true;
	}

	// ----------------------------------------------------------------- end get data




	// -----------------------------------------------------------------
	// Save Data
	// -----------------------------------------------------------------

	/**
	 * Update Scan
	 *
	 * @param array $args Arguments.
	 *
	 * @arg int $scheduled Scheduled scan.
	 * @arg string $status Status.
	 * @arg int $tries # Tries.
	 * @arg string|array $details Details.
	 * @arg string $error Error.
	 *
	 * @return bool True/false.
	 */
	public function save($args=null) {
		global $wpdb;

		// If this isn't a scan, we're creating a scan. We don't need
		// any input from outside. Haha.
		if (!$this->is_scan()) {
			$user_id = 0;
			$scheduled = 0;

			// Who is doing this thing? Anyone?
			if (!$user_id && is_user_logged_in()) {
				$current_user = wp_get_current_user();
				if (is_a($current_user, 'WP_User')) {
					$user_id = $current_user->ID;
				}
			}

			// Default details.
			$details = null;
			static::sanitize_details($details);
			if (isset($args['scan'])) {
				$details['scan'] = common\data::parse_args($args['scan'], $details['scan']);
			}

			$data = array(
				'scheduled'=>$scheduled,
				'user_id'=>$user_id,
				'date_created'=>current_time('mysql'),
				'status'=>'created',
				'details'=>json_encode($details),
			);
			$wpdb->insert(
				"{$wpdb->prefix}looksee3_scans",
				$data,
				array('%d', '%d', '%s', '%s', '%s')
			);
			$scan_id = (int) $wpdb->insert_id;
		}
		else {
			$default = array(
				'status'=>$this->get_status(),
				'tries'=>$this->get_tries(),
				'error'=>$this->get_error(),
			);
			$data = common\data::parse_args($args, $default);

			// Gotta make sure the details are formatted correctly
			// before we parse.
			if (is_array($args) && isset($args['details'])) {
				static::sanitize_details($args['details']);
				$data['details'] = $args['details'];
			}

			// Status must be good. Can't recover from here.
			if (!in_array($data['status'], static::STATUSES, true)) {
				return false;
			}

			if ('finished' === $data['status']) {
				// Just finished?
				if ('0000-00-00 00:00:00' === $this->data['date_finished']) {
					$data['date_finished'] = current_time('mysql');
				}

				$data['tries'] = 0;

				if ($data['error'] && !in_array($data['error'], static::ERRORS, true)) {
					$data['error'] = '';
				}
			}
			else {
				$data['error'] = '';
				common\ref\sanitize::to_range($data['tries'], 0);
			}

			// Encode our details before saving.
			if (isset($data['details'])) {
				$data['details'] = json_encode($data['details']);
			}

			// Okay, let's save!
			$wpdb->update(
				"{$wpdb->prefix}looksee3_scans",
				$data,
				array('scan_id'=>$this->get_scan_id()),
				'%s',
				'%d'
			);
			$scan_id = (int) $this->get_scan_id();
		}

		// Re-initiate so all our data is populated correctly.
		return $this->__construct($scan_id);
	}

	/**
	 * Finish a Scan
	 *
	 * @param string $error Error.
	 * @return True/false.
	 */
	public function finish($error=null) {
		if (!$this->is_scan()) {
			return false;
		}

		// Clear our transients, if applicable.
		delete_transient('looksee_scan_abort');
		delete_transient('looksee_scan_lock');

		// Already finished?
		if ('finished' === $this->get_status()) {
			if (!$error) {
				return true;
			}
			return $this->save(array('error'=>$error));
		}

		$data = array(
			'status'=>'finished',
			'tries'=>0,
			'error'=>$error ? $error : '',
		);
		return $this->save($data);
	}

	// ----------------------------------------------------------------- end save



	// -----------------------------------------------------------------
	// Scanning
	// -----------------------------------------------------------------

	/**
	 * Scan!
	 *
	 * This is a gateway function that will run whatever sub-task is
	 * needing running.
	 *
	 * @return bool True/false.
	 */
	public function scan() {
		global $wpdb;

		$status = $this->get_status();
		if (!$this->is_scan() || ('finished' === $status)) {
			return false;
		}

		if (false !== get_transient('looksee_scan_abort')) {
			$this->finish('user-abort');
			return false;
		}

		// Send them on their way.
		switch ($status) {
			case 'created':
			case 'building-core':
				return $this->scan_build_core();
			case 'building-plugins':
				return $this->scan_build_plugins();
			case 'building-themes':
				return $this->scan_build_themes();
			case 'building-local':
				return $this->scan_build_local();
			case 'building-history':
				return $this->scan_build_history();
		}

		// What remains is the regular scan, which we might as well do
		// here.
		$scan_id = $this->get_scan_id();
		$dbResult = $wpdb->get_results("
			SELECT
				`file_hash`,
				`file_path`,
				`type`,
				`checksum_expected`,
				`tries`
			FROM `{$wpdb->prefix}looksee3_scan_files`
			WHERE
				`scan_id`=$scan_id AND
				`status`=''
			LIMIT " . $this->get_option('batch_size'), ARRAY_A);
		if (is_array($dbResult) && count($dbResult)) {
			foreach ($dbResult as $Row) {
				// First, update the number of tries early. This isn't
				// very efficient, but is necessary to allow graceful
				// recovery for impossible files.
				$Row['tries'] = (int) $Row['tries'];
				++$Row['tries'];

				$out = array('tries'=>$Row['tries']);
				if ($Row['tries'] > 3) {
					$out['status'] = 'timeout';
					$out['date_scanned'] = current_time('mysql');
				}

				$conds = array(
					'scan_id'=>$scan_id,
					'file_hash'=>$Row['file_hash'],
				);

				$wpdb->update(
					"{$wpdb->prefix}looksee3_scan_files",
					$out,
					$conds,
					'%s',
					array('%d', '%s')
				);

				// Skip this file if we've tried too much.
				if ($Row['tries'] > 3) {
					continue;
				}

				// Gather info.
				$response = files::info($Row['file_path'], true);
				$out['status'] = 'ok';
				$out['date_scanned'] = current_time('mysql');
				foreach ($response as $k=>$v) {
					// This status isn't the same as we'll ultimately be
					// saving, but will help us get there.
					if ('status' === $k) {
						$status = $v;
					}
					// We already know the path. Everything else is a
					// keeper, though.
					elseif ('path' !== $k) {
						$out[$k] = $v;
					}
				}

				// Figure out scan status.
				if ('invalid' === $status) {
					$out['status'] = 'deleted';
				}
				elseif ('skipped' === $status) {
					$out['status'] = 'skipped';
				}
				elseif ($Row['checksum_expected'] !== $out['checksum']) {
					if ($Row['checksum_expected']) {
						$out['status'] = 'modified';
					}
					else {
						$out['status'] = 'new';
					}
				}

				// Save what we've got.
				$wpdb->update(
					"{$wpdb->prefix}looksee3_scan_files",
					$out,
					$conds,
					'%s',
					array('%d', '%s')
				);

				// Last thing, find any warnings that apply. The design
				// went with modularity rather than single efficiency,
				// so we don't want to send every file to it.
				if ('skipped' !== $out['status']) {
					$this->scan_warnings($Row['file_hash']);
				}
			}
		}
		// Otherwise we're done scanning, time to do some quick cleanup
		// and mark it done!
		else {
			$this->finish();
			static::prune();
			return false;
		}

		return true;
	}

	/**
	 * Scan: Build Core
	 *
	 * Make sure the database has the necessary checksums for the
	 * installed version of WordPress.
	 *
	 * @return bool True/false.
	 */
	protected function scan_build_core() {
		// Maximum number of tries: 1.
		if (!$this->get_tries()) {
			// Update the database early just in case there's a problem.
			$this->save(
				array(
					'status'=>'building-core',
					'tries'=>1,
				)
			);

			core::load_core_checksums();
		}

		// Move on.
		$this->save(
			array(
				'status'=>'building-plugins',
				'tries'=>0,
			)
		);
		return true;
	}

	/**
	 * Scan: Build Plugins
	 *
	 * Try to generate checksums for any installed plugins.
	 *
	 * @return bool True/false.
	 */
	protected function scan_build_plugins() {
		// This is likely to timeout, so we'll allow up to 5 tries.
		if ($this->get_tries() >= 5) {
			$this->save(
				array(
					'status'=>'building-themes',
					'tries'=>0,
				)
			);
			return true;
		}

		// Update the database early just in case there's a problem.
		$this->save(
			array(
				'status'=>'building-plugins',
				'tries'=>($this->get_tries() + 1),
			)
		);

		core::load_plugin_checksums();

		// Move on.
		$this->save(
			array(
				'status'=>'building-themes',
				'tries'=>0,
			)
		);
		return true;
	}

	/**
	 * Scan: Build Themes
	 *
	 * Try to generate checksums for any installed themes.
	 *
	 * @return bool True/false.
	 */
	protected function scan_build_themes() {
		// This is likely to timeout, so we'll allow up to 3 tries.
		if ($this->get_tries() >= 3) {
			$this->save(
				array(
					'status'=>'building-local',
					'tries'=>0,
				)
			);
			return true;
		}

		// Update the database early just in case there's a problem.
		$this->save(
			array(
				'status'=>'building-themes',
				'tries'=>($this->get_tries() + 1),
			)
		);

		core::load_theme_checksums();

		// Move on.
		$this->save(
			array(
				'status'=>'building-local',
				'tries'=>0,
			)
		);
		return true;
	}

	/**
	 * Scan: Build Local
	 *
	 * Find all site files. This is meant to pull the minimal amount
	 * of information because it can be time-consuming; we'll get full
	 * details and apply more sanitizing later.
	 *
	 * @return bool True/false.
	 */
	protected function scan_build_local() {
		global $wpdb;

		// This has to be done in one go, but might make it through on
		// a second attempt where it failed on the first because of FS
		// caches, so we'll give it a couple tries. However failure here
		// means the scan as a whole failed.
		if ($this->get_tries() >= 2) {
			$this->finish('timeout');
			return false;
		}

		// Update the database early just in case there's a problem.
		$this->save(
			array(
				'status'=>'building-local',
				'tries'=>($this->get_tries() + 1),
			)
		);

		$files = files::find_files();
		if (!count($files)) {
			return $this->finish('other');
		}

		$inserts = array();
		$scan_id = $this->get_scan_id();
		foreach ($files as $v) {
			$inserts[] = "($scan_id, '" . esc_sql(core::md5($v)) . "', '" . esc_sql($v) . "')";
		}

		// Insert en masse, but in chunks. Single-inserts are way too
		// slow. Haha.
		$inserts = array_chunk($inserts, static::CHUNK);
		foreach ($inserts as $v) {
			$wpdb->query("
				INSERT INTO `{$wpdb->prefix}looksee3_scan_files` (`scan_id`, `file_hash`, `file_path`)
				VALUES " . implode(',', $v) . '
                ON DUPLICATE KEY UPDATE `scan_id`=`scan_id`
            ');
		}

		// Move on.
		$this->save(
			array(
				'status'=>'building-history',
				'tries'=>0,
			)
		);
		return true;
	}

	/**
	 * Scan: Build History
	 *
	 * Here we want to make sure that expected plugin/theme files are
	 * present in the scan table (even if they aren't on the system),
	 * and also populate any expected checksums we can populate.
	 *
	 * @return bool True/false.
	 */
	protected function scan_build_history() {
		global $wpdb;

		// This really needs to be done in one go too, but again, might
		// do better on a second pass because of cache. This is also a
		// hard fail; results will be worthless if we can't copy the
		// history.
		if ($this->get_tries() >= 2) {
			$this->finish('timeout');
			return false;
		}

		// Update the database early just in case there's a problem.
		$details = $this->get_details();
		$details['plugins'] = core::get_plugins();
		$details['themes'] = core::get_themes();
		static::sanitize_details($details);
		$this->save(
			array(
				'status'=>'building-history',
				'tries'=>($this->get_tries() + 1),
				'details'=>$details,
			)
		);

		$scan_id = $this->get_scan_id();

		// Copy any missing core files.
		$wpdb->query("
			INSERT INTO `{$wpdb->prefix}looksee3_scan_files` (`scan_id`, `file_hash`, `file_path`, `type`)
			(
				SELECT
					$scan_id AS `scan_id`,
					`file_hash`,
					`file_path`,
					`type`
				FROM `{$wpdb->prefix}looksee3_core`
			)
			ON DUPLICATE KEY UPDATE `type`=VALUES(`type`)
		");

		// Is there a previous scan?
		$previous = (int) $wpdb->get_var("
			SELECT `scan_id`
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE
				`scan_id` < $scan_id AND
				`status`='finished' AND
				NOT(LENGTH(`error`))
			ORDER BY `scan_id` DESC
			LIMIT 1
		");
		if ($previous) {
			$wpdb->query("
				INSERT INTO `{$wpdb->prefix}looksee3_scan_files` (`scan_id`, `file_hash`, `file_path`, `checksum_expected`)
				(
					SELECT
						$scan_id AS `scan_id`,
						`file_hash`,
						`file_path`,
						`checksum` AS `checksum_expected`
					FROM `{$wpdb->prefix}looksee3_scan_files`
					WHERE
						`scan_id`=$previous AND
						`type`='' AND
						LENGTH(`checksum`)
				)
				ON DUPLICATE KEY UPDATE `checksum_expected`=VALUES(`checksum_expected`)
			");
		}

		// One last query to set core checksums.
		$wpdb->query("
			UPDATE
				`{$wpdb->prefix}looksee3_scan_files` AS f,
				`{$wpdb->prefix}looksee3_core` AS c
			SET f.checksum_expected = c.checksum
			WHERE
				f.scan_id=$scan_id AND
				f.file_hash=c.file_hash AND
				f.type=c.type
		");

		// Okay wait, sorry, possibly one more thing. We are collecting
		// skippable files in the database so we can report the numbers
		// down the road. Some of the rules are simple enough that we
		// can exclude a bunch en masse. Otherwise we'll have to wait
		// until the deep scan, which is a lot slower.
		$conds = array();
		// Skipping cache files?
		if ($this->get_option('skip_cache')) {
			$conds[] = "`file_path` LIKE '" . esc_sql($wpdb->esc_like(files::get_content_dir() . 'cache/')) . "%'";
		}

		$soup = array();
		if ($this->get_option('skip_images')) {
			$soup = files::IMAGES;
		}
		if ($this->get_option('skip_media')) {
			$soup = array_merge($soup, files::MEDIA);
		}
		if (count($soup)) {
			sort($soup);
			$soup = implode('|', $soup);
			$conds[] = '(LEFT(`file_path`, ' . common\mb::strlen(files::get_uploads_dir()) . ") = '" . esc_sql(files::get_uploads_dir()) . "' AND `file_path` REGEXP '\.(" . esc_sql("{$soup})$") . "')";
		}

		$blacklist = $this->get_option('blacklist');
		if (count($blacklist)) {
			foreach ($blacklist as $v) {
				// Simple wildcard swap. If it doesn't work, it doesn't
				// work. We'll run a better test later.
				if (false !== strpos($v, '*')) {
					$conds[] = "`file_path` LIKE '" . str_replace('*', '%', esc_sql($wpdb->esc_like($v))) . "'";
				}
				// No wildcards, maybe a straight match?
				else {
					$conds[] = "`file_path`='" . esc_sql($v) . "'";
				}
			}
		}
		if (count($conds)) {
			$conds = implode(' OR ', $conds);
			$wpdb->query("
				UPDATE `{$wpdb->prefix}looksee3_scan_files`
				SET `status`='skipped'
				WHERE
					`scan_id`=$scan_id AND
					($conds)
			");
		}

		// Move on.
		$this->save(
			array(
				'status'=>'scanning',
				'tries'=>0,
			)
		);
		return true;
	}

	/**
	 * Scan: File Warnings
	 *
	 * There are a lot of things that can go wrong with a file; this is
	 * too much to calculate on-the-fly, so is baked into the scan.
	 *
	 * @param string $file_hash File Hash.
	 * @return bool True/false.
	 */
	protected function scan_warnings($file_hash) {
		global $wpdb;

		// Gotta be a scan.
		if (!$this->is_scan()) {
			return false;
		}

		$scan_id = $this->get_scan_id();
		$dbResult = $wpdb->get_results("
			SELECT
				`scan_id`,
				`file_hash`,
				`file_path`,
				`type`,
				`checksum_expected`,
				`checksum`,
				`size`,
				`mime`,
				`chmod`,
				`chown`,
				`status`
			FROM `{$wpdb->prefix}looksee3_scan_files`
			WHERE
				`scan_id`='$scan_id' AND
				`file_hash`='" . esc_sql($file_hash) . "'
		", ARRAY_A);
		if (!is_array($dbResult) || !count($dbResult)) {
			return false;
		}
		$Row = common\data::array_pop_top($dbResult);

		// First things first, remove any existing warnings.
		$wpdb->delete(
			"{$wpdb->prefix}looksee3_scan_warnings",
			array(
				'scan_id'=>$scan_id,
				'file_hash'=>$Row['file_hash'],
			),
			array('%d', '%s')
		);

		// Nothing else to do?
		if (('' === $Row['status']) || ('skipped' === $Row['status'])) {
			return true;
		}

		$inserts = array();
		$Row['file_hash'] = esc_sql($Row['file_hash']);
		$Row['size'] = (int) $Row['size'];

		// Start with some easy ones.
		if (!files::verify_chmod($Row['file_path'])) {
			$inserts['chmod'] = "($scan_id, '{$Row['file_hash']}', 'chmod')";
		}
		if (!files::verify_chown($Row['file_path'])) {
			$inserts['chown'] = "($scan_id, '{$Row['file_hash']}', 'chown')";
		}
		if ('timeout' === $Row['status']) {
			$inserts['timeout'] = "($scan_id, '{$Row['file_hash']}', 'timeout')";
		}
		else {
			if ($Row['type']) {
				if ($Row['checksum'] !== $Row['checksum_expected']) {
					// Make sure it isn't a readme.
					$filename = basename($Row['file_path']);
					if (
						!preg_match('/^readme\.(html?|md|txt)$/ui', $filename) &&
						('wp-config-sample.php' !== $filename)
					) {
						if ($Row['checksum']) {
							$inserts['core-modified'] = "($scan_id, '{$Row['file_hash']}', 'core-modified')";
						}
						else {
							$inserts['core-missing'] = "($scan_id, '{$Row['file_hash']}', 'core-missing')";
						}
					}
				}
			}
			elseif ($Row['checksum'] && files::is_core_path($Row['file_path'])) {
				if (files::is_old_core_file($Row['file_path'])) {
					$inserts['core-old'] = "($scan_id, '{$Row['file_hash']}', 'core-old')";
				}
				else {
					$inserts['core-extra'] = "($scan_id, '{$Row['file_hash']}', 'core-extra')";
				}
			}
		}

		// Additional checks if this is in fact a file.
		if ($Row['size'] || $Row['checksum']) {
			// Developer files are things like backup files, etc. Stuff
			// that shouldn't be left around on a production server.
			$filename = common\mb::strtolower(basename($Row['file_path']));
			if (
				('tmp.' === common\mb::substr($filename, 0, 4)) ||
				('~' === common\mb::substr($filename, -1)) ||
				preg_match('/(\.|_)(bac?k|backup|dist|log|old|save|sql|swo|swp|te?mp|1)$/u', $filename) ||
				(('wp-config.php' !== $Row['file_path']) && ('wp-config' === common\mb::substr($Row['file_path'], 0, 9)))
			) {
				$inserts['dev-file'] = "($scan_id, '{$Row['file_hash']}', 'dev-file')";
			}
			// The directory name might also be problemmatic.
			elseif (false !== strpos($Row['file_path'], '/')) {
				$dir = explode('/', $Row['file_path']);
				array_pop($dir);
				foreach ($dir as $v) {
					if (
						preg_match('/^(backups?|old|te?mp|test|bac?k)$/ui', $v) ||
						preg_match('/(\.|_)(bac?k|backup|old|save|te?mp)$/ui', $v)
					) {
						$inserts['dev-file'] = "($scan_id, '{$Row['file_hash']}', 'dev-file')";
						break;
					}
				}
			}

			// Take a deeper look into non-core files.
			if (('core' !== $Row['type']) || isset($inserts['core-modified'])) {
				// Check file type.
				$fileext = strtolower(pathinfo($Row['file_path'], PATHINFO_EXTENSION));
				if (
					$fileext &&
					!isset($inserts['dev-file']) &&
					!common\mime::check_ext_and_mime($fileext, $Row['mime'])
				) {
					$inserts['mime'] = "($scan_id, '{$Row['file_hash']}', 'mime')";
				}

				// PHP-specific checks. These are pretty inefficient,
				// but also illuminating, so it is what it is.
				if (('php' === $fileext) && !isset($inserts['mime'])) {
					try {
						// First remove comments and stupid whitespace,
						// which'll save looping time.
						$content = @php_strip_whitespace(files::get_base_dir() . $Row['file_path']);

						// Does this contain a long string of gibberish?
						// This is only useful for files that can't be
						// verified on their own.
						if (
							(!$Row['type'] || isset($inserts['core-modified'])) &&
							preg_match('/[^\s\'"]{150,}/u', $content)
						) {
							$inserts['php-gibberish'] = "($scan_id, '{$Row['file_hash']}', 'php-gibberish')";
						}

						// Tokenize the file, which is our best chance
						// of correctly identifying actual function
						// calls.
						$tokens = $content ? @token_get_all($content) : '';
						if (is_array($tokens) && count($tokens)) {
							foreach ($tokens as $k=>$v) {
								if (
									!is_array($v) ||
									((T_EVAL === $v[0]) && (T_STRING === $v[0]))
								) {
									continue;
								}

								// The tokenizer can't tell the user
								// functions from system ones. We can
								// assume the former if -> or :: comes
								// before.
								if (
									$k > 0 &&
									is_array($tokens[$k - 1]) &&
									((T_DOUBLE_COLON === $tokens[$k - 1][0]) || (T_OBJECT_OPERATOR === $tokens[$k - 1][0]))
								) {
									continue;
								}

								// An eval() statement.
								if (T_EVAL === $v[0]) {
									$inserts['php-eval'] = "($scan_id, '{$Row['file_hash']}', 'php-eval')";
								}
								// Maybe a function we care about?
								else {
									$v[1] = strtolower($v[1]);

									if ('phpinfo' === $v[1]) {
										$inserts['php-phpinfo'] = "($scan_id, '{$Row['file_hash']}', 'php-phpinfo')";
									}
									elseif (
										!isset($inserts['php-system']) &&
										in_array($v[1], static::SYSTEM_FUNCTIONS, true)
									) {
										$inserts['php-system'] = "($scan_id, '{$Row['file_hash']}', 'php-system')";
									}
								}
							}
						}
					} catch (\Throwable $e) {
						$content = '';
					} catch (\Exception $e) {
						$content = '';
					}
				}
			}
		}

		if (count($inserts)) {
			$wpdb->query("
				INSERT INTO `{$wpdb->prefix}looksee3_scan_warnings` (`scan_id`,`file_hash`,`warning`)
				VALUES " . implode(',', $inserts)
			);
		}

		return true;
	}

	/**
	 * Email Scan Results
	 *
	 * @return bool True/false.
	 */
	public function email() {
		if (
			!$this->is_scan() ||
			('finished' !== $this->get_status())
		) {
			return false;
		}

		$results = $this->get_results();
		$site_name = common\format::decode_entities(get_bloginfo('name'));
		$site_email = common\sanitize::email(get_bloginfo('admin_email'));
		$mode = $this->get_scheduled() ? 'scheduled' : 'WP-CLI';
		$attachments = array();

		$body = sprintf(
			__('The %s file scan for %s completed in %s.', LOOKSEE_L10N),
			$mode,
			$site_name,
			human_time_diff(strtotime($results['date_created']), strtotime($results['date_finished']))
		);

		if ($results['error']) {
			$body .= ' ' . __('Unfortunately this scan was not successful due to an error.', LOOKSEE_L10N);
		}
		else {
			$body .= "\n";
			$body .= "\n\t" . __('Files', LOOKSEE_L10N) . ": {$results['results']['total']}";
			$body .= "\n\t" . __('Scanned', LOOKSEE_L10N) . ": {$results['results']['scanned']}";
			$body .= "\n\t" . __('Skipped', LOOKSEE_L10N) . ": {$results['results']['skipped']}";
			$body .= "\n\t" . __('Warnings', LOOKSEE_L10N) . ": {$results['results']['warnings']}";

			// Warning attachment.
			if ($results['results']['warnings']) {
				$data = array();
				foreach ($results['details']['warnings'] as $v) {
					$data[] = array(
						__('Warning', LOOKSEE_L10N)=>$v['warningText'],
						__('Core', LOOKSEE_L10N)=>($v['type'] ? __('Yes', LOOKSEE_L10N) : __('No', LOOKSEE_L10N)),
						__('File', LOOKSEE_L10N)=>$v['file'],
					);
				}

				$filename = "look-see_{$this->get_scan_id()}_" . __('warnings', LOOKSEE_L10N) . '.csv';
				$filename = wp_unique_filename(files::get_tmp_dir(), $filename);
				$file = files::get_tmp_dir() . $filename;
				$data = common\format::to_csv($data);
				@file_put_contents($file, $data);
				@chmod($file, FS_CHMOD_FILE);
				if (@file_exists($file)) {
					$attachments[] = $file;
				}
			}

			// File Changes attachment.
			if (
				count($results['details']['new']) ||
				count($results['details']['modified']) ||
				count($results['details']['deleted'])
			) {
				$fields = array(
					'modified'=>__('Modified', LOOKSEE_L10N),
					'deleted'=>__('Deleted', LOOKSEE_L10N),
					'new'=>__('New', LOOKSEE_L10N),
				);
				$data = array();
				foreach ($fields as $k=>$v) {
					foreach ($results['details'][$k] as $v2) {
						$data[] = array(
							__('Status', LOOKSEE_L10N)=>$v,
							__('Core', LOOKSEE_L10N)=>($v2['type'] ? __('Yes', LOOKSEE_L10N) : __('No', LOOKSEE_L10N)),
							__('File', LOOKSEE_L10N)=>$v2['file'],
						);
					}
				}

				$filename = "look-see_{$this->get_scan_id()}_" . __('file-changes', LOOKSEE_L10N) . '.csv';
				$filename = wp_unique_filename(files::get_tmp_dir(), $filename);
				$file = files::get_tmp_dir() . $filename;
				$data = common\format::to_csv($data);
				@file_put_contents($file, $data);
				@chmod($file, FS_CHMOD_FILE);
				if (@file_exists($file)) {
					$attachments[] = $file;
				}
			}
		}

		$body .= "\n\n" . admin_url('admin.php?page=looksee-scan');
		$body .= "\nLook-See Security Scanner";

		wp_mail(
			$site_email,
			"[$site_name] Look-See " . common\mb::ucwords($mode) . ' ' . __('Scan', LOOKSEE_L10N),
			$body,
			null,
			$attachments
		);

		// Clean up attachments.
		foreach ($attachments as $v) {
			@unlink($v);
		}

		return true;
	}

	// ----------------------------------------------------------------- end scanning


	// -----------------------------------------------------------------
	// Misc
	// -----------------------------------------------------------------

	/**
	 * Get Open Scan
	 *
	 * We don't want to run multiple scans at the same time. This can be
	 * used to return the earliest ongoing scan.
	 *
	 * @param bool $scheduled Scheduled scan.
	 * @return bool|scan Scan or false.
	 */
	public static function get_open_scan($scheduled=false) {
		global $wpdb;

		$scan = (int) $wpdb->get_var("
			SELECT `scan_id`
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE
				`status` != 'finished' AND
				`scheduled`=" . ($scheduled ? 1 : 0) . '
            ORDER BY `date_created` ASC
            LIMIT 1
        ');

		return $scan ? new static($scan) : false;
	}

	/**
	 * Prune Database
	 *
	 * Reduce the number of completed scans stored in the database.
	 *
	 * @param int $max Max scans.
	 * @return bool True/false.
	 */
	public static function prune($max=null) {
		global $wpdb;

		if (is_null($max)) {
			if (!options::get('prune-active')) {
				return false;
			}
			$max = options::get('prune-limit');
		}
		else {
			common\ref\cast::to_int($max, true);
			if ($max <= 0) {
				return false;
			}
		}

		$old = array();
		$dbResult = $wpdb->get_results("
			SELECT `scan_id`
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE `status`='finished'
			ORDER BY `date_finished` DESC
			LIMIT $max, 1000
		", ARRAY_A);
		if (!is_array($dbResult) || !count($dbResult)) {
			return true;
		}

		foreach ($dbResult as $Row) {
			$old[] = (int) $Row['scan_id'];
		}
		sort($old);
		$old = implode(',', $old);

		// Delete some data!
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee3_scans` WHERE `scan_id` IN ($old)");
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee3_scan_files` WHERE `scan_id` IN ($old)");
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee3_scan_warnings` WHERE `scan_id` IN ($old)");

		return true;
	}

	/**
	 * Is Locked
	 *
	 * We don't want two people trying to run the same scan at the same
	 * time. This is a simple locking mechanism to help prevent such
	 * collisions.
	 *
	 * This won't help in cases where one person opens two windows, but
	 * hey, they're doing it to themselves.
	 *
	 * @param string $type Force lock type.
	 * @return mixed False or the active party.
	 */
	public static function is_locked($type=null) {
		if ('WP-CLI' !== $type) {
			$type = null;
		}

		// No lock exists.
		if (false === ($who = get_transient('looksee_scan_lock'))) {
			return false;
		}
		// WP apparently doesn't preserve scalar types.
		elseif (is_numeric($who)) {
			$who = (int) $who;
		}

		// If checking a specific lock, we can bail early maybe.
		if ($type === $who) {
			return false;
		}

		$me = false;
		if (defined('WP_CLI') && WP_CLI) {
			$me = 'WP-CLI';
		}
		elseif (is_user_logged_in()) {
			$current_user = wp_get_current_user();
			if (is_a($current_user, 'WP_User')) {
				$me = (int) $current_user->ID;
			}
		}

		if ($me === $who) {
			return false;
		}

		return $who;
	}

	/**
	 * Set Lock
	 *
	 * Again, we don't want multiple people running scans at the same
	 * time. This sets a quick database lock for the current user or
	 * access method.
	 *
	 * Because people get bored and computers crash, the lock will
	 * auto-expire after 10 minutes.
	 *
	 * @param string $type Force lock type.
	 * @return bool True/false.
	 */
	public static function set_lock($type=null) {
		if ('WP-CLI' !== $type) {
			$type = null;
		}

		if (static::is_locked($type)) {
			return false;
		}

		$me = false;
		if (('WP-CLI' === $type) || (defined('WP_CLI') && WP_CLI)) {
			$me = 'WP-CLI';
		}
		elseif (is_null($type) && is_user_logged_in()) {
			$current_user = wp_get_current_user();
			if (is_a($current_user, 'WP_User')) {
				$me = (int) $current_user->ID;
			}
		}

		if ($me) {
			set_transient('looksee_scan_lock', $me, 600);
		}
	}

	// ----------------------------------------------------------------- end misc
}
