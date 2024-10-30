<?php
/**
 * Look-See Security Scanner options.
 *
 * An options wrapper.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee;

use \blobfolio\wp\looksee\vendor\common;

class options {

	const OPTION_NAME = 'looksee_options';
	const OPTIONS = array(
		// Pro license.
		'license'=>'',

		// Prune history.
		'prune'=>array(
			'active'=>true,
			'limit'=>10,
		),

		// Default Scan Settings.
		'scan'=>array(
			'batch_size'=>250,
			'blacklist'=>array(),
			'skip_cache'=>true,
			'skip_images'=>false,
			'skip_media'=>false,
			'skip_size'=>2097152,
		),
	);

	// A few old settings map directly.
	const DEPRECATED = array(
		'skipCache'=>'scan-skip_cache',
		'skipMedia'=>'scan-skip_media',
		'skipSize'=>'scan-skip_size',
	);



	protected static $options;
	protected static $pro;

	protected static $last_license;
	protected static $last_license_status;



	/**
	 * Load Options
	 *
	 * @param bool $refresh Refresh.
	 * @return bool True/false.
	 */
	public static function load($refresh=false) {
		if (is_null(static::$options) || $refresh) {
			// Nothing saved yet?
			if (false === (static::$options = get_option(static::OPTION_NAME, false))) {
				static::$options = static::OPTIONS;
				update_option(static::OPTION_NAME, static::$options);
			}
			// Maybe an old version?
			elseif (is_array(static::$options)) {
				$overlap = array_intersect_key(static::DEPRECATED, static::$options);
				if (count($overlap)) {
					foreach ($overlap as $k) {
						list($a,$b) = explode('-', static::DEPRECATED[$k]);
						static::$options[$a][$b] = static::$options[$k];
					}
				}
			}

			// Before.
			$before = json_encode(static::$options);

			// Sanitize them.
			static::sanitize(static::$options);

			// After.
			$after = json_encode(static::$options);
			if ($before !== $after) {
				update_option(static::OPTION_NAME, static::$options);
			}
		}

		return true;
	}

	/**
	 * Sanitize Options
	 *
	 * @param array $options Options.
	 * @return bool True/false.
	 */
	protected static function sanitize(&$options) {

		// Make sure it fits the appropriate format.
		static::$options = common\data::parse_args($options, static::OPTIONS);

		// Validate license.
		static::$pro = static::validate_license($options['license']);

		// Pruning.
		if ($options['prune']['active']) {
			common\ref\sanitize::to_range($options['prune']['limit'], 1);
		}
		else {
			$options['prune']['limit'] = 0;
		}

		// Size can't be negative.
		common\ref\sanitize::to_range($options['scan']['skip_size'], 0);

		// Batch sizes increment by 25.
		common\ref\sanitize::to_range($options['scan']['batch_size'], 25, 1000);
		if ($options['scan']['batch_size'] % 25) {
			$options['scan']['batch_size'] = (int) (ceil($options['scan']['batch_size'] / 25) * 25);
			common\ref\sanitize::to_range($options['scan']['batch_size'], 25, 1000);
		}

		// Sanitize our blacklist.
		static::sanitize_blacklist($options['scan']['blacklist']);

		return true;
	}

	/**
	 * Sanitize Blacklist
	 *
	 * There is enough going on here that it pays to offload this set
	 * of routines to its own function.
	 *
	 * @param array $blacklist File paths.
	 * @return void Nothing.
	 */
	public static function sanitize_blacklist(&$blacklist) {
		common\ref\cast::to_array($blacklist);

		foreach ($blacklist as $k=>$v) {
			common\ref\cast::to_string($blacklist[$k], true);

			common\ref\mb::trim($blacklist[$k]);
			if ($blacklist[$k]) {
				files::sanitize_relative($blacklist[$k]);

				// Fix over wild wildcards.
				$blacklist[$k] = preg_replace('/\*{3,}/u', '**', $blacklist[$k]);
				if (('*' === $blacklist[$k]) || ('**' === $blacklist[$k])) {
					$blacklist[$k] = '';
				}
			}

			// Remove empties.
			if (!$blacklist[$k]) {
				unset($blacklist[$k]);
			}
		}

		$blacklist = array_unique($blacklist);
		sort($blacklist);
	}

	/**
	 * Sanitize Time
	 *
	 * @param string $time Time.
	 * @return bool True/false.
	 */
	protected static function sanitize_time(&$time) {
		if (!is_string($time) || !preg_match('/^\d\d:\d\d:\d\d$/', $time)) {
			common\ref\sanitize::datetime($time);
			$time = substr($time, -8);
		}

		return true;
	}

	/**
	 * Get Option
	 *
	 * @param string $key Key.
	 * @return mixed Value or false.
	 */
	public static function get($key=null) {
		static::load();

		// Return everything?
		if (is_null($key)) {
			return static::$options;
		}

		common\ref\cast::to_string($key, true);

		// A single option.
		if (array_key_exists($key, static::$options)) {
			return static::$options[$key];
		}

		// It could also be a split.
		if (1 === substr_count($key, '-')) {
			list($a,$b) = explode('-', $key);
			if (
				array_key_exists($a, static::$options) &&
				is_array(static::$options[$a]) &&
				array_key_exists($b, static::$options[$a])
			) {
				return static::$options[$a][$b];
			}
		}

		// Must not exist.
		return false;
	}

	/**
	 * Save Option
	 *
	 * @param string $key Key.
	 * @param mixed $value Value.
	 * @param bool $force Force resaving.
	 * @return bool True/false.
	 */
	public static function save($key, $value, $force=false) {
		static::load();
		common\ref\cast::to_string($key, true);

		// Everything else...
		if (!array_key_exists($key, static::$options)) {
			return false;
		}

		// No change?
		if (!$force && static::$options[$key] === $value) {
			return true;
		}

		$original = static::$options[$key];

		static::$options[$key] = $value;
		update_option(static::OPTION_NAME, static::$options);
		static::load(true);

		return true;
	}

	/**
	 * Validate License
	 *
	 * @param string $license License.
	 * @return bool True/false.
	 */
	public static function validate_license(&$license) {
		if (!$license) {
			return false;
		}

		if (static::$last_license !== $license) {
			$tmp = license::get($license);
			$license = $tmp->is_license() ? $tmp->get_raw(true) : '';

			// Cache results since this might get run multiple times.
			static::$last_license_status = $tmp->is_pro();
			static::$last_license = $license;
		}

		return static::$last_license_status;
	}

	/**
	 * Is Pro
	 *
	 * @return bool True/false.
	 */
	public static function is_pro() {
		static::load();
		return static::$pro;
	}
}
