<?php
/**
 * Look-See Security Scanner Core.
 *
 * Find checksums for the installed version of WordPress, its plugins,
 * and themes.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee;

use \blobfolio\wp\looksee\vendor\common;
use \WP_Error;

class core {

	// The template we'll use for cached data.
	const TEMPLATE = array(
		'active'=>true,
		'base'=>'',
		'checksums'=>false,
		'current'=>true,
		'name'=>'',
		'slug'=>'',
		'uri'=>'',
		'version'=>'',
	);

	// To keep things consistent we hash the Core's "slug", but this
	// isn't going to change, so we'll save a few microseconds by
	// pre-calculating it.
	const CORE_SLUG = 'R+kR0TKN61(P6e^B}@pG';

	// The database chunk size.
	const CHUNK = 100;

	// The ASCII-85 charset we're using to condense hex hashes.
	const Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';

	// WordPress SALTS.
	const SALTS = array(
		'AUTH_KEY',
		'AUTH_SALT',
		'LOGGED_IN_KEY',
		'LOGGED_IN_SALT',
		'NONCE_KEY',
		'NONCE_SALT',
		'SECURE_AUTH_KEY',
		'SECURE_AUTH_SALT',
	);

	protected static $core;
	protected static $plugins;
	protected static $themes;
	protected static $old;



	// -----------------------------------------------------------------
	// Core (i.e. WordPress)
	// -----------------------------------------------------------------

	/**
	 * Get Core Details
	 *
	 * @return array Core details.
	 */
	public static function get_core() {
		global $wpdb;

		if (is_null(static::$core)) {
			static::$core = static::TEMPLATE;

			$version = common\format::decode_entities(get_bloginfo('version', 'display'));
			$locale = get_locale();
			if (!$locale || !preg_match('/^[a-z]{2}_[A-Z]{2}$/', $locale)) {
				$locale = 'en_US';
			}

			static::$core['version'] = "$version-$locale";
			static::$core['slug'] = 'core';
			static::$core['base'] = files::get_base_dir();
			static::$core['name'] = 'WordPress';

			$tmp = wp_get_update_data();
			static::$core['current'] = (!$tmp['counts']['wordpress'] && !$tmp['counts']['translations']);

			static::$core['checksums'] = 0 < (int) $wpdb->get_var("
				SELECT COUNT(*)
				FROM `{$wpdb->prefix}looksee3_core`
				WHERE
					`type`='core' AND
					`slug`='" . static::CORE_SLUG . "' AND
					`version`=" . static::crc32(static::$core['version'])
			);

			// If there are no current checksums, let's delete any old
			// ones that might be around.
			if (!static::$core['checksums']) {
				$wpdb->delete(
					"{$wpdb->prefix}looksee3_core",
					array(
						'type'=>'core',
						'slug'=>static::CORE_SLUG,
					),
					'%s'
				);
			}
		}

		return static::$core;
	}

	/**
	 * Load Core Checksums
	 *
	 * This makes sure Core checksums are in the database.
	 *
	 * @param bool $refresh Refresh.
	 * @return bool|WP_Error True or error.
	 */
	public static function load_core_checksums($refresh=false) {
		global $wpdb;

		static::get_core();
		if (!$refresh && static::$core['checksums']) {
			return true;
		}

		// If refreshing, clear the database.
		if ($refresh) {
			$wpdb->delete(
				"{$wpdb->prefix}looksee3_core",
				array('type'=>'core'),
				'%s'
			);
		}

		@require_once(ABSPATH . 'wp-admin/includes/update.php');

		// Separate the version and locale.
		$version = substr(static::$core['version'], 0, -6);
		$locale = substr(static::$core['version'], -5);

		// Gotta ask the API.
		$tmp = get_core_checksums($version, $locale);
		// Try again with Umerican English.
		if ((!is_array($tmp) || !count($tmp)) && ('en_US' !== $locale)) {
			$tmp = get_core_checksums($version, 'en_US');
		}
		// Still bad? Return an error.
		if (!is_array($tmp) || !count($tmp)) {
			return new WP_Error(
				'api',
				__('The WordPress.org API could not be reached.', LOOKSEE_L10N)
			);
		}

		$inserts = array();
		foreach ($tmp as $k=>$v) {
			// Skip wp-content paths.
			if ('wp-content/' === common\mb::substr($k, 0, 11)) {
				continue;
			}

			$line = array(
				"'core'",
				"'" . static::CORE_SLUG . "'",
				static::crc32(static::$core['version']),
				"'" . static::md5($k) . "'",
				"'" . esc_sql($k) . "'",
				"'" . static::md5($v) . "'",
			);
			$inserts[] = '(' . implode(',', $line) . ')';
		}

		// Add to the database in chunks.
		$inserts = array_chunk($inserts, static::CHUNK);
		foreach ($inserts as $v) {
			$wpdb->query("
				INSERT INTO `{$wpdb->prefix}looksee3_core` (`type`, `slug`, `version`, `file_hash`, `file_path`, `checksum`)
				VALUES " . implode(',', $v)
			);
		}

		// Do this the hard way just to make sure things got saved.
		static::$core['checksums'] = 0 < (int) $wpdb->get_var("
			SELECT COUNT(*)
			FROM `{$wpdb->prefix}looksee3_core`
			WHERE
				`type`='core' AND
				`slug`='" . static::CORE_SLUG . "' AND
				`version`=" . static::crc32(static::$core['version'])
		);

		if (!static::$core['checksums']) {
			return new WP_Error(
				'database',
				__('The WordPress Core checksums could not be saved.', LOOKSEE_L10N)
			);
		}

		// All good!
		return true;
	}

	/**
	 * Is Old File?
	 *
	 * Whether or not a file used to be part of the WP Core but has
	 * since been removed. This covers changes from 2.7 forward, which
	 * is better than nothing, and better than trying to figure this out
	 * by diffing checksums, which only go back to 3.6.
	 *
	 * @param string $path Path.
	 * @return bool True/false.
	 */
	public static function is_old_core_file($path) {
		files::to_relative($path);
		if (!$path) {
			return false;
		}

		// WordPress keeps this list, but it is sorted by version. It
		// is more efficient for us to copy and sort the list by name
		// since we're doing potentially hundreds of lookups.
		if (is_null(static::$old)) {
			global $_old_files;
			@require_once(ABSPATH . 'wp-admin/includes/update-core.php');
			static::$old = $_old_files;
			sort(static::$old);
		}

		return in_array($path, static::$old, true);
	}

	// ----------------------------------------------------------------- end core



	// -----------------------------------------------------------------
	// Plugins
	// -----------------------------------------------------------------

	/**
	 * Get Plugin Details
	 *
	 * @return array Plugin details.
	 */
	public static function get_plugins() {
		global $wpdb;

		if (is_null(static::$plugins)) {
			@require_once(ABSPATH . 'wp-admin/includes/plugin.php');

			$active = get_option('active_plugins', array());
			$all = get_plugins();
			static::$plugins = array();

			// The relative plugin root.
			$base = files::get_plugins_dir();

			// Loop through everything.
			foreach ($all as $k=>$v) {
				$tmp = static::TEMPLATE;

				$tmp['active'] = in_array($k, $active, true);
				$tmp['slug'] = (false === strpos($k, '/')) ? $k : dirname($k);
				$tmp['base'] = $base;
				if (false !== strpos($k, '/')) {
					$tmp['base'] .= "{$tmp['slug']}/";
				}
				$tmp['name'] = $v['Name'];
				$tmp['version'] = $v['Version'];

				// "Musty" filters allow third-party plugins to specify
				// their own remote version/download information. We'll
				// try this first.
				if (
					(false !== ($musty_version = apply_filters("musty_download_version_$k", false))) &&
					(false !== ($musty_uri = apply_filters("musty_download_uri_$k", false)))
				) {
					$tmp['current'] = version_compare($musty_version, $tmp['version']) === 0;
					$tmp['uri'] = common\sanitize::url($musty_uri);
				}

				// Otherwise just check WordPress.
				if (!$tmp['uri']) {
					// There is also a "Musty" filter for supplying an
					// alternative JSON feed. If that exists, we'll use
					// theirs instead of asking WP.org.
					if (false !== ($remote = apply_filters("musty_info_uri_$k", false))) {
						$remote = wp_remote_get($remote);
						if (200 === wp_remote_retrieve_response_code($remote)) {
							$remote = wp_remote_retrieve_body($remote);
							if (is_string($remote)) {
								$remote = json_decode($remote, true);
							}
						}
					}
					// Just a regular WP.org query!
					else {
						$remote = static::get_plugin_remote($tmp['slug']);
					}
					if (is_array($remote) && count($remote) && isset($remote['version'])) {
						$tmp['current'] = version_compare($remote['version'], $tmp['version']) === 0;
						if (isset($remote['download_link'])) {
							$tmp['uri'] = $remote['download_link'];
						}
						else {
							$tmp['uri'] = '';
						}
					}
				}

				// Are there checksums?
				$tmp['checksums'] = 0 < (int) $wpdb->get_var("
					SELECT COUNT(*)
					FROM `{$wpdb->prefix}looksee3_core`
					WHERE
						`type`='plugin' AND
						`slug`='" . static::md5($tmp['slug']) . "' AND
						`version`=" . static::crc32($tmp['version'])
				);

				// Remove obsolete checksums while we're here.
				if (!$tmp['checksums']) {
					$wpdb->delete(
						"{$wpdb->prefix}looksee3_core",
						array(
							'type'=>'plugin',
							'slug'=>static::md5($tmp['slug']),
						),
						'%s'
					);
				}

				static::$plugins[] = $tmp;
			}

			// Sort by name to make display nicer.
			usort(static::$plugins, function($a, $b) {
				if ($a['name'] === $b['name']) {
					return 0;
				}

				return $a['name'] < $b['name'] ? -1 : 1;
			});
		}

		return static::$plugins;
	}

	/**
	 * Get Remote Details
	 *
	 * Pull information from the WordPress API and cache the results to
	 * save a little overhead.
	 *
	 * @param string $slug Slug.
	 * @return array Remote details.
	 */
	protected static function get_plugin_remote($slug='') {
		$transient_key = 'looksee_remote_plugin_' . static::md5($slug);
		if (false === ($out = get_transient($transient_key))) {
			@require_once(ABSPATH . 'wp-admin/includes/plugin.php');
			@require_once(ABSPATH . 'wp-admin/includes/plugin-install.php');

			$out = plugins_api(
				'plugin_information',
				array(
					'slug'=>$slug,
					'fields'=>about::API_FIELDS,
				)
			);
			if (is_wp_error($out)) {
				$out = array();
			}
			else {
				// StdClasses are stupid. Sorry. Not sorry.
				$out = (array) $out;
				set_transient($transient_key, $out, 3600);
			}
		}

		return $out;
	}

	/**
	 * Get Remote Checksums
	 *
	 * WordPress has started storing plugin file checksums! Let's use
	 * this preferentially as it requires less overhead and supports
	 * some older versions.
	 *
	 * @param string $slug Slug.
	 * @param string $version Version.
	 * @return array|bool Checksums or false.
	 */
	protected static function get_plugin_remote_checksums_api($slug, $version) {
		common\ref\cast::to_string($slug, true);
		common\ref\cast::to_string($version, true);

		// Missing data.
		if (!$slug || !$version) {
			return false;
		}

		// The API URL.
		$url = "https://downloads.wordpress.org/plugin-checksums/$slug/$version.json";
		common\ref\sanitize::url($url);
		if (!$url) {
			return false;
		}

		// Ask the API!
		$response = wp_remote_get($url);
		if (200 === wp_remote_retrieve_response_code($response)) {
			$response = wp_remote_retrieve_body($response);
			$json = json_decode($response, true);
			if (
				!isset($json['files'], $json['plugin']) ||
				!is_array($json['files']) ||
				!count($json['files'])
			) {
				return false;
			}

			// File paths are missing the wp-content/plugins bit.
			$base = files::get_plugins_dir() . $json['plugin'] . '/';
			$out = array();

			// Build our output and we're done!
			foreach ($json['files'] as $k=>$v) {
				if (!isset($v['md5'])) {
					continue;
				}

				$out["{$base}{$k}"] = core::md5($v['md5']);
			}

			// Done!
			return count($out) ? $out : false;
		}

		return false;
	}

	/**
	 * Get Remote Checksums
	 *
	 * For plugins the WP.org API doesn't have history for, we can try
	 * to build it manually by downloading a fresh copy.
	 *
	 * A bit crazy...
	 *
	 * @param string $uri Download Zip.
	 * @return array|bool Checksums or false.
	 */
	protected static function get_plugin_remote_checksums($uri='') {
		if (!files::can_write()) {
			return false;
		}

		// Make sure the URL looks good.
		common\ref\sanitize::url($uri);
		if (!$uri || !preg_match('/\.zip$/ui', $uri)) {
			return false;
		}

		// Our tmp directory.
		if (false === ($base = files::make_tmp_dir())) {
			return false;
		}

		// Download the Zip file.
		$zip = download_url($uri);
		if (is_wp_error($zip)) {
			files::clean_tmp_files();
			return false;
		}

		// Extract it.
		if (true !== files::unzip_file($zip, $base)) {
			files::clean_tmp_files();
			return false;
		}

		// Get hashes.
		$files = files::find_files($base);
		$hashes = files::checksum($files, false);

		// We need to rebuild the hashes to pretend that the files were
		// in the regular plugins directory.
		$old_base = $base;
		files::to_relative($old_base);
		common\ref\file::trailingslash($old_base);
		$new_base = common\file::trailingslash(files::get_plugins_dir());

		$out = array();
		foreach ($hashes as $k=>$v) {
			$out[str_replace($old_base, $new_base, $k)] = $v;
		}

		// Clean up.
		files::clean_tmp_files();

		return $out;
	}

	/**
	 * Load Plugin Checksums
	 *
	 * Make sure checksums for each plugin are in the database.
	 *
	 * @param bool $refresh Refresh.
	 * @return bool|WP_Error True or error.
	 */
	public static function load_plugin_checksums($refresh=false) {
		global $wpdb;

		static::get_plugins();
		$inserts = array();
		$slugs = array();

		// If refreshing, clear the database.
		if ($refresh) {
			$wpdb->delete(
				"{$wpdb->prefix}looksee3_core",
				array('type'=>'plugin'),
				'%s'
			);
		}

		// Loop through each plugin.
		foreach (static::$plugins as $k=>$v) {
			$slug = static::md5($v['slug']);
			$slugs[$k] = $slug;

			// Already present, or we can't do it.
			if ((!$refresh && $v['checksums']) || !$v['uri']) {
				continue;
			}

			$hashes = false;

			// Try the WP.org API.
			if (0 === strpos($v['uri'], 'https://downloads.wordpress.org/')) {
				$hashes = static::get_plugin_remote_checksums_api($v['slug'], $v['version']);
			}

			// Fallback to downloading the source.
			if ($v['current'] && (false === $hashes)) {
				$hashes = static::get_plugin_remote_checksums($v['uri']);
			}

			// We got hashes! Let's save them!
			if (false !== $hashes) {
				foreach ($hashes as $k2=>$v2) {
					$line = array(
						"'plugin'",
						"'" . esc_sql($slug) . "'",
						static::crc32($v['version']),
						"'" . static::md5($k2) . "'",
						"'" . esc_sql($k2) . "'",
						"'$v2'",
					);
					$inserts[] = '(' . implode(',', $line) . ')';
				}
			}
		}

		// Add to the database in chunks.
		if (count($inserts)) {
			$inserts = array_chunk($inserts, static::CHUNK);
			foreach ($inserts as $v) {
				$wpdb->query("
					INSERT INTO `{$wpdb->prefix}looksee3_core` (`type`, `slug`, `version`, `file_hash`, `file_path`, `checksum`)
					VALUES " . implode(',', $v)
				);
			}
		}

		// Recalculate which plugins have checksums, and also remove any
		// entries that are no longer applicable.
		$dbResult = $wpdb->get_results("
			SELECT DISTINCT `slug`
			FROM `{$wpdb->prefix}looksee3_core`
			WHERE `type`='plugin'
		", ARRAY_A);
		if (is_array($dbResult) && count($dbResult)) {
			foreach ($dbResult as $Row) {
				if (false !== ($k = array_search($Row['slug'], $slugs, true))) {
					static::$plugins[$k]['checksums'] = true;
				}
				else {
					$wpdb->delete(
						"{$wpdb->prefix}looksee3_core",
						array(
							'type'=>'plugin',
							'slug'=>$Row['slug'],
						),
						'%s'
					);
				}
			}
		}

		// All good!
		return true;
	}

	// ----------------------------------------------------------------- end plugins



	// -----------------------------------------------------------------
	// Themes
	// -----------------------------------------------------------------

	/**
	 * Get Theme Details
	 *
	 * @return array Theme details.
	 */
	public static function get_themes() {
		global $wpdb;

		if (is_null(static::$themes)) {
			@require_once(ABSPATH . 'wp-admin/includes/theme.php');

			$active = basename(get_stylesheet_directory());
			$all = wp_get_themes();

			static::$themes = array();

			// The relative theme root.
			$base = files::get_themes_dir();

			// Loop through everything.
			foreach ($all as $k=>$v) {
				$tmp = static::TEMPLATE;

				$tmp['active'] = ($k === $active);
				$tmp['slug'] = $k;
				$tmp['base'] = "{$base}$k/";
				$tmp['name'] = $v->Name;
				$tmp['version'] = $v->Version;

				$remote = static::get_theme_remote($tmp['slug']);
				if (count($remote)) {
					$tmp['current'] = version_compare($remote['version'], $tmp['version']) === 0;
					$tmp['uri'] = $remote['download_link'];
				}

				// Are there checksums?
				$tmp['checksums'] = 0 < (int) $wpdb->get_var("
					SELECT COUNT(*)
					FROM `{$wpdb->prefix}looksee3_core`
					WHERE
						`type`='theme' AND
						`slug`='" . static::md5($tmp['slug']) . "' AND
						`version`=" . static::crc32($tmp['version'])
				);

				// Remove obsolete checksums while we're here.
				if (!$tmp['checksums']) {
					$wpdb->delete(
						"{$wpdb->prefix}looksee3_core",
						array(
							'type'=>'theme',
							'slug'=>static::md5($tmp['slug']),
						),
						'%s'
					);
				}

				static::$themes[] = $tmp;
			}

			// Sort by name to make display nicer.
			usort(static::$themes, function($a, $b) {
				if ($a['name'] === $b['name']) {
					return 0;
				}

				return $a['name'] < $b['name'] ? -1 : 1;
			});
		}

		return static::$themes;
	}

	/**
	 * Get Remote Details
	 *
	 * Pull information from the WordPress API and cache the results to
	 * save a little overhead.
	 *
	 * @param string $slug Slug.
	 * @return array Remote details.
	 */
	protected static function get_theme_remote($slug='') {
		$transient_key = 'looksee_remote_theme_' . static::md5($slug);
		if (false === ($out = get_transient($transient_key))) {
			@require_once(ABSPATH . 'wp-admin/includes/theme.php');
			@require_once(ABSPATH . 'wp-admin/includes/theme-install.php');

			$out = themes_api(
				'theme_information',
				array(
					'slug'=>$slug,
					'fields'=>about::API_FIELDS,
				)
			);
			if (is_wp_error($out)) {
				$out = array();
			}
			else {
				// StdClasses are stupid. Sorry. Not sorry.
				$out = (array) $out;
				set_transient($transient_key, $out, 3600);
			}
		}

		return $out;
	}

	/**
	 * Get Remote Checksums
	 *
	 * WordPress doesn't maintain an easy database of theme checksums
	 * like they do with the Core, so we have to download clean copies,
	 * crunch the hashes, then remove the said copy.
	 *
	 * A bit crazy...
	 *
	 * @param string $uri Download Zip.
	 * @return array|bool Checksums or false.
	 */
	protected static function get_theme_remote_checksums($uri='') {
		if (!files::can_write()) {
			return array();
		}

		// Make sure the URL looks good.
		common\ref\sanitize::url($uri);
		if (!$uri || !preg_match('/\.zip$/ui', $uri)) {
			return false;
		}

		// Our tmp directory.
		if (false === ($base = files::make_tmp_dir())) {
			return false;
		}

		// Download the Zip file.
		$zip = download_url($uri);
		if (is_wp_error($zip)) {
			files::clean_tmp_files();
			return false;
		}

		// Extract it.
		if (true !== files::unzip_file($zip, $base)) {
			files::clean_tmp_files();
			return false;
		}

		// Get hashes.
		$files = files::find_files($base);
		$hashes = files::checksum($files, false);

		// We need to rebuild the hashes to pretend that the files were
		// in the regular themes directory.
		$old_base = $base;
		files::to_relative($old_base);
		common\ref\file::trailingslash($old_base);
		$new_base = common\file::trailingslash(files::get_themes_dir());

		$out = array();
		foreach ($hashes as $k=>$v) {
			$out[str_replace($old_base, $new_base, $k)] = $v;
		}

		// Clean up.
		files::clean_tmp_files();

		return $out;
	}

	/**
	 * Load Plugin Checksums
	 *
	 * Make sure checksums for each theme are in the database.
	 *
	 * @param bool $refresh Refresh.
	 * @return bool|WP_Error True or error.
	 */
	public static function load_theme_checksums($refresh=false) {
		global $wpdb;

		static::get_themes();
		$inserts = array();
		$slugs = array();

		// If refreshing, clear the database.
		if ($refresh) {
			$wpdb->delete(
				"{$wpdb->prefix}looksee3_core",
				array('type'=>'theme'),
				'%s'
			);
		}

		// Loop through each theme.
		foreach (static::$themes as $k=>$v) {
			$slug = static::md5($v['slug']);
			$slugs[$k] = $slug;

			// Already present, or we can't do it.
			if (
				(!$refresh && $v['checksums']) ||
				!$v['current'] ||
				!$v['uri']
			) {
				continue;
			}

			if (false !== ($hashes = static::get_theme_remote_checksums($v['uri']))) {
				foreach ($hashes as $k2=>$v2) {
					$line = array(
						"'theme'",
						"'" . esc_sql($slug) . "'",
						static::crc32($v['version']),
						"'" . static::md5($k2) . "'",
						"'" . esc_sql($k2) . "'",
						"'$v2'",
					);
					$inserts[] = '(' . implode(',', $line) . ')';
				}
			}
		}

		// Add to the database in chunks.
		if (count($inserts)) {
			$inserts = array_chunk($inserts, static::CHUNK);
			foreach ($inserts as $v) {
				$wpdb->query("
					INSERT INTO `{$wpdb->prefix}looksee3_core` (`type`, `slug`, `version`, `file_hash`, `file_path`, `checksum`)
					VALUES " . implode(',', $v)
				);
			}
		}

		// Recalculate which themes have checksums, and also remove any
		// entries that are no longer applicable.
		$dbResult = $wpdb->get_results("
			SELECT DISTINCT `slug`
			FROM `{$wpdb->prefix}looksee3_core`
			WHERE `type`='theme'
		", ARRAY_A);
		if (is_array($dbResult) && count($dbResult)) {
			foreach ($dbResult as $Row) {
				if (false !== ($k = array_search($Row['slug'], $slugs, true))) {
					static::$themes[$k]['checksums'] = true;
				}
				else {
					$wpdb->delete(
						"{$wpdb->prefix}looksee3_core",
						array(
							'type'=>'theme',
							'slug'=>$Row['slug'],
						),
						'%s'
					);
				}
			}
		}

		// All good!
		return true;
	}

	// ----------------------------------------------------------------- end themes



	// -----------------------------------------------------------------
	// Hashing
	// -----------------------------------------------------------------

	/**
	 * ASCII-85 MD5 Hash
	 *
	 * We use MD5 for checksums, but also for certain string values like
	 * paths and slugs as a workaround for case-insensitivity and max
	 * key-length database restrictions.
	 *
	 * That's all good and well, but hexidecimal notation requires a
	 * string length of 32 for each hash. By using a larger charset, it
	 * is possible to store the equivalent information in a more compact
	 * way.
	 *
	 * @see {https://en.wikipedia.org/wiki/Ascii85#ZeroMQ_Version_.28Z85.29}
	 *
	 * @param string $str String.
	 * @return string Hash.
	 */
	public static function md5($str) {
		common\ref\cast::to_string($str, true);

		// Let's start by getting raw MD5 output.
		if (preg_match('/^[a-f\d]{32}$/', $str)) {
			$raw = pack('H*', $str);
		}
		else {
			$raw = md5($str, 1);
		}

		$hash = '';
		$length = strlen($raw);
		$byte = $value = 0;

		while ($byte < $length) {
			$chr = ord($raw[$byte++]);
			$value = ($value * 256) + $chr;
			if (($byte % 4) === 0) {
				$divisor = 52200625; // This is 85^4.
				while ($divisor >= 1) {
					$x = bcmod(floor($value / $divisor), 85);
					$hash .= static::Z85[$x];
					$divisor /= 85;
				}
				$value = 0;
			}
		}

		return $hash;
	}

	/**
	 * CRC32
	 *
	 * This is a simple CRC32 wrapper that ensures an unsigned value
	 * is always returned, which 32-bit PHP environments might not do.
	 *
	 * @param string $str String.
	 * @return string Hash.
	 */
	public static function crc32($str) {
		$hash = crc32($str);
		return sprintf('%u', $hash);
	}

	// ----------------------------------------------------------------- end hashing



	// -----------------------------------------------------------------
	// Analysis
	// -----------------------------------------------------------------

	/**
	 * Missing Salts
	 *
	 * Over the years WordPress has added additional authentication keys
	 * and salts to the core. Old sites might not have newer ones
	 * defined.
	 *
	 * @return array Missing salts.
	 */
	public static function get_missing_salts() {
		$out = array();
		foreach (static::SALTS as $salt) {
			if (!defined($salt) || !constant($salt)) {
				$out[] = $salt;
			}
		}

		return $out;
	}

	/**
	 * Weak Salts
	 *
	 * Test for defined but weak salts.
	 *
	 * @return array Weak salts.
	 */
	public static function get_weak_salts() {
		$out = array();
		foreach (static::SALTS as $salt) {
			if (
				defined($salt) &&
				is_string(constant($salt)) &&
				common\mb::strlen(constant($salt)) < 35
			) {
				$out[] = $salt;
			}
		}

		return $out;
	}

	/**
	 * Test Salts
	 *
	 * Whether or not all salts are defined and/or strongish.
	 *
	 * @param bool $weak Test weak.
	 * @return bool True/false.
	 */
	public static function analyze_salts($weak=false) {
		return !(
			count(static::get_missing_salts()) ||
			($weak && count(static::get_weak_salts()))
		);
	}

	/**
	 * Test Default Prefix
	 *
	 * Whether or not the site is using a custom database prefix.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_prefix() {
		global $wpdb;
		return ('wp_' !== $wpdb->prefix);
	}

	/**
	 * Test Default Users
	 *
	 * Whether or not the site has default admin users.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_administrators() {
		return !(username_exists('admin') || username_exists('administrator'));
	}

	/**
	 * Test File Editor
	 *
	 * Whether or not the file editor is enabled.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_editor() {
		return (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT);
	}

	/**
	 * Test SSL
	 *
	 * Test whether SSL is required.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_ssl() {
		// First, make sure the base URL has HTTPS protocol.
		$url = get_option('siteurl');
		if (!preg_match('/^https:/ui', $url)) {
			return false;
		}

		// We can go farther if CURL is supported and make sure that
		// content is redirected.
		$url = 'http:' . LOOKSEE_PLUGIN_URL . 'img/blobfolio.svg';
		if (extension_loaded('curl')) {
			try {
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $url);
				curl_setopt($ch, CURLOPT_HEADER, true);
				curl_setopt($ch, CURLOPT_NOBODY, true);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($ch, CURLOPT_TIMEOUT, 10);
				curl_setopt($ch, CURLOPT_USERAGENT, 'Look-See');
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
				curl_exec($ch);

				$test = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
				common\ref\sanitize::url($test);

				curl_close($ch);

				if ($test) {
					return !!preg_match('/^https:/ui', $test);
				}
			} catch (\Throwable $e) {
				$test = false;
			} catch (\Exception $e) {
				$test = false;
			}
		}

		return true;
	}

	/**
	 * Test Inactive Themes
	 *
	 * Inactive content is still content, just not loved.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_inactive_themes() {
		$themes = static::get_themes();
		foreach ($themes as $v) {
			if (!$v['active']) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Test Inactive Plugins
	 *
	 * Inactive content is still content, just not loved.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_inactive_plugins() {
		$plugins = static::get_plugins();
		foreach ($plugins as $v) {
			if (!$v['active']) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Test Updates
	 *
	 * Make sure all updates are applied.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_updates() {
		$updates = wp_get_update_data();
		$total = isset($updates['counts']['total']) ? (int) $updates['counts']['total'] : 0;
		return !$total;
	}

	/**
	 * Test SVG
	 *
	 * If SVGs are enabled, make sure there is some sanitizing.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_svg() {
		$types = get_allowed_mime_types();
		if (!isset($types['svg'])) {
			$svg = false;
			foreach ($types as $k=>$v) {
				common\ref\mb::strtolower($k);
				$ext = explode('|', $k);
				if (in_array('svg', $ext, true)) {
					$svg = true;
					break;
				}
			}
			if (!$svg) {
				return true;
			}
		}

		// SVG is enabled, is there a plugin to help?
		return (
			defined('BLOBMIMES_BASE_PATH') ||
			class_exists('safe_svg') ||
			function_exists('common_upload_real_mimes')
		);
	}

	/**
	 * Test Directory Index
	 *
	 * Whether or not directory indexing is enabled.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_index() {
		$url = (is_ssl() ? 'https:' : 'http:') . LOOKSEE_PLUGIN_URL . 'img/';
		$response = wp_remote_get($url);
		if (200 === wp_remote_retrieve_response_code($response)) {
			$response = wp_remote_retrieve_body($response);
			return (false === common\mb::strpos($response, 'blobfolio.svg'));
		}

		return true;
	}

	/**
	 * Test Apocalypse Meow
	 *
	 * Whether or not Apocalypse Meow is installed, but only if the
	 * environment would support it.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_meow() {
		return (!extension_loaded('bcmath') || defined('MEOW_PLUGIN_DIR'));
	}

	/**
	 * Test Recent Scan
	 *
	 * Whether or not a scan has been run recently.
	 *
	 * @return bool True/false.
	 */
	public static function analyze_scan() {
		global $wpdb;
		return 0 < intval($wpdb->get_var("
			SELECT COUNT(*)
			FROM `{$wpdb->prefix}looksee3_scans`
			WHERE
				`status`='finished' AND
				`error`='' AND
				`date_finished` >= '" . date('Y-m-d H:i:s', strtotime('-1 week', current_time('timestamp'))) . "'
		"));
	}

	// ----------------------------------------------------------------- end analysis
}
