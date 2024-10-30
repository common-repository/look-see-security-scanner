<?php
/**
 * Look-See Security Scanner Filesystem.
 *
 * Various path and file helpers. Everything is meant to be handled
 * relative to ABSPATH. This reduces the amount of data having to be
 * stored and makes the results more portable.
 *
 * @package look-see-security-scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

namespace blobfolio\wp\looksee;

use \blobfolio\wp\looksee\vendor\common;
use \ZipArchive;
use \PclZip;

class files {

	// Image formats.
	const IMAGES = array(
		'a?png',
		'ai',
		'dib',
		'eps',
		'gif',
		'ico',
		'iff',
		'ilbm',
		'j2(c|k)',
		'jb2',
		'jfif?',
		'jif',
		'jp(2|c|e|f|m|x)',
		'jpe?g',
		'jpg(2|m)',
		'lbm',
		'mjp?2',
		'psd',
		'svgz?',
		'tiff?',
		'w?bmp',
		'webp',
		'xbm',
	);

	// Audio and video formats.
	const MEDIA = array(
		'3ga',
		'3gp{0,2}2?',
		'a?snd',
		'aac?',
		'aax',
		'ac3',
		'adp',
		'aif(c|f)?',
		'am(r|z)',
		'ape',
		'asx',
		'au',
		'av(i|f|x)',
		'awb',
		'axu',
		'cpt',
		'divx',
		'drc',
		'dts(hd)?',
		'f4(a|b)',
		'f4v',
		'flac',
		'flc',
		'jpg?m',
		'jpgv',
		'lrv',
		'm(1|2)v',
		'm(2|3)a',
		'm3u8?',
		'm4(a|b|u|v)',
		'midi?',
		'mjp?2',
		'mlp',
		'moo?v',
		'mp(1|2|3|4|g)a?',
		'mp4v',
		'mpe',
		'mpg4',
		'mxu',
		'og(a|g|m|v|x)',
		'opus',
		'pcm',
		'qt',
		'qtl',
		'qtvr',
		'ra',
		'spx',
		'vivo?',
		'vob',
		'wave?',
		'wax',
		'weba',
		'webm',
		'wm(a|x)',
		'wvx',
	);

	const INFO = array(
		'checksum'=>'',
		'chmod'=>0,
		'chown'=>'',
		'date_modified'=>'0000-00-00 00:00:00',
		'mime'=>'application/octet-stream',
		'path'=>'',
		'size'=>0,
		'status'=>'invalid',
	);

	// A transient key for temporary files and directories we've made.
	const TMP_FILES = 'looksee_tmp_files';

	// Files used to build an ownership/permission consensus.
	const TEST_FILES = array(
		'index.php',
		'wp-config.php',
		'wp-cron.php',
		'wp-load.php',
		'wp-settings.php',
	);

	protected static $can_write;

	protected static $abspath;
	protected static $admin_dir;
	protected static $content_dir;
	protected static $includes_dir;
	protected static $plugins_dir;
	protected static $themes_dir;
	protected static $tmp_dir;
	protected static $uploads_dir;

	protected static $chmod;
	protected static $chown;

	protected static $blacklist = array();
	protected static $skip_cache = false;
	protected static $skip_media = false;
	protected static $skip_size = 0;

	protected static $_init = false;



	// -----------------------------------------------------------------
	// Setup/Init
	// -----------------------------------------------------------------

	/**
	 * Init
	 *
	 * Run a couple things early on so the environment is ready for us.
	 *
	 * @return void Nothing.
	 */
	public static function init() {
		if (!static::$_init) {
			static::$_init = true;

			static::get_base_dir();

			// Define some constants. This is the most efficient way to
			// repeatedly reference values within large loops.

			// Strip ABSPATH from a path.
			define('LOOKSEE_REGEX_ABSPATH', '/^([a-z]:)?' . preg_quote(static::$abspath, '/') . '/ui');

			// Match restricted paths.
			define('LOOKSEE_REGEX_RESTRICTED', '/^(' . preg_quote(static::get_admin_dir(), '/') . '|' . preg_quote(static::get_includes_dir(), '/') . ')/ui');
			define('LOOKSEE_REGEX_RESTRICTED_UPLOADS', '/^' . preg_quote(static::get_uploads_dir(), '/') . '.*\.php$/uiS');

			// Set up a few more options.
			static::scan_init();

			// And finish it off.
			static::can_write();
			static::clean_tmp_files();
		}
	}

	/**
	 * Scan Settings
	 *
	 * Set option-specific scan filters, etc.
	 *
	 * @param array $scan Scan settings.
	 * @return bool True/false.
	 */
	public static function scan_init($scan=null) {
		if (is_array($scan)) {
			$scan = common\data::parse_args($scan, options::get('scan'));
			options::sanitize_blacklist($scan['blacklist']);
		}
		else {
			$scan = options::get('scan');
		}

		static::$skip_cache = false;
		static::$skip_media = false;
		static::$skip_size = 0;
		static::$blacklist = $scan['blacklist'];

		// Match cache.
		if ($scan['skip_cache']) {
			static::$skip_cache = '/^(' . preg_quote(static::get_content_dir() . 'cache/', '/') . ')/ui';
		}

		// Match media. We'll combine the image and audio/video filters
		// into one.
		$soup = array();
		if ($scan['skip_images']) {
			$soup = static::IMAGES;
		}
		if ($scan['skip_media']) {
			$soup = array_merge($soup, static::MEDIA);
		}
		if (count($soup)) {
			sort($soup);
			$soup = implode('|', $soup);
			static::$skip_media = '/^' . preg_quote(static::get_uploads_dir(), '/') . '.*\.(' . $soup . ')$/uiS';
		}

		// Max file size.
		if ($scan['skip_size'] > 0) {
			static::$skip_size = $scan['skip_size'];
		}

		return true;
	}

	/**
	 * Can We Write?
	 *
	 * Not all WordPress environments (or connection types) come with
	 * the necessary ability to write filesystem changes.
	 *
	 * @return string Path.
	 */
	public static function can_write() {
		if (is_null(static::$can_write)) {
			require_once(ABSPATH . 'wp-admin/includes/file.php');

			if (!defined('FS_CHMOD_DIR')) {
				define('FS_CHMOD_DIR', (@fileperms(ABSPATH) & 0777 | 0755));
			}
			if (!defined('FS_CHMOD_FILE')) {
				define('FS_CHMOD_FILE', (@fileperms(ABSPATH . 'index.php') & 0777 | 0644));
			}

			try {
				static::$can_write = (
					@is_readable(ABSPATH) &&
					@is_writable(static::get_tmp_dir())
				);
			} catch (\Throwable $e) {
				static::$can_write = false;
			} catch (\Exception $e) {
				static::$can_write = false;
			}
		}

		return static::$can_write;
	}

	// ----------------------------------------------------------------- end init



	// -----------------------------------------------------------------
	// Paths
	// -----------------------------------------------------------------

	/**
	 * Get Abspath
	 *
	 * @return string Path.
	 */
	public static function get_base_dir() {
		if (is_null(static::$abspath)) {
			static::$abspath = common\file::path(ABSPATH);
			static::$abspath = preg_replace('/^[a-z]:/ui', '', static::$abspath);
		}

		return static::$abspath;
	}

	/**
	 * Get Admin Root
	 *
	 * @return string Path.
	 */
	public static function get_admin_dir() {
		if (is_null(static::$admin_dir)) {
			static::$admin_dir = common\file::path(static::get_base_dir() . 'wp-admin/');
			static::to_relative(static::$admin_dir);
			common\ref\file::trailingslash(static::$admin_dir);
		}

		return static::$admin_dir;
	}

	/**
	 * Get Content Root
	 *
	 * @return string Path.
	 */
	public static function get_content_dir() {
		if (is_null(static::$content_dir)) {
			static::$content_dir = common\file::path(WP_CONTENT_DIR);
			static::to_relative(static::$content_dir);
			common\ref\file::trailingslash(static::$content_dir);
		}

		return static::$content_dir;
	}

	/**
	 * Get Includes Root
	 *
	 * @return string Path.
	 */
	public static function get_includes_dir() {
		if (is_null(static::$includes_dir)) {
			static::$includes_dir = common\file::path(static::get_base_dir() . WPINC);
			static::to_relative(static::$includes_dir);
			common\ref\file::trailingslash(static::$includes_dir);
		}

		return static::$includes_dir;
	}

	/**
	 * Get Plugins Root
	 *
	 * @return string Path.
	 */
	public static function get_plugins_dir() {
		if (is_null(static::$plugins_dir)) {
			static::$plugins_dir = common\file::path(WP_PLUGIN_DIR);
			static::to_relative(static::$plugins_dir);
			common\ref\file::trailingslash(static::$plugins_dir);
		}

		return static::$plugins_dir;
	}

	/**
	 * Get Themes Root
	 *
	 * @return string Path.
	 */
	public static function get_themes_dir() {
		if (is_null(static::$themes_dir)) {
			static::$themes_dir = common\file::path(WP_CONTENT_DIR . '/themes');
			static::to_relative(static::$themes_dir);
			common\ref\file::trailingslash(static::$themes_dir);
		}

		return static::$themes_dir;
	}

	/**
	 * Get Tmp Root
	 *
	 * @return string Path.
	 */
	public static function get_tmp_dir() {
		if (is_null(static::$tmp_dir)) {
			static::$tmp_dir = static::get_base_dir() . static::get_uploads_dir() . '_look-see/';

			// Make sure the temporary directory exists.
			if (!@file_exists(static::$tmp_dir)) {
				@mkdir(static::$tmp_dir, FS_CHMOD_DIR);
				if (!@file_exists(static::$tmp_dir)) {
					static::$can_write = false;
				}
			}
		}

		return static::$tmp_dir;
	}

	/**
	 * Make a Temporary Directory
	 *
	 * @return string|bool Path or false.
	 */
	public static function make_tmp_dir() {
		$base = static::get_tmp_dir();
		if ($base) {
			$sub = '.' . common\data::random_string(10);
			while (@file_exists("{$base}{$sub}")) {
				$sub = '.' . common\data::random_string(10);
			}

			@mkdir("{$base}{$sub}", FS_CHMOD_DIR);
			if (!@file_exists("{$base}{$sub}")) {
				static::$can_write = false;
				$base = '';
			}
			else {
				$base = common\file::path("{$base}{$sub}");
			}
		}

		return $base ? $base : false;
	}

	/**
	 * Get Uploads Root
	 *
	 * @return string Path.
	 */
	public static function get_uploads_dir() {
		if (is_null(static::$uploads_dir)) {
			$uploads_dir = wp_upload_dir();
			static::$uploads_dir = common\file::path($uploads_dir['basedir']);
			static::to_relative(static::$uploads_dir);
			common\ref\file::trailingslash(static::$uploads_dir);
		}

		return static::$uploads_dir;
	}

	/**
	 * To Relative Path
	 *
	 * @param string $path Absolute path.
	 * @return void Nothing.
	 */
	public static function to_relative(&$path) {
		static::sanitize_relative($path);
	}

	/**
	 * To Absolute Path
	 *
	 * @param string $path Relative path.
	 * @return void Nothing.
	 */
	public static function to_absolute(&$path) {
		static::sanitize_relative($path);
		$path = static::get_base_dir() . $path;
		if (@is_dir($path)) {
			common\ref\file::trailingslash($path);
		}
	}

	/**
	 * Sanitize Relative Path
	 *
	 * @param string $path Absolute path.
	 * @return bool True/false.
	 */
	public static function sanitize_relative(&$path) {
		common\ref\cast::to_string($path, true);
		common\ref\mb::trim($path);
		common\ref\file::unixslash($path);
		common\ref\file::trailingslash($path);

		$path = preg_replace(LOOKSEE_REGEX_ABSPATH, '', $path);

		common\ref\file::unleadingslash($path);
		common\ref\file::untrailingslash($path);

		// Can't be above ABSPATH.
		if (
			('.' === $path) ||
			('../' === common\mb::substr($path, 0, 3))
		) {
			$path = '';
			return false;
		}

		// Get rid of middle selfies.
		$path = str_replace('/./', '/', $path);

		// Try to fix .. Unix links.
		if ((false !== strpos($path, '/')) && (false !== strpos($path, '..'))) {
			$parts = explode('/', $path);
			if (in_array('..', $parts, true)) {
				$parts = array_reverse($parts);

				// Remove the .. and what comes after (before as
				// this is being run in reverse).
				for ($x = 0; $x < count($parts) - 1; ++$x) {
					if ('..' === $parts[$x]) {
						array_splice($parts, $x, 2);
						$x--;
					}
				}

				$parts = array_reverse($parts);
				$path = implode('/', $parts);
			}
		}

		// Get rid of trailing or ending selfies.
		$path = preg_replace('/^\.\//u', '', $path);
		$path = preg_replace('/\/\.$/u', '', $path);

		return $path ? true : false;
	}

	/**
	 * Clean Up Temporary Files
	 *
	 * Delete any temporary files the previous session might have
	 * missed (because of timeouts, etc.).
	 *
	 * @return bool True/False.
	 */
	public static function clean_tmp_files() {
		if (!static::can_write()) {
			return false;
		}

		$dir = static::get_tmp_dir();
		if (!@is_dir($dir)) {
			return false;
		}

		if ($handle = opendir($dir)) {
			while (false !== ($file = readdir($handle))) {
				// Ignore dots.
				if (('.' === $file) || ('..' === $file)) {
					continue;
				}

				$path = "{$dir}{$file}";
				if (@is_dir($path)) {
					common\file::rmdir($path);
				}
				elseif (@is_file($path)) {
					@unlink($path);
				}
			}
			closedir($handle);
		}

		return true;
	}

	/**
	 * Get "Default" Ownership
	 *
	 * A server might have a mixture of ownerships. We'll check a few
	 * files and pick the most common.
	 *
	 * @return string Owner:Group.
	 */
	public static function chown() {
		if (!static::can_write()) {
			return '';
		}

		if (is_null(static::$chown)) {
			$out = array();
			foreach (static::TEST_FILES as $v) {
				$owner = static::get_owner($v);
				$group = static::get_group($v);
				if ($owner && $group) {
					$chown = "$owner:$group";
					if (!isset($out[$chown])) {
						$out[$chown] = 0;
					}
					++$out[$chown];
				}
			}

			if (count($out)) {
				arsort($out);
				static::$chown = array_keys($out);
				static::$chown = static::$chown[0];
			}
			else {
				static::$chown = '';
			}
		}

		return static::$chown;
	}

	/**
	 * Get "Default" Permissions
	 *
	 * A server might have a mixture of permissions. We'll check a few
	 * files and pick the most common.
	 *
	 * @return int Permissions.
	 */
	public static function chmod() {
		if (!static::can_write()) {
			return 0;
		}

		if (is_null(static::$chmod)) {
			$out = array();
			foreach (static::TEST_FILES as $v) {
				$chmod = static::get_chmod($v);
				if ($chmod > 0) {
					if (!isset($out[$chmod])) {
						$out[$chmod] = 0;
					}
					++$out[$chmod];
				}
			}

			if (count($out)) {
				arsort($out);
				static::$chmod = array_keys($out);
				static::$chmod = static::$chmod[0];
			}
			else {
				static::$chmod = 0;
			}
		}

		return static::$chmod;
	}

	// ----------------------------------------------------------------- end paths



	// -----------------------------------------------------------------
	// Scanning Functions
	// -----------------------------------------------------------------

	/**
	 * Get Chmod
	 *
	 * @param string $file File.
	 * @return int Chmod.
	 */
	public static function get_chmod($file) {
		return (int) substr(decoct(@fileperms($file)), -3);
	}

	/**
	 * Get Owner
	 *
	 * @param string $file File.
	 * @return string Owner.
	 */
	public static function get_owner($file) {
		$uid = (int) @fileowner($file);
		if (!$uid) {
			return '';
		}
		if (!function_exists('posix_getpwuid')) {
			return (string) $uid;
		}
		$info = posix_getpwuid($uid);
		return $info['name'];
	}

	/**
	 * Get Group
	 *
	 * @param string $file File.
	 * @return int Chmod.
	 */
	public static function get_group($file) {
		$uid = (int) @filegroup($file);
		if (!$uid) {
			return '';
		}
		if (!function_exists('posix_getgrgid')) {
			return (string) $uid;
		}
		$info = posix_getgrgid($uid);
		return $info['name'];
	}

	/**
	 * Find Files
	 *
	 * Return an array of file paths. The emphasis here is speed. Once
	 * we have a master list, we can do more precise calculations in
	 * chunks.
	 *
	 * @param string $path Path.
	 * @return array Files.
	 */
	public static function find_files($path=null) {
		if (!static::can_write()) {
			return array();
		}

		// Default to ABSPATH.
		if (is_null($path)) {
			$path = static::get_base_dir();
		}
		else {
			static::to_absolute($path);
			if ((static::get_tmp_dir() === $path) || !@is_dir($path)) {
				return array();
			}
		}

		$out = array();

		try {
			// Scan all files in dir.
			$handle = opendir($path);
			while (false !== ($entry = readdir($handle))) {
				// Anything but a dot === not empty.
				if (('.' === $entry) || ('..' === $entry)) {
					continue;
				}

				$file = "{$path}{$entry}";

				// Add file.
				if (@is_file($file)) {
					// We can trust these results enough to avoid some
					// of the heavier relative-path tasks. Let's just
					// fix slashes and chop the root off.
					common\ref\file::unixslash($file);
					$file = preg_replace(LOOKSEE_REGEX_ABSPATH, '', $file);

					$out[] = $file;
				}
				// Recursively search directories.
				else {
					$tmp = static::find_files($file);
					foreach ($tmp as $v) {
						$out[] = $v;
					}
					unset($tmp);
				}
			}
		} catch (\Throwable $e) {
			return $out;
		} catch (\Exception $e) {
			return $out;
		}

		$out = array_unique($out);
		sort($out);

		return $out;
	}

	/**
	 * Hash Files
	 *
	 * Return an array of file hashes.
	 *
	 * @param array $paths Relative paths.
	 * @return array Files.
	 */
	public static function checksum($paths) {
		if (!static::can_write()) {
			return array();
		}

		$out = array();

		common\ref\cast::to_array($paths);
		$paths = array_unique($paths);

		foreach ($paths as $v) {
			static::to_absolute($v);
			if (
				$v &&
				('/' !== common\mb::substr($v, -1)) &&
				@is_file($v)
			) {
				try {
					if (false !== ($md5 = @md5_file($v))) {
						$md5 = core::md5($md5);
						// Just strip the root off.
						$v = preg_replace(LOOKSEE_REGEX_ABSPATH, '', $v);
						$out[$v] = $md5;
					}
				} catch (\Throwable $e) {
					continue;
				} catch (\Exception $e) {
					continue;
				}
			}
		}

		ksort($out);
		return $out;
	}

	/**
	 * Extended File Info
	 *
	 * Return an array of file information.
	 *
	 * @param string $path Paths.
	 * @param string $conditional Conditional.
	 * @return array Files.
	 */
	public static function info($path, $conditional=false) {
		$out = static::INFO;

		if (!static::can_write()) {
			return $out;
		}

		static::to_absolute($path);
		if (!$path || '/' === common\mb::substr($path, -1) || !@is_file($path)) {
			return $out;
		}

		// Conditional checks?
		if ($conditional && static::is_ignored($path)) {
			$out['status'] = 'skipped';
			return $out;
		}

		$out['path'] = preg_replace(LOOKSEE_REGEX_ABSPATH, '', $path);

		try {
			$out['size'] = (int) @filesize($path);
			if (static::$skip_size && $out['size'] > static::$skip_size) {
				$out['status'] = 'skipped';
				return $out;
			}

			$owner = static::get_owner($path);
			$group = static::get_group($path);
			if ($owner && $group) {
				$out['chown'] = "$owner:$group";
			}

			$out['chmod'] = static::get_chmod($path);

			$out['date_modified'] = date('Y-m-d H:i:s', @filemtime($path));

			$finfo = common\mime::finfo($path);
			$out['mime'] = $finfo['mime'];

			if (false === ($out['checksum'] = @md5_file($path))) {
				$out['checksum'] = '';
			}
			else {
				$out['checksum'] = core::md5($out['checksum']);
			}

			$out['status'] = 'valid';
		} catch (\Throwable $e) {
			return $out;
		} catch (\Exception $e) {
			return $out;
		}

		return $out;
	}

	/**
	 * Ignore a File?
	 *
	 * Check whether a given file should be ignored because of its path.
	 *
	 * @param string $path Path.
	 * @return bool True/false.
	 */
	public static function is_ignored($path) {
		// If we can't check, we can't scan.
		if (!static::can_write()) {
			return true;
		}

		// Start with some straight-forward path-matching.
		static::to_relative($path);
		if (
			!$path ||
			!@is_file(static::get_base_dir() . $path) ||
			(static::$skip_cache && preg_match(static::$skip_cache, $path)) ||
			(static::$skip_media && preg_match(static::$skip_media, $path))
		) {
			return true;
		}

		// The user blacklist is a little wilder.
		if (count(static::$blacklist) && function_exists('fnmatch')) {
			foreach (static::$blacklist as $v) {
				if (fnmatch($v, $path)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Is Core Path?
	 *
	 * Check whether a given file is in a directory that should have
	 * authoritative checksums. This is used primarily in locating
	 * unexpected files.
	 *
	 * @param string $path Path.
	 * @return bool True/false.
	 */
	public static function is_core_path($path) {
		// If we can't check, we can't scan.
		if (!static::can_write()) {
			return true;
		}

		static::to_relative($path);
		if (
			!$path ||
			!@is_file($path)
		) {
			return false;
		}

		// Some easy checks.
		if (
			preg_match(LOOKSEE_REGEX_RESTRICTED, $path) ||
			(('index.php' !== basename($path)) && preg_match(LOOKSEE_REGEX_RESTRICTED_UPLOADS, $path))
		) {
			return true;
		}

		// Check plugins and themes.
		$files = array_merge(core::get_plugins(), core::get_themes());
		foreach ($files as $v) {
			if (
				$v['checksums'] &&
				preg_match('/^' . preg_quote($v['base'], '/') . '/ui', $path)
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Chown Match?
	 *
	 * Check whether a given file has the expected ownership. True will
	 * be returned if the ownership matches as well as if any sort of
	 * system error prevents ownership from being checked.
	 *
	 * @param string $path Path.
	 * @return bool True/false.
	 */
	public static function verify_chown($path) {
		$chown = static::chown();
		if (!$chown) {
			return true;
		}

		static::to_absolute($path);
		if (!$path) {
			return true;
		}

		$owner = static::get_owner($path);
		$group = static::get_group($path);
		return (!$owner || !$group || ("$owner:$group" === $chown));
	}

	/**
	 * Chmod Match?
	 *
	 * Check whether a given file has the expected permissions. True
	 * will be returned if the file's permissions are at or below the
	 * expected, or if any sort of system error prevents checking.
	 *
	 * @param string $path Path.
	 * @return bool True/false.
	 */
	public static function verify_chmod($path) {
		$chmod = static::chmod();
		if (!$chmod) {
			return true;
		}

		static::to_absolute($path);
		if (!$path) {
			return true;
		}

		$chmod2 = static::get_chmod($path);
		if (!$chmod2) {
			return true;
		}

		$perms = static::chmod_to_permissions($chmod);
		$perms2 = static::chmod_to_permissions($chmod2);

		foreach ($perms2 as $k=>$v) {
			// Looking for extra permissions only.
			if (count(array_diff($v, $perms[$k]))) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Chmod Decimal to Privilege Array
	 *
	 * This will convert a simple decimal like 644 to an array of
	 * privileges arranged by who.
	 *
	 * @param int $chmod Chmod.
	 * @return array Permissions.
	 */
	public static function chmod_to_permissions($chmod) {
		common\ref\cast::to_int($chmod, true);
		$chmod = (string) $chmod;
		$chmod = str_pad($chmod, 3, '0', STR_PAD_LEFT);
		if (isset($chmod[3])) {
			$chmod = substr($chmod, -3);
		}

		$out = array(
			'u'=>array(),
			'g'=>array(),
			'o'=>array(),
		);

		foreach (array_keys($out) as $k=>$v) {
			$char = $chmod[$k];
			// Everything.
			if ('7' === $char) {
				$out[$v] = array('r', 'w', 'x');
			}
			else {
				// Read.
				if (in_array($char, array('4', '5', '6'), true)) {
					$out[$v][] = 'r';
				}
				// Write.
				if (in_array($char, array('2', '3', '6'), true)) {
					$out[$v][] = 'w';
				}
				// Execute.
				if (in_array($char, array('1', '3', '5'), true)) {
					$out[$v][] = 'x';
				}
			}
		}

		return $out;
	}

	// ----------------------------------------------------------------- end scanning



	// -----------------------------------------------------------------
	// Misc
	// -----------------------------------------------------------------

	/**
	 * Unzip File
	 *
	 * The native WordPress functions rely on WP_Filesystem, which is
	 * not compatible with some of the modes in which this plugin runs.
	 * So... gotta rewrite it all. Haha.
	 *
	 * Unlike the WP version, the destination path is expected to exist.
	 *
	 * @param string $zip Zip path.
	 * @param string $to Destination path.
	 * @return bool True/false.
	 */
	public static function unzip_file($zip, $to) {
		common\ref\file::path($zip);
		common\ref\file::path($to);

		if (
			!$zip ||
			!$to ||
			!@is_file($zip) ||
			!@is_dir($to)
		) {
			return false;
		}

		// Do it with ZipArchive?
		if (
			class_exists('ZipArchive', false) &&
			apply_filters('unzip_file_use_ziparchive', true)
		) {
			try {
				$size = 0;
				$dirs = array();

				$z = new ZipArchive();
				if (true !== ($zopen = $z->open($zip, ZipArchive::CHECKCONS))) {
					return false;
				}

				// First pass, calculate the needed size and build a
				// list of directories.
				for ($x = 0; $x < $z->numFiles; ++$x) {
					if (false === ($info = $z->statIndex($x))) {
						return false;
					}

					// Skip Mac nonsense.
					if ('__MACOSX/' === common\mb::substr($info['name'], 0, 9)) {
						continue;
					}

					$size += $info['size'];

					if ('/' === common\mb::substr($info['name'], -1)) {
						$dirs[] = common\file::path("{$to}{$info['name']}", false);
					}
					elseif ('.' !== ($dirname = dirname($info['name']))) {
						$dirs[] = common\file::path($to . trailingslashit($dirname), false);
					}
				}

				// Make sure we have room.
				$space = (int) @disk_free_space(WP_CONTENT_DIR);
				if ($space && ($size * 2.1) > $space) {
					return false;
				}

				// Make the directories.
				$dirs = array_unique($dirs);
				rsort($dirs);
				foreach ($dirs as $d) {
					if (!@file_exists($d)) {
						@mkdir($d, FS_CHMOD_DIR, true);
						if (!@is_dir($d)) {
							return false;
						}
					}
				}

				// One more time around, kick out the files.
				for ($x = 0; $x < $z->numFiles; ++$x) {
					if (false === ($info = $z->statIndex($x))) {
						return false;
					}

					// Skippable things.
					if (
						('/' === common\mb::substr($info['name'], -1)) ||
						('__MACOSX/' === common\mb::substr($info['name'], 0, 9))
					) {
						continue;
					}

					if (false === ($out = $z->getFromIndex($x))) {
						return false;
					}

					@file_put_contents("{$to}{$info['name']}", $out);
					if (!@file_exists("{$to}{$info['name']}")) {
						return false;
					}
					else {
						@chmod("{$to}{$info['name']}", FS_CHMOD_FILE);
					}
				}

				$z->close();

				return true;
			} catch (\Throwable $e) {
				return false;
			} catch (\Exception $e) {
				return false;
			}
		}

		// Try PclZip instead.
		require_once(ABSPATH . 'wp-admin/includes/class-pclzip.php');

		try {
			$z = new PclZip($zip);
			$size = 0;
			$dirs = array();

			$files = $z->extract(PCLZIP_OPT_EXTRACT_AS_STRING);
			if (!is_array($files) || !count($files)) {
				return false;
			}

			// Again, one loop for size and whatnot.
			foreach ($files as $v) {
				// Skip Mac nonsense.
				if ('__MACOSX/' === common\mb::substr($v['filename'], 0, 9)) {
					continue;
				}

				$size += $v['size'];

				if ($v['folder']) {
					$dirs[] = common\file::path("{$to}{$v['filename']}", false);
				}
				else {
					$dirs[] = common\file::path($to . trailingslashit(dirname($v['filename'])), false);
				}
			}

			// Make sure we have room.
			$space = (int) @disk_free_space(WP_CONTENT_DIR);
			if ($space && ($size * 2.1) > $space) {
				return false;
			}

			// Make the directories.
			$dirs = array_unique($dirs);
			rsort($dirs);
			foreach ($dirs as $d) {
				if (!@file_exists($d)) {
					@mkdir($d, FS_CHMOD_DIR, true);
					if (!@is_dir($d)) {
						return false;
					}
				}
			}

			// And once more around to actually extract the files.
			foreach ($files as $v) {
				// Skippable things.
				if (
					$v['folder'] ||
					('__MACOSX/' === common\mb::substr($v['filename'], 0, 9))
				) {
					continue;
				}

				@file_put_contents("{$to}{$v['filename']}", $v['content']);
				if (!@file_exists("{$to}{$v['filename']}")) {
					return false;
				}
				else {
					@chmod("{$to}{$v['filename']}", FS_CHMOD_FILE);
				}
			}

			return true;
		} catch (\Throwable $e) {
			return false;
		} catch (\Exception $e) {
			return false;
		}

		return false;
	}

	// ----------------------------------------------------------------- end misc
}
