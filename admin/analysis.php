<?php
/**
 * Admin: Configuration Analysis
 *
 * @package Look-See Security Scanner
 * @author  Blobfolio, LLC <hello@blobfolio.com>
 */

/**
 * Do not execute this file directly.
 */
if (!defined('ABSPATH')) {
	exit;
}

use \blobfolio\wp\looksee\core;
use \blobfolio\wp\looksee\vendor\common;

// Flesh out inactive content errors.
$inactive = array();
if (!core::analyze_inactive_plugins()) {
	$tmp = core::get_plugins();
	foreach ($tmp as $k=>$v) {
		if (!$v['active']) {
			$inactive[] = '<li>' . __('Plugin', LOOKSEE_L10N) . ': <code>' . esc_html($v['name']) . '</code></li>';
		}
	}
}
if (!core::analyze_inactive_themes()) {
	$tmp = core::get_themes();
	foreach ($tmp as $k=>$v) {
		if (!$v['active']) {
			$inactive[] = '<li>' . __('Theme', LOOKSEE_L10N) . ': <code>' . esc_html($v['name']) . '</code></li>';
		}
	}
}

// And onto the data!
$data = array(
	'tests'=>array(
		array(
			'title'=>__('Administrator Accounts', LOOKSEE_L10N),
			'status'=>core::analyze_administrators(),
			'errors'=>array(
				sprintf(
					__('Generic usernames like "admin" or "administrator" are present and should be renamed. Plugins like %s (pro) and %s can help with this.', LOOKSEE_L10N),
					'<a href="https://wordpress.org/plugins/apocalypse-meow/" target="_blank" rel="noopener">Apocalypse Meow</a>',
					'<a href="https://wordpress.org/plugins/rename-users/" target="_blank" rel="noopener">Rename Users</a>'
				),
			),
		),
		array(
			'title'=>__('Authentication Salts & Keys', LOOKSEE_L10N),
			'status'=>core::analyze_salts(true),
			'errors'=>array(
				sprintf(
					__('Your site contains weak and/or missing authentication salts. Visit %s and copy the output into %s.', LOOKSEE_L10N),
					'<a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener">' . __('here', LOOKSEE_L10N) . '</a>',
					'<code>wp-config.php</code>'
				),
			),
		),
		array(
			'title'=>__('Database Prefix', LOOKSEE_L10N),
			'status'=>core::analyze_prefix(),
			'errors'=>array(
				sprintf(
					__('Your site is currently using the default table prefix, %s. It is not completely straightforward to retroactively fix this, however %s can point you in the right direction.', LOOKSEE_L10N),
					'<code>wp_</code>',
					'<a href="http://www.wpbeginner.com/wp-tutorials/how-to-change-the-wordpress-database-prefix-to-improve-security/" target="_blank" rel="noopener">' . __('this tutorial', LOOKSEE_L10N) . '</a>'
				),
			),
		),
		array(
			'title'=>__('Directory Listing', LOOKSEE_L10N),
			'status'=>core::analyze_index(),
			'errors'=>array(
				sprintf(
					__('Your site currently lists directory contents. For example, click %s. For information on how to fix this, visit %s.', LOOKSEE_L10N),
					'<a href="' . LOOKSEE_PLUGIN_URL . 'img/" target="_blank">' . __('here', LOOKSEE_L10N) . '</a>',
					'<a href="https://www.netsparker.com/blog/web-security/disable-directory-listing-web-servers/" target="_blank" rel="noopener">' . __('here', LOOKSEE_L10N) . '</a>'
				),
			),
		),
		array(
			'title'=>__('File Editor', LOOKSEE_L10N),
			'status'=>core::analyze_editor(),
			'errors'=>array(
				sprintf(
					__('The editor is currently enabled on your site. To disable it, add the following code to %s:', LOOKSEE_L10N),
					'<code>wp-config.php</code>'
				),
				"<code>define('DISALLOW_FILE_EDIT', true);</code>",
			),
		),
		array(
			'title'=>__('File Scans', LOOKSEE_L10N),
			'status'=>core::analyze_scan(),
			'errors'=>array(
				sprintf(
					__('You have not completed a file scan recently. Click %s to do that now.', LOOKSEE_L10N),
					'<a href="' . admin_url('admin.php?page=looksee-scan') . '">' . __('here', LOOKSEE_L10N) . '</a>'
				),
			),
		),
		array(
			'title'=>__('SSL', LOOKSEE_L10N),
			'status'=>core::analyze_ssl(),
			'errors'=>array(
				__('It appears that your site might not be fully protected with SSL. Look-See is not able to determine this with 100% accuracy, so if this assessment is wrong, please ignore it.', LOOKSEE_L10N),
				sprintf(
					__("Otherwise, you're in for a treat! For a rundown on how to get an existing WordPress web site up and running over SSL, click %s.", LOOKSEE_L10N),
					'<a href="https://blobfolio.com/2017/07/how-to-enable-ssl-for-wordpress/" target="_blank" rel="noopener">' . __('here', LOOKSEE_L10N) . '</a>'
				),
			),
		),
		array(
			'title'=>__('SVG', LOOKSEE_L10N),
			'status'=>core::analyze_svg(),
			'errors'=>array(
				sprintf(
					__('SVG support has been manually enabled for your site, leaving you at extreme risk. In order to protect yourself, please install %s.', LOOKSEE_L10N),
					'<a href="https://wordpress.org/plugins/blob-mimes/" target="_blank" rel="noopener">Lord of the Files</a>'
				),
			),
		),
		array(
			'title'=>__('Inactive Plugins & Themes', LOOKSEE_L10N),
			'status'=>!count($inactive),
			'errors'=>array(
				__('The following inactive content is still publicly accessible on your server. You should fully delete any content you are not using.', LOOKSEE_L10N),
				'<ul>' . implode("\n", $inactive) . '</ul>',
			),
		),
		array(
			'title'=>__('Updates & Security Patches', LOOKSEE_L10N),
			'status'=>core::analyze_updates(),
			'errors'=>array(
				sprintf(
					__('Your copy of WordPress is not fully up-to-date. Please head on over to %s to apply all available updates.', LOOKSEE_L10N),
					'<a href="' . admin_url('update-core.php') . '">' . __('the update page', LOOKSEE_L10N) . '</a>'
				),
			),
		),
	),
	'meow'=>core::analyze_meow(),
	'modal'=>'',
	'modals'=>array(
		// @codingStandardsIgnoreStart
		__('Administrator Accounts', LOOKSEE_L10N)=>array(
			sprintf(
				__('WordPress\' popularity makes it a strong target for automated, %s login attacks. The vast majority of these attacks are waged by rather stupid robots that assume the existence of default usernames like "admin" or "administrator".', LOOKSEE_L10N),
				'<a href="https://en.wikipedia.org/wiki/Brute-force_attack" target="_blank" rel="noopener">' . __('brute-force', LOOKSEE_L10N) . '</a>'
			),
			__('By not having logins with these names, the vast majority of login attacks are moot.', LOOKSEE_L10N),
		),
		__('Authentication Salts & Keys', LOOKSEE_L10N)=>array(
			sprintf(
				__('WordPress uses site-defined %s to improve session security. It is important that each salt is defined in %s, and that that definition is strong.', LOOKSEE_L10N),
				'<a href="https://en.wikipedia.org/wiki/Salt_(cryptography)" target="_blank" rel="noopener">' . __('salts', LOOKSEE_L10N) . '</a>',
				'<code>wp-config.php</code>'
			),
			sprintf(
				__("Don't try to think of random values on your own. Just visit %s and copy-and-paste the results into your %s.", LOOKSEE_L10N),
				'<a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener">WP.org</a>',
				'<code>wp-config.php</code>'
			),
		),
		__('Database Prefix', LOOKSEE_L10N)=>array(
			sprintf(
				__('%s attacks often require that the attacker already know the names of tables in the database. To help combat this, WordPress allows sites to prepend a custom prefix to each table name.', LOOKSEE_L10N),
				'<a href="https://en.wikipedia.org/wiki/SQL_injection" target="_blank" rel="noopener">' . __('SQL Injection', LOOKSEE_L10N) . '</a>'
			),
		),
		__('Directory Listing', LOOKSEE_L10N)=>array(
			sprintf(
				__('Depending on the server configuration, if someone visits a directory that does not include a file named %s or %s, etc., in a web browser, the contents of that directory will be listed.', LOOKSEE_L10N),
				'<code>index.html</code>',
				'<code>index.php</code>'
			),
			__('This can make it much easier for attackers to gather information about the files on your server and better target their attacks.', LOOKSEE_L10N)
		),
		__('File Editor', LOOKSEE_L10N)=>array(
			__('WordPress ships with a tool that allows site administrators to directly edit the code of themes, plugins, and other files on the server.', LOOKSEE_L10N),
			__('If this tool is enabled and someone manages to break into WordPress, it will give them broader system access than they might otherwise have.', LOOKSEE_L10N),
		),
		__('File Scans', LOOKSEE_L10N)=>array(
			__("It is important that you run frequent file scans of your site to ensure that everything is as it should be. But hey, that's what Look-See is for!", LOOKSEE_L10N),
		),
		__('SSL', LOOKSEE_L10N)=>array(
			__('Without an SSL certificate, any communication between a visitor and your site can be intercepted by anybody else on the networks.', LOOKSEE_L10N),
			__('This means things like login and other personal information can be stolen, but the corruption can work in the other direction too. Many cheap hotel, cafe, and airport networks, for example, will inject advertising into unencrypted pages, and sinister networks can even inject malware.', LOOKSEE_L10N),
			__('Thus it is important that EVERY communication is encrypted, not just administrative areas.', LOOKSEE_L10N),
		),
		__('SVG', LOOKSEE_L10N)=>array(
			sprintf(
				__('Despite the massive popularity of the %s image format (particularly with modern web designers), WordPress does not allow them to be uploaded by default. As it turns out, SVG is insanely susceptible to malicious content and %s impossible to sanitize.', LOOKSEE_L10N),
				'<a href="https://en.wikipedia.org/wiki/Scalable_Vector_Graphics" target="_blank" rel="noopener">SVG</a>',
				'<a href="https://blobfolio.com/2017/03/when-a-stranger-calls-sanitizing-svgs/" target="_blank" rel="noopener">' . __('almost', LOOKSEE_L10N) . '</a>'
			),
		),
		__('Inactive Plugins & Themes', LOOKSEE_L10N)=>array(
			__('Any code on your server has the potential to contain exploitable vulnerabilities, even if it is part of a theme or plugin that is not currently "active".', LOOKSEE_L10N),
		),
		__('Updates & Security Patches', LOOKSEE_L10N)=>array(
			sprintf(
				__('WordPress and its plugins and themes are %s. This is beneficial in that bugs and security issues can be identified and fixed more quickly, however in order for users to benefit, updates must be applied.', LOOKSEE_L10N),
				'<a href="https://en.wikipedia.org/wiki/Open-source_software_development#Model" target="_blank" rel="noopener">' . __('open-source', LOOKSEE_L10N) . '</a>'
			),
		),
		// @codingStandardsIgnoreEnd
	),
);


// JSON doesn't appreciate broken UTF.
common\ref\sanitize::utf8($data);
?>
<script>var lookseeData=<?php echo json_encode($data, JSON_HEX_AMP); ?>;</script>
<div class="wrap" id="vue-analysis" v-cloak>
	<h1>Look-See Security Scanner: <?php echo __('Configuration Analysis', LOOKSEE_L10N); ?></h1>

	<div id="poststuff">
		<div id="post-body" class="metabox-holder looksee-columns" v-bind:class="{'one-two' : !meow}">

			<!-- Main Items -->
			<div class="postbox-container two">
				<div class="postbox">
					<h3 class="hndle"><?php echo __('Issues', LOOKSEE_L10N); ?></h3>
					<div class="inside">
						<table class="looksee-results">
							<thead>
								<tr>
									<th><?php echo __('Status', LOOKSEE_L10N); ?></th>
									<th><?php echo __('Configuration', LOOKSEE_L10N); ?></th>
								</tr>
							</thead>
							<tbody>
								<tr class="looksee-analysis" v-for="item in tests">
									<td>
										<span class="dashicons" v-bind:class="{'dashicons-yes' : item.status, 'dashicons-no' : !item.status}"></span>
									</td>
									<td>
										<div class="looksee-analysis--title">
											<span v-bind:class="{'looksee-fg-orange' : !item.status}">{{ item.title }}</span>

											<span class="dashicons dashicons-info looksee-info-toggle" v-bind:class="{'is-active' : modal === item.title}" v-on:click.prevent="toggleModal(item.title)"></span>
										</div>

										<div v-if="!item.status" class="looksee-analysis--resolution">
											<p v-for="p in item.errors" v-html="p"></p>
										</div>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div><!--.postbox-container-->

			<!-- Sidebar -->
			<div class="postbox-container one" v-if="!meow">
				<div class="postbox">
					<h3 class="hndle">Apocalypse Meow</h3>
					<div class="inside">
						<?php
						$out = array(
							__("WordPress ships with a lot of inherent vulnerabilities. Some of these issues are related to advanced functionality that many users won't end up using, while others are felt to be outside the scope of what the main software should handle.", LOOKSEE_L10N),
							__('Regardless, most of these threats are completely unnecessary.', LOOKSEE_L10N),
							sprintf(
								__('%s is a simple, educational security plugin designed to harden WordPress security and help mitigate active threats.', LOOKSEE_L10N),
								'<a href="https://wordpress.org/plugins/apocalypse-meow/" target="_blank" rel="noopener">Apocalypse Meow</a>'
							),
							__('Look-See will help you identify possible security issues, but is mostly a post-mortem tool. To keep attackers from gaining access to your site in the first place, Apocalypse Meow is a must.', LOOKSEE_L10N),
						);

						echo '<p>' . implode('</p><p>', $out) . '</p>';
						?>
					</div>
				</div>
			</div><!--.postbox-container-->

		</div><!--#post-body-->
	</div><!--#poststuff-->



	<!-- ==============================================
	HELP MODAL
	=============================================== -->
	<transition name="fade">
		<div v-if="modal" class="looksee-modal">
			<span class="dashicons dashicons-dismiss looksee-modal--close" v-on:click.prevent="toggleModal('')"></span>
			<div class="looksee-modal--inner">
				<p v-for="p in modals[modal]" v-html="p"></p>
			</div>
		</div>
	</transition>
</div><!--.wrap-->
