<?php
/**
 * Admin: Premium License
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

use \blobfolio\wp\looksee\admin;
use \blobfolio\wp\looksee\ajax;
use \blobfolio\wp\looksee\license;
use \blobfolio\wp\looksee\options;
use \blobfolio\wp\looksee\vendor\common;

$data = array(
	'forms'=>array(
		'pro'=>array(
			'action'=>'looksee_ajax_pro',
			'n'=>ajax::get_nonce(),
			'license'=>options::get('license'),
			'errors'=>array(),
			'saved'=>false,
			'loading'=>false,
		),
	),
	'freeload'=>license::FREELOAD,
);
$license = license::get($data['forms']['pro']['license']);
$data['license'] = $license->get_license();

// JSON doesn't appreciate broken UTF.
common\ref\sanitize::utf8($data);
?>
<script>var lookseeData=<?php echo json_encode($data, JSON_HEX_AMP); ?>;</script>
<div class="wrap" id="vue-pro" v-cloak>
	<h1>Look-See Security Scanner: <?php echo __('Premium License', LOOKSEE_L10N); ?></h1>

	<?php
	// Warn about OpenSSL.
	if (!function_exists('openssl_get_publickey')) {
		echo '<div class="notice notice-warning">';
			// @codingStandardsIgnoreStart
			echo '<p>' . __('Please ask your system administrator to enable the OpenSSL PHP extension. Without this, your site will be unable to decode and validate the license details itself. In the meantime, Look-See Security Scanner will try to offload this task to its own server. This should get the job done, but won\'t be as efficient and could impact performance a bit.', LOOKSEE_L10N) . '</p>';
			// @codingStandardsIgnoreEnd
		echo '</div>';
	}
	?>

	<div class="updated" v-if="forms.pro.saved"><p><?php echo __('Your license has been saved!', LOOKSEE_L10N); ?></p></div>
	<div class="error" v-for="error in forms.pro.errors"><p>{{error}}</p></div>

	<div id="poststuff">
		<div id="post-body" class="metabox-holder looksee-columns one-two">

			<!-- License -->
			<div class="postbox-container two">
				<div class="postbox">
					<h3 class="hndle"><?php echo __('License Key', LOOKSEE_L10N); ?></h3>
					<div class="inside">
						<form name="proForm" method="post" action="<?php echo admin_url('admin-ajax.php'); ?>" v-on:submit.prevent="proSubmit">
							<textarea id="looksee-license" class="looksee-code" name="license" v-model.trim="forms.pro.license" placeholder="Paste your license key here."></textarea>
							<p><button type="submit" v-bind:disabled="forms.pro.loading" class="button button-primary button-large"><?php echo __('Save', LOOKSEE_L10N); ?></button></p>
						</form>
					</div>
				</div>
			</div><!--.postbox-container-->

			<!-- License -->
			<div class="postbox-container one">

				<div class="postbox" v-if="!license.license_id">
					<h3 class="hndle"><?php echo __('The Pro Pitch', LOOKSEE_L10N); ?></h3>
					<div class="inside">
						<?php
						echo '<p>' . sprintf(
							__("For the cost of an expensive sandwich, you can get a Look-See %s! It's the same great administrative tool, just more of it:", LOOKSEE_L10N),
							'<a href="' . LOOKSEE_URL . '" target="_blank">' . __('Premium license', LOOKSEE_L10N) . '</a>'
						) . '</p>';

						echo '<ul style="list-style: disc; margin-left: 2em;">';
						echo '<li>' . __('Quick Actions: view source code, fix permission/ownership issues, ignore, or delete entries with the push of a button;', LOOKSEE_L10N) . '</li>';
						echo '<li>' . sprintf(
							__('Complete %s integration;', LOOKSEE_L10N),
							'<a href="https://wp-cli.org/" target="_blank" rel="noopener">WP-CLI</a>'
						) . '</li>';
						echo '</ul>';

						echo '<p>' . sprintf(
							__('To learn more, visit %s.', LOOKSEE_L10N),
							'<a href="' . LOOKSEE_URL . '" target="_blank">blobfolio.com</a>'
						) . '</p>';
						?>
					</div>
				</div>

				<div class="postbox" v-if="license.license_id && !isFreeload">
					<h3 class="hndle"><?php echo __('Your License', LOOKSEE_L10N); ?></h3>
					<div class="inside">
						<table class="looksee-meta">
							<tbody>
								<tr>
									<th scope="row"><?php echo __('Created', LOOKSEE_L10N); ?></th>
									<td>{{license.date_created}}</td>
								</tr>
								<tr v-if="license.date_created !== license.date_updated">
									<th scope="row"><?php echo __('Updated', LOOKSEE_L10N); ?></th>
									<td>{{license.date_updated}}</td>
								</tr>
								<tr v-if="license.errors.revoked">
									<th class="looksee-fg-orange" scope="row"><?php echo __('Revoked', LOOKSEE_L10N); ?></th>
									<td>{{license.date_revoked}}</td>
								</tr>
								<tr>
									<th scope="row"><?php echo __('Name', LOOKSEE_L10N); ?></th>
									<td>{{license.name}}</td>
								</tr>
								<tr v-if="license.company">
									<th scope="row"><?php echo __('Company', LOOKSEE_L10N); ?></th>
									<td>{{license.company}}</td>
								</tr>
								<tr>
									<th scope="row"><?php echo __('Email', LOOKSEE_L10N); ?></th>
									<td>{{license.email}}</td>
								</tr>
								<tr>
									<th scope="row"><?php echo __('Type', LOOKSEE_L10N); ?></th>
									<td>{{license.type}}</td>
								</tr>
								<tr>
									<th v-bind:class="{'looksee-fg-orange' : license.errors.item}" scope="row"><?php echo __('Thing', LOOKSEE_L10N); ?></th>
									<td>{{license.item}}</td>
								</tr>
								<tr v-if="license.type === 'single'">
									<th v-bind:class="{'looksee-fg-orange' : license.errors.domain}" scope="row"><?php echo __('Domain(s)', LOOKSEE_L10N); ?></th>
									<td>
										<div v-for="domain in license.domains">{{domain}}</div>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php echo __('Help', LOOKSEE_L10N); ?></th>
									<td>
										<span v-if="!license.errors.domain && !license.errors.item && !license.errors.revoked"><?php echo __('Thanks for going Pro!', LOOKSEE_L10N); ?></span>
										<?php
										echo sprintf(
											__('If you have any questions or need help, visit %s.', LOOKSEE_L10N),
											'<a href="' . LOOKSEE_URL . '" target="_blank">blobfolio.com</a>'
										);
										?>
									</td>
							</tbody>
						</table>
					</div>
				</div>

				<div class="postbox" v-if="!license.license_id || isFreeload">
					<h3 class="hndle"><?php echo __('Freeload Edition', LOOKSEE_L10N); ?></h3>
					<div class="inside" v-if="!isFreeload">
						<?php
						$out = array(
							sprintf(
								__("If you can't afford a %s or do not wish to purchase one, you can still enable premium functionality by clicking the button below.", LOOKSEE_L10N),
								'<a href="' . LOOKSEE_URL . '" target="_blank">Premium License</a>'
							),
							__('If your situation changes in the future, you can always switch the registration to a real license. :)', LOOKSEE_L10N),
						);

						echo '<p>' . implode('</p><p>', $out) . '</p>';
						?>
						<p><button class="button" type="button" v-on:click.prevent="freeloadSubmit" v-bind:disabled="forms.pro.loading"><?php echo __('Enable', LOOKSEE_L10N); ?></button></p>
					</div>
					<div class="inside" v-else>
						<?php
						$out = array(
							__('The Freeload Edition has been enabled so you have access to all premium features. Hurray for Code Anarchy!', LOOKSEE_L10N),
							sprintf(
								__('If you went ahead and purchased a %s — thanks! — just go ahead and replace the key and hit save.', LOOKSEE_L10N),
								'<a href="' . LOOKSEE_URL . '" target="_blank">Premium License</a>'
							),
						);

						echo '<p>' . implode('</p><p>', $out) . '</p>';
						?>
					</div>
				</div>

				<?php
				$plugins = admin::sister_plugins();
				if (count($plugins)) {
					?>
					<div class="postbox">
						<div class="inside">
							<a href="https://blobfolio.com/" target="_blank" class="sister-plugins--blobfolio"><?php echo file_get_contents(LOOKSEE_PLUGIN_DIR . 'img/blobfolio.svg'); ?></a>

							<div class="sister-plugins--intro">
								<?php
								echo sprintf(
									__('Impressed with %s?', LOOKSEE_L10N) . '<br>' .
									__('You might also enjoy these other fine and practical plugins from %s.', LOOKSEE_L10N),
									'<strong>Look-See Security Scanner</strong>',
									'<a href="https://blobfolio.com/" target="_blank">Blobfolio, LLC</a>'
								);
								?>
							</div>

							<nav class="sister-plugins">
								<?php foreach ($plugins as $p) { ?>
									<div class="sister-plugin">
										<a href="<?php echo esc_attr($p['url']); ?>" target="_blank" class="sister-plugin--name"><?php echo esc_html($p['name']); ?></a>

										<div class="sister-plugin--text"><?php echo esc_html($p['description']); ?></div>
									</div>
								<?php } ?>
							</nav>
						</div>
					</div>
				<?php } ?>

			</div><!--.postbox-container-->

		</div><!--#post-body-->
	</div><!--#poststuff-->
</div><!--.wrap-->
