<?php
//----------------------------------------------------------------------
//  Look-See Core Scanner
//----------------------------------------------------------------------
//Compare checksums of core WP files with a list of what's expected.
//
// @since 1.0.0



//--------------------------------------------------
//Check permissions

//let's make sure this page is being accessed through WP
if (!function_exists('current_user_can'))
	die('Sorry');
//and let's make sure the current user has sufficient permissions
elseif(!current_user_can('manage_options'))
	wp_die(__('You do not have sufficient permissions to access this page.'));



//--------------------------------------------------
//Some variables we'll be using

//we need wpdb
global $wpdb;
//a list of currently installed plugins
$current_plugins = get_option('active_plugins');

?>
<div class="wrap">

	<h2>Look-See Security Scanner</h2>

	<h3 class="nav-tab-wrapper">
		&nbsp;
		<a href="<?php echo admin_url('tools.php?page=looksee-security-scanner'); ?>" class="nav-tab" title="Scan files">File system</a>
		<a href="<?php echo admin_url('tools.php?page=looksee-security-analysis'); ?>" class="nav-tab nav-tab-active" title="Analyze configurations">Configuration analysis</a>
	</h3>

	<div class="metabox-holder has-right-sidebar">

		<div id="post-body-content" class="has-sidebar">
			<div class="has-sidebar-content">

				<!--start scan history-->
				<div class="postbox">
					<h3 class="hndle">Scan Results</h3>
					<div class="inside">
						<ul id="looksee-scan-results">
<?php

//--------------------------------------------------
//Check security keys

$security_keys = array();
foreach(array('AUTH_KEY','AUTH_SALT','LOGGED_IN_KEY','LOGGED_IN_SALT','NONCE_KEY','NONCE_SALT','SECURE_AUTH_KEY','SECURE_AUTH_SALT') AS $key)
{
	if(!defined($key))
		$security_keys[] = "<i>$key</i> is missing.";
	elseif(constant($key) == 'put your unique phrase here')
		$security_keys[] = "<i>$key</i> has the unsafe default value.";
	elseif(!strlen(constant($key)))
		$security_keys[] = "<i>$key</i> is blank.";
}
echo '<li data-scan="securitykeys" class="looksee-status looksee-status-' . (count($security_keys) ? 'bad">Authentication keys and salts are incomplete.' : 'good">Authentication keys and salts are properly configured.') . '</li>';
if(count($security_keys))
{
	echo '<li class="looksee-status-details looksee-status-details-securitykeys looksee-status-details-description">WordPress uses eight authentication keys and salts that should be <b>unique</b> to each individual installation, making it harder for hackers to launch generic attacks.</li>
	<li class="looksee-status-details looksee-status-details-securitykeys looksee-status-details-description">Replace the definitions in your wp-config.php file with the random results generated at <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">https://api.wordpress.org/secret-key/1.1/salt/</a>.</li>';
	foreach($security_keys AS $key)
		echo '<li class="looksee-status-details looksee-status-details-securitykeys">' . $key . '</li>';
}

//--------------------------------------------------
//Check table prefix

echo '<li data-scan="tableprefix" class="looksee-status looksee-status-' . ($wpdb->prefix == 'wp_' ? 'bad">Default database table prefix detected.' : 'good">Database table prefix looks good.') . '</li>';
if($wpdb->prefix == 'wp_')
{
	echo '<li class="looksee-status-details looksee-status-details-tableprefix looksee-status-details-description">Changing the table prefix from <i>wp_</i> to anything else will protect your site from the vast majority of SQL injection attacks.</li>';
	echo '<li class="looksee-status-details looksee-status-details-tableprefix looksee-status-details-description">Take a look at <a href="http://www.wpbeginner.com/wp-tutorials/how-to-change-the-wordpress-database-prefix-to-improve-security/" title="How to Change the WordPress Database Prefix" target="_blank">http://www.wpbeginner.com/wp-tutorials/how-to-change-the-wordpress-database-prefix-to-improve-security/</a> for a helpful tutorial.</li>';
}

//--------------------------------------------------
//Check for default username

echo '<li data-scan="admin" class="looksee-status looksee-status-' . (username_exists('admin') ? 'bad">Default &quot;admin&quot; username exists.' : 'good">Default username not in use.') . '</li>';
if(username_exists('admin'))
{
	echo '<li class="looksee-status-details looksee-status-details-admin looksee-status-details-description">Almost every illicit attempt to gain access to your blog will do so with the default username &quot;admin&quot;.</li>';
	echo '<li class="looksee-status-details looksee-status-details-admin looksee-status-details-description">' . (in_array('apocalypse-meow/index.php', $current_plugins) ? 'Visit the <a href="' . admin_url('options-general.php?page=meow-settings') . '" title="Apocalypse Meow">Apocalypse Meow settings page</a> to rename this user.' : 'Apocalypse Meow can fix this for you (see below).') . '</li>';
}

//--------------------------------------------------
//Check for Apocalypse Meow

echo '<li data-scan="meow" class="looksee-status looksee-status-' . (!in_array('apocalypse-meow/index.php', $current_plugins) ? 'bad">Apocalypse Meow is not installed.' : 'good">Apocalypse Meow is installed.') . '</li>';
if(!in_array('apocalypse-meow/index.php', $current_plugins))
	echo '<li class="looksee-status-details looksee-status-details-meow looksee-status-details-description">Apocalypse Meow is Look-See\'s (pro-active) companion plugin.  It includes several tools to help lockdown your site and is highly recommended (and not just because we wrote it!).  Visit <a href="http://wordpress.org/extend/plugins/apocalypse-meow/" title="Apocalypse Meow" target="_blank">wordpress.org/extend/plugins/apocalypse-meow/</a> for more information.</li>';

//--------------------------------------------------
//Check for updates

$tmp = wp_get_update_data();
echo '<li data-scan="updates" class="looksee-status looksee-status-' . ($tmp['counts']['total'] > 0 ? 'bad">WordPress updates are available.' : 'good">WordPress is up-to-date.') . '</li>';
if($tmp['counts']['total'] > 0)
	echo '<li class="looksee-status-details looksee-status-details-updates looksee-status-details-description">Keeping your software up-to-date is critical!  Go to <a href="' . admin_url('update-core.php') . '" title="Updates">' . admin_url('update_core.php') . '</a> to get up to speed.</li>';


?>
						</ul>
					</div>
				</div>

			</div>
		</div>
	</div>

</div>