<?php
//----------------------------------------------------------------------
//  Look-See Core Scanner
//----------------------------------------------------------------------
//Upgrade the WordPress core definitions
//
// @since 3.5-3



//--------------------------------------------------
//Check permissions

//let's make sure this page is being accessed through WP
if (!function_exists('current_user_can'))
	die('Sorry');
//and let's make sure the current user has sufficient permissions
elseif(!current_user_can('manage_options'))
	wp_die(__('You do not have sufficient permissions to access this page.'));



//--------------------------------------------------
//Should we even be here?  If not, load the scanner

//some quick variables
global $wpdb;
//any errors will go here for easy processing
$errors = array();



//--------------------------------------------------
//Updating definitions
if(getenv("REQUEST_METHOD") == "POST")
{
	//bad nonce, no scan
	if(!wp_verify_nonce($_POST['_wpnonce'],'looksee-core-definitions'))
		$errors[] = 'Sorry the form had expired.  Please try again.';
	else
	{
		if(false !== looksee_install_core_definitions())
		{
			//one more test, make sure there are actually rules!
			$rules = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `wp`='" . esc_sql(get_bloginfo('version')) . "'");
			if($rules > 0)
			{
				echo '<div class="updated fade"><p>The core definitions for WordPress ' . get_bloginfo('version') . ' have been successfully installed.  Click <a href="' . esc_url(admin_url('tools.php?page=looksee-security-scanner')) . '" title="Look-See Security Scanner">here</a> to continue to the Look-See Security Scanner.</p></div>';
				return;
			}
		}

		$errors[] = 'The core definitions could not be installed.';
	}
}
?>
<div class="wrap">

	<h2>Look-See Security Scanner</h2>
<?php
//error output
if(count($errors))
{
	foreach($errors AS $e)
		echo '<div class="error fade"><p>' . $e . '</p></div>';
}
?>

	<div class="error fade">
	<?php

	//do we need the table?
	$table = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}looksee_files'");
	if(is_null($table) || $table !== "{$wpdb->prefix}looksee_files")
	{
		?>
		<p>Zoinks!  The Look-See database table is missing.  This should have been created automatically when you first activated the plugin, but sometimes other plugins or themes might prevent that from happening.</p>
		<p>You can manually run the following MySQL command to build the missing table:</p>
			<textarea readonly onclick="this.select();" style="width: 100%; display: block; height: 200px;">CREATE TABLE <?php echo $wpdb->prefix; ?>looksee_files (
  id bigint(15) NOT NULL AUTO_INCREMENT,
  file varchar(300) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  wp varchar(10) DEFAULT '' NOT NULL,
  md5_expected char(32) DEFAULT '' NOT NULL,
  md5_found char(32) DEFAULT '' NOT NULL,
  md5_saved char(32) DEFAULT '' NOT NULL,
  queued tinyint(1) DEFAULT 0 NOT NULL,
  skipped tinyint(1) DEFAULT 0 NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY file (file),
  KEY wp (wp),
  KEY queued (queued),
  KEY skipped (skipped)
);</textarea>
		<p>Once you have done so, reload this page.</p>
		<?php
	}//no table
	//we just need definitions
	else
	{
		?>
		<p>The core definitions for WordPress <?php echo get_bloginfo('version'); ?> need to be installed before a scan can be run.</p>
		<p>
			<form id="form-looksee-core-scan" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
			<?php wp_nonce_field('looksee-core-definitions'); ?>
			<input type="submit" value="Install Now" />
			</form>
		</p>
		<?php
	}//need definitions
	?>
	</div><!--.error-->

</div>
<?php return; ?>