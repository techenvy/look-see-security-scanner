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
			echo '<div class="updated fade"><p>The core definitions for WordPress ' . get_bloginfo('version') . ' have been successfully installed.  Click <a href="' . esc_url(admin_url('tools.php?page=looksee-security-scanner')) . '" title="Look-See Security Scanner">here</a> to continue to the Look-See Security Scanner.</p></div>';
			return;
		}
		else
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
		<p>The core definitions for WordPress <?php echo get_bloginfo('version'); ?> need to be installed before a scan can be run.</p>
		<p>
			<form id="form-looksee-core-scan" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
			<?php wp_nonce_field('looksee-core-definitions'); ?>
			<input type="submit" value="Install Now" />
			</form>
		</p>
	</div>

</div>
<?php return; ?>