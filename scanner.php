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

//hold any error messages we come up with
$errors = array();
//we need wpdb
global $wpdb;



//--------------------------------------------------
//Check server/plugin support

//is there a version file?
if(!looksee_support_version())
	$errors[] = 'There is no file database for your version of WP (' . get_bloginfo('version') . ').  Double-check for available <a href="' . esc_url(admin_url('update-core.php')) . '" title="WordPress updates">software updates</a>, as applying them may well fix this problem.';

//can PHP generate MD5s?
if(!looksee_support_md5())
	$errors[] = 'This server does not support MD5 checksum generation, which is required to verify the integrity of your files.';

//error output
if(count($errors))
{
	foreach($errors AS $e)
		echo '<div class="error fade"><p>' . $e . '</p></div>';

	//these are deal-breakers, so let's get outta here
	return;
}

//if the database is missing proper core definitions, we need to load them before we can scan
if(!looksee_support_version_installed())
{
	//the code for doing so is offloaded to another file to keep things tidy
	require_once(dirname(__FILE__) . '/upgrade.php');
	return;
}



//--------------------------------------------------
//Setup the scan!

if(getenv("REQUEST_METHOD") === "POST")
{
	//--------------------------------------------------
	//Save Look-See settings
	if($_POST["action"] == 'looksee_scan_settings')
	{
		//bad nonce, no scan
		if(!wp_verify_nonce($_POST['nonce_settings'],'looksee_scan_settings'))
			$errors[] = 'Sorry the form had expired.  Please try again.';
		elseif(looksee_is_scanning())
			$errors[] = 'Settings cannot be changed while a scan is underway!';
		else
		{
			$looksee_settings = array();

			//sanitize post data
			$looksee_settings['looksee_max_size'] = (int) trim($_POST['looksee_max_size']);
			if($looksee_settings['looksee_max_size'] < 0)
				$looksee_settings['looksee_max_size'] = 10;

			$looksee_settings['looksee_skip_cache'] = array_key_exists('looksee_skip_cache', $_POST) && intval($_POST['looksee_skip_cache']) === 1 ? 1 : 0;

			//save settings
			$updated = 0;
			foreach($looksee_settings AS $k=>$v)
			{
				if(true === update_option($k, $v))
					$updated++;
			}

			//if there were any changes, let's spread the good word
			if($updated > 0)
				echo '<div class="updated fade"><p>The settings have been successfully saved.</p></div>';
		}
	}

	//--------------------------------------------------
	//Prepare for a Look-See Scan
	elseif($_POST["action"] == 'looksee_scan_start')
	{
		$core_only = array_key_exists('looksee_core_only', $_POST) && intval($_POST['looksee_core_only']) === 1;

		//bad nonce, no scan
		if(!wp_verify_nonce($_POST['nonce_start'],'looksee_scan_start'))
			$errors[] = 'Sorry the form had expired.  Please try again.';
		elseif(looksee_is_scanning())
			$errors[] = 'A scan is already underway!';
		elseif(false !== looksee_scan_start(false, $core_only))
			echo '<div class="updated fade"><p>Let\'s have a look-see!</p></div>';
		else
			$errors[] = 'The scan could not be started.';
	}

	//--------------------------------------------------
	//Reset scan definitions
	elseif($_POST["action"] == 'looksee_scan_definitions_reset')
	{
		//bad nonce, no scan
		if(!wp_verify_nonce($_POST['nonce_definitions_reset'],'looksee_scan_definitions_reset'))
			$errors[] = 'Sorry the form had expired.  Please try again.';
		elseif(looksee_is_scanning())
			$errors[] = 'The core definitions cannot be reset while a scan is underway!';
		elseif(false !== looksee_install_core_definitions(true))
			echo '<div class="updated fade"><p>The core definitions for WordPress ' . get_bloginfo('version') . ' have been successfully re-installed.</p></div>';
		else
			$errors[] = 'The core definitions were not reinstalled successfully.';
	}

	//--------------------------------------------------
	//Abort a scan
	elseif($_POST["action"] == 'looksee_scan_abort')
	{
		//bad nonce, no scan
		if(!wp_verify_nonce($_POST['nonce_abort'],'looksee_scan_abort'))
			$errors[] = 'Sorry the form had expired.  Please try again.';
		elseif(!looksee_is_scanning())
			$errors[] = 'A scan is not currently running.';
		elseif(false !== looksee_scan_abort())
			echo '<div class="updated fade"><p>The scan has been aborted.</p></div>';
		else
			$errors[] = 'The scan could not be aborted.';
	}
}
?>
<div class="wrap">

	<h2>Look-See Security Scanner</h2>

	<h3 class="nav-tab-wrapper">
		&nbsp;
		<a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>" class="nav-tab nav-tab-active" title="Scan files">File system</a>
		<a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-analysis')); ?>" class="nav-tab" title="Analyze configurations">Configuration analysis</a>
	</h3>
<?php
//error output
if(count($errors))
{
	foreach($errors AS $e)
		echo '<div class="error fade"><p>' . esc_html($e) . '</p></div>';
}
?>
	<div class="metabox-holder has-right-sidebar">

		<div class="inner-sidebar">

<?php
//present the form to start a scan
if(!looksee_is_scanning()) {
?>
			<!--start scan settings -->
			<div class="postbox">
				<form id="form-looksee-core-settings" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
				<?php wp_nonce_field('looksee_scan_settings','nonce_settings'); ?>
				<input type="hidden" name="action" value="looksee_scan_settings" />
				<h3 class="hndle">Settings</h3>
				<div class="inside">
					<ul>
						<li>
							<label for="looksee_max_size">Max Size (MB)</label>
							<input type="number" step="1" min="0" id="looksee_max_size" name="looksee_max_size" value="<?php echo looksee_get_option('looksee_max_size'); ?>" class="small-text" />
							<a href="#" class="settings-help" title="Click for more information" data-help="Most web scripts (including those hackers might monkey with) tend to be relatively small, and the larger a file is, the longer it takes the server to scan.  As such, ignoring large files could result in performance gains, especially if your web site hosts huge archives and/or runs on a tired old server.<?php echo "\n\n"; ?>To scan all files regardless of their size, set this option to '0'.">[?]</a>
						</li>
<?php
//scanning cache files is kind of annoying, so we can give the option to skip them
if(is_dir(dirname(dirname(dirname(__FILE__))) . '/cache'))
{
?>
						<li>
							<label><input type="checkbox" name="looksee_skip_cache" value="1" <?php echo (looksee_get_option('looksee_skip_cache') === true ? 'checked' : ''); ?> /> Skip cache files</label>
							<a href="#" class="settings-help" title="Click for more information" data-help="Cache files generated by plugins like W3TC change frequently, and therefore are not very useful to include in scan results.  Skipping them will increase the speed of the scan, too.">[?]</a>
						</li>
<?php
}
?>
						<li>
							<input type="submit" value="Save" />
						</li>
					</ul>
				</div>
				</form>
			</div>
			<!--end scan settings-->

			<!--start scan now-->
			<div class="postbox">
				<form id="form-looksee-core-scan" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
				<?php wp_nonce_field('looksee_scan_start','nonce_start'); ?>
				<input type="hidden" name="action" value="looksee_scan_start" />
				<h3 class="hndle">Run Scan Now</h3>
				<div class="inside">
					<ul>
						<li>
							<label for="looksee_core_only"><input type="checkbox" name="looksee_core_only" id="looksee_core_only" value="1" /> Core Scan only</label>
							<p class="description">Check the above box to limit the scan to only WP core files. You should only run this limited scan if your server is too slow to run a complete scan.</p>
						</li>
						<li>
							<input type="submit" value="Scan Now" />
						</li>
					</ul>
				</div>
				</form>
			</div>
			<!--end scan now-->

			<!--start reset core definitions-->
			<div class="postbox">
				<form id="form-looksee-core-definitions" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
				<?php wp_nonce_field('looksee_scan_definitions_reset','nonce_definitions_reset'); ?>
				<input type="hidden" name="action" value="looksee_scan_definitions_reset" />
				<h3 class="hndle">Reset Core Definitions</h3>
				<div class="inside">
					<ul>
						<li>If the server threw up an error during installation or if the installation was prematurely aborted, it is probably a good idea to give it another go.  Click the button below to re-install the definitions for WordPress <?php echo get_bloginfo('version'); ?>.</li>
						<li>
							<input type="submit" value="Reset" />
						</li>
					</ul>
				</div>
				</form>
			</div>
			<!--end reset core definitions-->
<?php
}//end scan button
//otherwise if a scan is in progress, let's show the progress!
else {
	$total = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");
	$completed = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=0");
	$percent = round(100 * $completed / $total, 0);
?>
			<!--start scan progress-->
			<div class="postbox">
				<h3 class="hndle">Scan Progress</h3>
				<div class="inside">
					<ul>
						<li><span id="looksee-scan-label-percent"><?php echo $percent; ?>%</span><span id="looksee-scan-label">Scanned <?php echo "$completed of $total"; ?></span></li>
						<li><div id="looksee-scan-bar" style="width: <?php echo $percent; ?>%;">&nbsp;</div></li>
						<li>
							<form id="form-looksee-core-scan" method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>">
								<?php wp_nonce_field('looksee_scan_abort','nonce_abort'); ?>
								<input type="hidden" name="action" value="looksee_scan_abort" />
								<input type="submit" value="Abort" />
							</form>
						</li>
					</ul>
				</div>
			</div>
			<!--end scan progress-->
<script type="text/javascript">

	//the actual scanning is done via AJAX so it can be split into chunks with progress updates
	function looksee_scan(){
		jQuery.post(ajaxurl, {action:'looksee_scan',looksee_nonce:'<?php echo wp_create_nonce("l00ks33n0nc3");?>'}, function(data){

			try {
				response = jQuery.parseJSON(data);
			}
			catch(e){
				jQuery("#looksee-scan-label").text('The server choked and returned bad data!');
				jQuery('input[type=submit]', jQuery('#form-looksee-core-scan')).remove();
				jQuery('#form-looksee-core-scan').append('<p>Click <a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>" title="Reset">here</a> to reset and try again.</p>');
				return;
			}

			//if the response was crap OR if we are done, reload the page
			if(response.total==response.completed)
			{
				jQuery("#looksee-scan-label-percent").text(response.percent + '%');
				jQuery("#looksee-scan-label").text('Finished scanning ' + response.completed + ' files!');
				jQuery("#looksee-scan-bar").css('width', response.percent + '%');
				jQuery('input[type=submit]', jQuery('#form-looksee-core-scan')).remove();
				jQuery('#form-looksee-core-scan').append('<p>Click <a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>" title="Results">here</a> to see the results.</p>');
				return;
			}

			//otherwise let's update the progress
			jQuery("#looksee-scan-label-percent").text(response.percent + '%');
			jQuery("#looksee-scan-label").text('Scanned ' + response.completed + ' of ' + response.total);
			jQuery("#looksee-scan-bar").css('width', response.percent + '%');

			looksee_scan();
		});
	}

	jQuery(document).ready(function(){ looksee_scan(); });

</script>
<?php
}//end scan progress
?>

			<!-- About Us -->
			<div class="postbox">
				<div class="inside">
					<a href="http://www.blobfolio.com/donate.html" title="Blobfolio, LLC" target="_blank"><img src="<?php echo esc_url(plugins_url('images/blobfolio.png', __FILE__)); ?>" class="logo" alt="Blobfolio logo"></a>

					<p>We hope you find this plugin useful.  If you do, you might be interested in our other plugins, which are also completely free (and useful).</p>
					<ul>
						<li><a href="http://wordpress.org/plugins/apocalypse-meow/" target="_blank" title="Apocalypse Meow">Apocalypse Meow</a>: a simple, light-weight collection of tools to help protect wp-admin, including password strength requirements and brute-force log-in prevention.</li>
						<li><a href="http://wordpress.org/plugins/sockem-spambots/" target="_blank" title="Sock'Em SPAMbots">Sock'Em SPAMbots</a>: a more seamless approach to deflecting the vast majority of SPAM comments.</li>
					</ul>
				</div>
			</div><!--.postbox-->

		</div><!--end sidebar-->

		<div id="post-body-content" class="has-sidebar">
			<div class="has-sidebar-content">

				<!--start scan history-->
				<div class="postbox">
<?php

//scan details
$scan_report = looksee_get_option('looksee_scan_report');

if(looksee_is_scanning())
	echo '<h3 class="hndle">Scan Results</h3><div class="inside"><p><img src="' . esc_url(plugins_url('images/loading1.gif', __FILE__)) . '" id="looksee-loading" /> A report will be generated once the scan is completed.</p>';
elseif($scan_report['ended'] AND count($scan_report['errors']))
	echo '<h3 class="hndle">Scan Results</h3><div class="inside"><p>' . implode('</p><p>', $scan_report['errors']) . '</p>';
elseif($scan_report['ended'] > 0)
{
	//let's get the date/time details
	$h = $m = 0;
	$s = round($scan_report['ended'] - $scan_report['started'], 5);
	$duration = array();
	//hours?
	if($s >= 60 * 60)
	{
		$h = floor($s/60/60);
		$s -= $h * 60 * 60;
		$duration[] = "$h hour" . ($h === 1 ? '' : 's');
	}
	//minutes?
	if($s >= 60)
	{
		$m = floor($s/60);
		$s -= $m * 60;
		$duration[] = "$m minute" . ($m === 1 ? '' : 's');
	}
	//seconds?
	if($s > 0)
		$duration[] = (count($duration) ? 'and ' : '') . "$s second" . ($s === 1 ? '' : 's');

	//now some file details...
	$total = $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");
	$altered = array();
	$core = array();
	$extra = array();
	$missing = array();
	$suspicious = array();
	$old = array();
	$skipped = array();
	$previous_custom = intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND LENGTH(`md5_expected`)")) > 0;
	//grab checksum mismatches
	$dbResult = $wpdb->get_results("SELECT `file`, `md5_expected`, `md5_found`, `wp` FROM `{$wpdb->prefix}looksee_files` WHERE NOT(`md5_expected`=`md5_found` OR (LENGTH(`md5_saved`) AND `md5_saved`=`md5_found`)) AND `skipped`=0 ORDER BY `file` ASC", ARRAY_A);
	if($wpdb->num_rows)
	{
		foreach($dbResult AS $Row)
		{
			if(!strlen($Row["md5_expected"]))
			{
				//ignore extra files if there is not anything previous to compare them with
				if($previous_custom)
					$extra[] = $Row['file'];
			}
			elseif(!strlen($Row["md5_found"]))
				$missing[] = $Row['file'];
			else
				$altered[] = $Row['file'];

			//we'll want to draw attention to files belonging to the WP core
			if(strlen($Row["wp"]))
				$core[] = $Row['file'];
		}
	}
	//look for files that aren't part of the core, but are lurking around in core places!
	$dbResult = $wpdb->get_results("SELECT `file` FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND LENGTH(`md5_found`) AND `skipped`=0 AND (`file` LIKE 'wp-admin/%' OR `file` LIKE 'wp-includes/%' OR `file` LIKE 'wp-content/uploads/%.php') ORDER BY `file` ASC", ARRAY_A);
	if($wpdb->num_rows)
	{
		$core_old = looksee_get_old_core_definitions();

		//first, let's take a
		foreach($dbResult AS $Row)
		{
			if(in_array($Row['file'], $core_old))
				$old[] = $Row['file'];
			else
				$suspicious[] = $Row['file'];
		}

	}
	//find skipped or ignored files
	$dbResult = $wpdb->get_results("SELECT `file` FROM `{$wpdb->prefix}looksee_files` WHERE `skipped`=1 ORDER BY `file` ASC", ARRAY_A);
	if($wpdb->num_rows)
	{
		foreach($dbResult AS $Row)
			$skipped[] = $Row['file'];
	}

	//explanations for the individual tests
	$info = array(
		'altered'=>'The following file(s) have been modified since the last Look-See scan was run.  This could be utterly innocuous (like if you\'ve updated a plugin), or it might indicate site exploitation.  To be sure, manually review the list.',
		'altered_core'=>'The following file(s) belonging to the WordPress core have been modified from their original state.  This may indicate your blog has been exploited, or it may be that your server modified the files automatically when they were uploaded (see the <a href="http://wordpress.org/extend/plugins/look-see-security-scanner/faq/" target="_blank">plugin FAQ</a> for more information about this annoyance).  Please review the list or, if in doubt, replace the file(s) with freshly downloaded copies from WordPress.',
		'extra'=>'The following file(s) have magically appeared since the last Look-See scan was run.  Please review the list to ensure everything is expected.',
		'missing'=>'The following file(s) have been removed since the last Look-See scan was run.  It is rare for a hacker to delete files, but have a look just to make sure.',
		'missing_core'=>'The follow core WordPress file(s) are missing and should be replaced with freshly downloaded copies, otherwise your site might not work correctly.',
		'suspicious'=>'The following unexpected file(s) should be reviewed and probably deleted.  This list includes any non-core files found in the wp-admin/ and wp-include/ folders, as well as any PHP scripts found lurking in the labyrinthine wp-content/uploads/ folder.  Such files are almost certainly either garbage from old WordPress installations or backdoors planted by hackers and can be safely removed.',
		'old'=>'The following files are no longer part of the WordPress core and can be safely deleted.  Go on!  A bit of spring cleaning every now and again will keep things nice and tidy!',
		'skipped'=>'The following file(s) were skipped due to scan settings (e.g. they were too large, etc.).'
	);

?>
			<h3 class="hndle">Scan Results: <?php echo date("M j Y", floor($scan_report['ended'])); ?></h3>
				<div class="inside">
					<p><b>Scanned <?php echo $total; ?> files in <?php echo implode(", ", $duration); ?>.</b></p>
					<ul id="looksee-scan-results">
						<?php
						foreach(array('altered','extra','missing','suspicious','old','skipped') AS $status)
						{
							echo '<li data-scan="' . $status . '" class="looksee-status ' . (count(${$status}) ? 'looksee-status-bad' : 'looksee-status-good') . '">';
							if($status === 'skipped')
								echo 'Skipped ' . count($skipped) . ' file' . (count($skipped) === 1 ? '' : 's');
							else
								echo 'Found ' . count(${$status}) . " $status file" . (count(${$status}) === 1 ? '' : 's');
							echo '</li>';
							if(count(${$status}))
							{
								$tmp = array_intersect(${$status}, $core);
								if(count($tmp))
								{
									echo '<li class="looksee-status-details looksee-status-details-' . $status . ' looksee-status-details-description">' . $info[$status . "_core"] . '</li>';
									foreach($tmp AS $f)
										echo '<li class="looksee-status-details looksee-status-details-' . $status . '">' . esc_html(looksee_straighten_windows(ABSPATH . $f)) . '</li>';
								}
								if(count($tmp) < count(${$status}))
								{
									echo '<li class="looksee-status-details looksee-status-details-' . $status . ' looksee-status-details-description">' . $info[$status] . '</li>';
									foreach(${$status} AS $f)
									{
										if(!in_array($f, $core))
											echo '<li class="looksee-status-details looksee-status-details-' . $status . '">' . esc_html(looksee_straighten_windows(ABSPATH . $f)) . '</li>';
									}
								}
							}
						}
						?>
					</ul>
<?php
}//end print results
else
	echo '<h3 class="hndle">Scan Results</h3><div class="inside"><p>There are no scan results to report.  Click the SCAN NOW button at right to begin!</p>';
?>
					</div>
				</div>
				<!--end scan history-->

			</div><!--end .has-sidebar-content-->
		</div><!--end .has-sidebar-->
	</div>
</div>