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
//scan in progress?
$is_scanning = intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=1")) > 0;



//--------------------------------------------------
//Check server/plugin support

$support_md5 = looksee_support_md5();
$support_version = looksee_support_version();

//is there a version file?
if(!$support_version)
	$errors[] = 'There is no file database for your version of WP (' . get_bloginfo('version') . ').  Double-check for available <a href="' . admin_url('update-core.php') . '" title="WordPress updates">software updates</a>, as applying them may well fix this problem.';

//can PHP generate MD5s?
if(!$support_md5)
	$errors[] = 'This server does not support MD5 checksum generation, which is required to verify the integrity of your files.';

//error output
if(count($errors))
{
	foreach($errors AS $e)
		echo '<div class="error fade"><p>' . $e . '</p></div>';

	//these are deal-breakers, so let's get outta here
	return;
}



//--------------------------------------------------
//Setup the scan!

if(getenv("REQUEST_METHOD") === "POST")
{
	//bad nonce, no scan
	if(!wp_verify_nonce($_POST['_wpnonce'],'looksee-core-scanner'))
		$errors[] = 'Sorry the form had expired.  Please try again.';
	//existing scan?
	elseif($is_scanning)
		$errors[] = 'A scan is already underway!';
	//let's set it up!
	else
	{
		//start the clock!
		update_option('looksee_scan_started', looksee_microtime());
		update_option('looksee_scan_finished', 0);


		//remove entries for custom files that were missing (as of last scan)
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND NOT(LENGTH(`md5_found`))");

		//update checksums for custom files (using found values from last scan)
		$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_expected`=`md5_found` WHERE NOT(LENGTH(`wp`))");

		//determine whether there are new files to scan
		$files_actual = looksee_readdir(ABSPATH);
		sort($files_actual);
		$files_db = array();
		$dbResult = mysql_query("SELECT `file` FROM `{$wpdb->prefix}looksee_files` ORDER BY `file` ASC");
		if(mysql_num_rows($dbResult))
		{
			while($Row = mysql_fetch_assoc($dbResult))
				$files_db[] = $Row["file"];
		}
		$files_new = array_diff($files_actual, $files_db);
		unset($files_actual);
		unset($files_db);
		if(count($files_new))
		{
			$inserts = array();
			foreach($files_new AS $f)
			{
				//add to the database in blocks of 250
				if(count($inserts) === 250)
				{
					$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`) VALUES ('" . implode("'),('", $inserts) . "')");
					$inserts = array();
				}
				$inserts[] = mysql_real_escape_string($f);
			}
			//add whatever's left to add
			$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`) VALUES ('" . implode("'),('", $inserts) . "')");
			unset($inserts);
		}
		unset($files_new);

		//queue up the files!
		$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_found`='', `queued`=1");

		echo '<div class="updated fade"><p>Let\'s have a look-see!</p></div>';

		//now we are scanning...
		$is_scanning = true;
	}
}



//--------------------------------------------------
?>
<style type="text/css">
	.looksee-scan-description {
		text-decoration: none;
		font-weight: bold;
	}
	.looksee-scan-description:hover {
		text-decoration: underline;
	}
	.form-table {
		clear: left!important;
	}
	#looksee-scan-bar{
		height: 15px;
		width: auto;
		padding: 0;
		margin: 0;
		border: 0;
		background-color: #464645;
		background-image: -ms-linear-gradient(bottom,#373737,#464646 5px);
		background-image: -moz-linear-gradient(bottom,#373737,#464646 5px);
		background-image: -o-linear-gradient(bottom,#373737,#464646 5px);
		background-image: -webkit-gradient(linear,left bottom,left top,from(#373737),to(#464646));
		background-image: -webkit-linear-gradient(bottom,#373737,#464646 5px);
		background-image: linear-gradient(bottom,#373737,#464646 5px);
		overflow: hidden;
	}
	#looksee-scan-label-percent {
		width: 50px;
		display: inline-block;
		height: 15px;
		line-height: 15px;
	}
	#looksee-scan-label {
		display: inline-block;
		width: auto;
		height: 15px;
		line-height: 15px;
	}
	#looksee-loading {
		width: 16px;
		height: 16px;
		float: left;
		margin-right: 10px;
		border: 0;
	}
	#looksee-scan-results li {
		line-height: 15px;
	}
	#looksee-scan-results li.looksee-status {
		padding-left: 20px;
		height: 15px;
		background: transparent url('<?php echo plugins_url('images/status-sprite.png', __FILE__); ?>') no-repeat scroll 0 0;
		font-weight: bold;
	}
	#looksee-scan-results li.looksee-status-bad {
		background-position: 0 -20px;
		cursor: pointer;
	}
	#looksee-scan-results li.looksee-status-details {
		display: none;
		padding-left: 40px;
	}
	#looksee-scan-results li.looksee-status-details-description {
		padding-left: 20px;
		color: #666;
		font-style: italic;
	}
</style>
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
	<div class="metabox-holder has-right-sidebar">

		<div class="inner-sidebar">

			<!--start available scans -->
			<div class="postbox">
<?php
//present the form to start a scan
if(!$is_scanning) {
?>
				<form id="form-looksee-core-scan" method="post" action="<?php echo admin_url('tools.php?page=looksee-security-scanner'); ?>">
				<?php wp_nonce_field('looksee-core-scanner'); ?>
				<h3 class="hndle">Run Scan Now</h3>
				<div class="inside">
					<ul>
						<li>
							<input type="submit" value="Scan Now" />
						</li>
					</ul>
				</div>
				</form>
<?php
}//end scan button
//otherwise if a scan is in progress, let's show the progress!
else {
	$total = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");
	$completed = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=0");
	$percent = round(100 * $completed / $total, 0);
?>
				<h3 class="hndle">Scan Progress</h3>
				<div class="inside">
					<ul>
						<li><span id="looksee-scan-label-percent"><?php echo $percent; ?>%</span><span id="looksee-scan-label">Scanned <?php echo "$completed of $total"; ?></span></li>
						<li><div id="looksee-scan-bar" style="width: <?php echo $percent; ?>%;">&nbsp;</div></li>
					</ul>
				</div>
<script type="text/javascript">

	//the actual scanning is done via AJAX so it can be split into chunks with progress updates
	function looksee_scan(){
		jQuery.post(ajaxurl, {action:'looksee_scan',looksee_nonce:'<?php echo wp_create_nonce("l00ks33n0nc3");?>'}, function(data){

			response = jQuery.parseJSON(data);

			//if the response was crap OR if we are done, reload the page
			if(response.total==undefined || response.completed==undefined || response.percent==undefined || response.total==response.completed)
				window.location.reload();

			//otherwise let's update the progress
			jQuery("#looksee-scan-label-percent").text(response.percent + '%');
			jQuery("#looksee-scan-label").text('Scanned ' + response.completed + ' of ' + response.total);
			jQuery("#looksee-scan-bar").css('width',response.percent + '%');

			looksee_scan();
		});
	}

	jQuery(document).ready(function(){ looksee_scan(); });

	function htmlspecialchars(string){ return jQuery('<span>').text(string).html(); }

</script>
<?php
}//end scan progress
?>
			</div>
			<!--end available scans-->

		</div><!--end sidebar-->

		<div id="post-body-content" class="has-sidebar">
			<div class="has-sidebar-content">

				<!--start scan history-->
				<div class="postbox">
<?php
if($is_scanning)
	echo '<h3 class="hndle">Scan Results</h3><div class="inside"><p><img src="' . plugins_url('images/loading1.gif', __FILE__) . '" id="looksee-loading" /> A report will be generated once the scan is completed.</p>';
elseif(get_option('looksee_scan_finished', 0) > 0)
{
	//let's get the date/time details
	$started = (double) get_option('looksee_scan_started', 0);
	$finished = (double) get_option('looksee_scan_finished', 0);
	$h = $m = 0;
	$s = round($finished - $started, 5);
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
	$previous_custom = intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND LENGTH(`md5_expected`)")) > 0;
	//grab checksum mismatches
	$dbResult = mysql_query("SELECT `file`, `md5_expected`, `md5_found`, `wp` FROM `{$wpdb->prefix}looksee_files` WHERE NOT(`md5_expected`=`md5_found`) ORDER BY `file` ASC");
	if(mysql_num_rows($dbResult))
	{
		while($Row = mysql_fetch_assoc($dbResult))
		{

			if(!strlen($Row["md5_expected"]))
			{
				//ignore extra files if there is not anything previous to compare them with
				if($previous_custom)
					$extra[] = $Row["file"];
			}
			elseif(!strlen($Row["md5_found"]))
				$missing[] = $Row["file"];
			else
				$altered[] = $Row["file"];

			//we'll want to draw attention to files belonging to the WP core
			if(strlen($Row["wp"]))
				$core[] = $Row["file"];
		}
	}
	//look for files that aren't part of the core, but are lurking around in core places!
	$dbResult = mysql_query("SELECT `file` FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND LENGTH(`md5_found`) AND (`file` LIKE 'wp-admin/%' OR `file` LIKE 'wp-includes/%' OR `file` LIKE 'wp-content/uploads/%.php') ORDER BY `file` ASC");
	if(mysql_num_rows($dbResult))
	{
		while($Row = mysql_fetch_assoc($dbResult))
			$suspicious[] = $Row["file"];
	}

	//explanations for the individual tests
	$info = array(
		'altered'=>'The following file(s) have been modified since the last Look-See scan was run.  This could be utterly innocuous (like if you\'ve updated a plugin), or it might indicate site exploitation.  To be sure, manually review the list.',
		'altered_core'=>'The following file(s) belonging to the WordPress core have been modified from their original state.  This may indicate your blog has been exploited, or it may be that your server modified the files automatically when they were uploaded (see the <a href="http://wordpress.org/extend/plugins/look-see-security-scanner/faq/" target="_blank">plugin FAQ</a> for more information about this annoyance).  Please review the list or, if in doubt, replace the file(s) with freshly downloaded copies from WordPress.',
		'extra'=>'The following file(s) have magically appeared since the last Look-See scan was run.  Please review the list to ensure everything is expected.',
		'missing'=>'The following file(s) have been removed since the last Look-See scan was run.  It is rare for a hacker to delete files, but have a look just to make sure.',
		'missing_core'=>'The follow core WordPress file(s) are missing and should be replaced with freshly downloaded copies, otherwise your site might not work correctly.',
		'suspicious'=>'The following unexpected file(s) should be reviewed and probably deleted. Non-core files appearing in wp-admin/ or wp-includes/ are almost certainly either garbage left over from previous versions of WordPress (which can be safely deleted) or scripts injected by hackers (which definitely should be deleted).  This scan also looks for PHP files in your wp-content/uploads folder, which unless you\'ve put them there yourself, are almost certainly backdoors left by hackers who have exploited your site.  Regardless, review these entries carefully.'
	);
?>
			<h3 class="hndle">Scan Results: <?php echo date("M j Y", floor($finished)); ?></h3>
				<div class="inside">
					<p><b>Scanned <?php echo $total; ?> files in <?php echo implode(", ", $duration); ?>.</b></p>
					<ul id="looksee-scan-results">
						<?php
						foreach(array('altered','extra','missing','suspicious') AS $status)
						{
							echo '<li data-scan="' . $status . '" class="looksee-status ' . (count(${$status}) ? 'looksee-status-bad' : 'looksee-status-good') . '">Found ' . count(${$status}) . " $status file" . (count(${$status}) === 1 ? '' : 's') . '</li>';
							if(count(${$status}))
							{
								$tmp = array_intersect(${$status}, $core);
								if(count($tmp))
								{
									echo '<li class="looksee-status-details looksee-status-details-' . $status . ' looksee-status-details-description">' . $info[$status . "_core"] . '</li>';
									foreach($tmp AS $f)
										echo '<li class="looksee-status-details looksee-status-details-' . $status . '">' . htmlspecialchars(looksee_straighten_windows(ABSPATH . $f)) . '</li>';
								}
								if(count($tmp) < count(${$status}))
								{
									echo '<li class="looksee-status-details looksee-status-details-' . $status . ' looksee-status-details-description">' . $info[$status] . '</li>';
									foreach(${$status} AS $f)
									{
										if(!in_array($f, $core))
											echo '<li class="looksee-status-details looksee-status-details-' . $status . '">' . htmlspecialchars(looksee_straighten_windows(ABSPATH . $f)) . '</li>';
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
				<!--end scan history

			</div><!--end .has-sidebar-content-->
		</div><!--end .has-sidebar-->

</div>

<script type="text/javascript">
	//toggle detailed display
	jQuery("#looksee-scan-results li.looksee-status-bad").click(function(){
		var obj = jQuery(".looksee-status-details-" + jQuery(this).attr('data-scan'));
		if(obj.css('display') == 'none')
			obj.css('display','block');
		else
			obj.css('display','none');
	});
</script>