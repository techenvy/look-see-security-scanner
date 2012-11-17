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
//whether or not there are results to display
$results = false;



//--------------------------------------------------
//Check server/plugin support

$support_md5 = looksee_support_md5();
$support_version = looksee_support_version();
$support_custom = looksee_support_custom();
$support_crc32 = looksee_support_crc32();

//is there a version file?
if(!$support_version)
	$errors[] = 'There is no file database for your version of WP (' . get_bloginfo('version') . '), meaning several of the security scans are unavailable.  Double-check for available <a href="' . admin_url('update-core.php') . '" title="WordPress updates">software updates</a>, as applying them may well fix this problem.';

//can PHP generate MD5s?
if(!$support_md5)
	$errors[] = 'This server does not support MD5 checksum generation, so certain security scans are unavailable.';

//can PHP write the custom.crc32 file?  we'll assume it can if the file exists.
//if that assumption is wrong, we'll find out later and produce an error.
if(!$support_custom)
	$errors[] = 'The custom CRC32 checksum file (' . CRC32_CUSTOM_FILE . ') is not writeable, so the custom scan has been disabled.  See the <a href="http://wordpress.org/extend/plugins/look-see-security-scanner/faq/" title="FAQ" target="_blank">FAQ</a> for help.';

//can PHP generate CRC32 hashes?
if(!$support_crc32)
	$errors[] = 'The server does not support CRC32 checksum generation, so the custom scan is unavailable.';




//--------------------------------------------------
//Scan!

if(getenv("REQUEST_METHOD") === "POST")
{
	//bad nonce, no scan
	if(!wp_verify_nonce($_POST['_wpnonce'],'looksee-core-scanner'))
		$errors[] = 'Sorry the form had expired.  Please try again.';
	else
	{
		$results = array();

		//--------------------------------------------------
		//Load the core checksums?

		if(intval($_POST["scan_wpcore"]) === 1 || intval($_POST["scan_wpadmin"]) === 1 || intval($_POST["scan_wpincludes"]) === 1 || intval($_POST["scan_custom"]) === 1)
		{
			$md5_core = looksee_core_checksums();
			if(!count($md5_core))
			{
				$errors[] = 'The file database for your version of WP (' . get_bloginfo('version') . ') could not be loaded, either due to restrictive server configurations or file corruption.  Several scans are unavailable as a result.';
				$support_version = false;
			}
		}

		//--------------------------------------------------
		//Load the custom checksums?

		if(intval($_POST["scan_custom"]) === 1)
			$crc32_custom = looksee_custom_checksums();

		//--------------------------------------------------
		//Verify WordPress core files

		if(intval($_POST["scan_wpcore"]) === 1 && $support_version && $support_md5)
		{
			looksee_clock_start();
			//keep track of missing files
			$missing = array();
			//keep track of altered files
			$altered = array();

			$results[] = '--------------------------------------------------';
			$results[] = 'Verifying WordPress core files...';

			//cycle through all standard core files
			foreach($md5_core AS $f=>$c)
			{
				if(!file_exists(looksee_straighten_windows(ABSPATH . $f)))
					$missing[] = $f;
				elseif($c !== md5_file(looksee_straighten_windows(ABSPATH . $f)))
					$altered[] = $f;
			}

			//compile results of missing files check
			$results[] = "\t" . count($missing) . ' file' . (count($missing) === 1 ? ' was' : 's were') . ' missing.';
			if(count($missing))
			{
				//disclaimer
				$results[] = "\t**NOTE** Missing files generally indicate WordPress was incompletely installed.  You can fix these errors by re-installing WordPress.";
				foreach($missing AS $f)
					$results[] = "\t\t[missing] $f";
			}

			//compile results of altered files check
			$results[] = "\t" . count($altered) . ' file' . (count($altered) === 1 ? ' has' : 's have') . ' been altered from their original state.';
			if(count($altered))
			{
				//disclaimer
				$results[] = "\t**NOTE** Altered files should be manually reviewed to ensure they do not contain code injected by a hacker.  If you are unsure, simply override them with a fresh copy downloaded from WordPress.";
				$results[] = "\t**NOTE** To keep things interesting, some servers will automatically convert the line ending format or file encoding of text documents when uploaded.  These changes are generally innocuous and can be ignored.";
				foreach($altered AS $f)
					$results[] = "\t\t[altered] $f";
			}

			//update last-run timestamp
			update_option('looksee_last_scan_wpcore', current_time('timestamp'));

			$results[] = "\tScanned " . count($md5_core) . " files in " . looksee_clock_finish() . " seconds.";
			$results[] = "";
			unset($missing);
			unset($altered);
		}

		//--------------------------------------------------
		//Extra files in wp-admin/ and/or wp-includes/

		foreach(array('wp-admin','wp-includes') AS $where)
		{
			if(intval($_POST["scan_" . preg_replace('/[^a-z]/i', '', $where)]) === 1 && $support_version)
			{
				looksee_clock_start();
				$results[] = '--------------------------------------------------';
				$results[] = "Scanning $where/ for unexpected files...";
				//extra files?
				$found = looksee_readdir(looksee_straighten_windows(ABSPATH . $where));
				$extra = array_diff($found, array_keys($md5_core));

				//compile results of extra files check
				$results[] = "\t" . count($extra) . ' unexpected file' . (count($extra) === 1 ? ' was' : 's were') . ' found.';
				if(count($extra))
				{
					$results[] = "\t**NOTE** User content doesn't belong in $where/, so unexpected files are generally going to be malicious or leftovers from old versions of WordPress, either of which can be safely deleted.";
					foreach($extra AS $f)
						$results[] = "\t\t[???] $f";
				}

				//update last-run timestamp
				update_option('looksee_last_scan_' . preg_replace('/[^a-z]/i', '', $where), current_time('timestamp'));

				$results[] = "\tFinished in " . looksee_clock_finish() . " seconds.";
				$results[] = "";
				unset($extra);
				unset($found);
			}
		}

		//--------------------------------------------------
		//Scripts in wp-content/uploads/

		if(intval($_POST["scan_wpuploads"]) === 1)
		{
			looksee_clock_start();
			$results[] = '--------------------------------------------------';
			$results[] = "Scanning wp-content/uploads/ for scripts...";

			$scripts = looksee_readdir(looksee_straighten_windows(ABSPATH . 'wp-content/uploads'), array('php','php5','php4','php3','xml','html','js','asp','vb','rb'));

			//compile results of script files check
			$results[] = "\t" . count($scripts) . ' unexpected file' . (count($scripts) === 1 ? ' was' : 's were') . ' found in your uploads directory.';
			if(count($scripts))
			{
				$results[] = "\t**NOTE** It is unusual to intentionally upload non-media files to WordPress, so regard these files with suspicion.";
				foreach($scripts AS $f)
					$results[] = "\t\t[???] $f";
			}

			//update last-run timestamp
			update_option('looksee_last_scan_wpuploads', current_time('timestamp'));

			$results[] = "\tFinished in " . looksee_clock_finish() . " seconds.";
			$results[] = "";
			unset($scripts);
		}

		//--------------------------------------------------
		//Custom file changes

		if(intval($_POST['scan_custom']) === 1 && $support_version && $support_crc32 && $support_custom)
		{
			looksee_clock_start();
			$results[] = '--------------------------------------------------';
			$results[] = "Scanning custom files for changes";

			//all files not part of WP core
			$custom_files = array_diff(looksee_readdir(looksee_straighten_windows(ABSPATH)), array_keys($md5_core), array(looksee_straighten_windows(str_replace(ABSPATH,'',CRC32_CUSTOM_FILE))));
			sort($custom_files);
			//ultimately this will produce the new custom.md5
			$crc32_custom_new = array();
			//keep track of new files
			$extra = array_diff($custom_files, array_keys($crc32_custom));
			//keep track of altered files
			$altered = array();
			//keep track of missing files
			$missing = array_diff(array_keys($crc32_custom), $custom_files);

			//cycle through the current list of files and see what's changed
			foreach($custom_files AS $f)
			{
				$crc32_custom_new[$f] = hash_file('crc32', looksee_straighten_windows(ABSPATH . $f));
				if(array_key_exists($f, $crc32_custom) && $crc32_custom_new[$f] !== $crc32_custom[$f])
					$altered[] = $f;
			}

			//compile results of extra files check
			$results[] = "\t" . count($extra) . ' new file' . (count($extra) === 1 ? ' was' : 's were') . ' found.';
			if(!count($crc32_custom))
				$results[] = "\t**NOTE** The custom file database was empty so no comparisons can be made, however the results will be used for comparison next time you run the scan.";
			//only list new files if there was no previous scan
			elseif(count($extra))
			{
				foreach($extra AS $f)
					$results[] = "\t\t[new] $f";
			}

			//compile results for altered and missing files
			foreach(array('altered','missing') AS $status)
			{
				$results[] = "\t" . count(${$status}) . " $status file" . (count(${$status}) === 1 ? ' was' : 's were') . ' found.';
				if(count(${$status}))
				{
					foreach(${$status} AS $f)
						$results[] = "\t\t[$status] $f";
				}
			}

			//save results
			if(false !== ($handle = @fopen(CRC32_CUSTOM_FILE, "wb")))
			{
				foreach($crc32_custom_new AS $f=>$c)
				{
					$line = "$c  $f\n";
					@fwrite($handle, $line, strlen($line));
				}
				@fclose($handle);
			}
			else
				$errors[] = 'The custom CRC32 checksum file (' . CRC32_CUSTOM_FILE . ') is not writeable, so the custom scan has been disabled.  See the <a href="http://wordpress.org/extend/plugins/look-see-security-scanner/faq/" title="FAQ" target="_blank">FAQ</a> for help.';

			//update last-run timestamp
			update_option('looksee_last_scan_custom', current_time('timestamp'));

			$results[] = "\tScanned " . count($custom_files) . " files in " . looksee_clock_finish() . " seconds.";
			$results[] = "";
			unset($custom_files);
			unset($extra);
			unset($altered);
			unset($missing);
			unset($crc32_custom_new);
		}

	}
}



//--------------------------------------------------
//Error output?

if(count($errors))
{
	foreach($errors AS $e)
		echo '<div class="error fade"><p>' . $e . '</p></div>';
}



?>
<div class="wrap">

	<h2>Look-See Security Scanner</h2>

	<form id="form-looksee-core-scan" method="post" action="<?php echo admin_url('tools.php?page=looksee-security-scanner'); ?>">
	<?php wp_nonce_field('looksee-core-scanner'); ?>

	<h3>Scan(s) to Run</h3>
	<table class="form-table">
		<tbody>
			<?php if($support_version && $support_md5) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpcore">Verify WordPress core files<?php
					$lastrun = (int) get_option('looksee_last_scan_wpcore', 0);
					if($lastrun > 0)
						echo  '<br><span class="description">last run ' . date("Y-m-d H:i:s", $lastrun) . '</span>';
					?></label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpcore" id="scan_wpcore" value="1" checked=checked /> We know exactly what a clean installation of WordPress is supposed to contain.  This scan searches the file database corresponding to your version of WordPress and reports any files that are missing or altered.  Missing files are indicative of a screwy (e.g. incomplete) installation, while altered files might indicate malware infection.
				</td>
			</tr>
			<?php } ?>
			<?php if($support_version) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpadmin">Extra files in wp-admin/<?php
					$lastrun = (int) get_option('looksee_last_scan_wpadmin', 0);
					if($lastrun > 0)
						echo  '<br><span class="description">last run ' . date("Y-m-d H:i:s", $lastrun) . '</span>';
					?></label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpadmin" id="scan_wpadmin" value="1" checked=checked /> Legitimate user content shouldn't really end up in the wp-admin/ folder.  This scan searches for files which are not part of a clean installation.
				</td>
			</tr>
			<?php } ?>
			<?php if($support_version) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpincludes">Extra files in wp-includes/<?php
					$lastrun = (int) get_option('looksee_last_scan_wpincludes', 0);
					if($lastrun > 0)
						echo  '<br><span class="description">last run ' . date("Y-m-d H:i:s", $lastrun) . '</span>';
					?></label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpincludes" id="scan_wpincludes" value="1" checked=checked /> As with the above, wp-includes/ is no place for legitimate user content.  This scan searches for files which are not part of a clean installation.
				</td>
			</tr>
			<?php } ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpuploads">Scripts in wp-content/uploads/<?php
					$lastrun = (int) get_option('looksee_last_scan_wpuploads', 0);
					if($lastrun > 0)
						echo  '<br><span class="description">last run ' . date("Y-m-d H:i:s", $lastrun) . '</span>';
					?></label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpuploads" id="scan_wpuploads" value="1" checked=checked /> The wp-content/uploads folder can quickly become labyrinthine and so is an excellent place for hackers to hide backdoors.  This scan searches the uploads folder for executable scripts.
				</td>
			</tr>
			<?php if($support_version && $support_md5 && $support_custom) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_custom">Custom file changes<?php
					$lastrun = (int) get_option('looksee_last_scan_custom', 0);
					if($lastrun > 0)
						echo  '<br><span class="description">last run ' . date("Y-m-d H:i:s", $lastrun) . '</span>';
					?></label>
				</th>
				<td>
					<input type="checkbox" name="scan_custom" id="scan_custom" value="1" /> This scan compares all non-core files against what things looked like the last time it was run, reporting any new, missing, or altered files.<br>
					<span class="description">NOTE: the custom file database is reset whenever this plugin is updated, so it is a good idea to run this scan prior to updating to ensure no changes go unnoticed.</span>
				</td>
			</tr>
			<?php } ?>
			<tr valign="top">
				<th scope="row">&nbsp;</th>
				<td>
					<input type="submit" value="Scan Now" />
					<p class="description">If the server hosting your web site is slow or if your blog is gratuitously large, it might be best to run these tests one at a time.</p>
				</td>
			</tr>
		</tbody>
	</table>
	</form>

<?php
//if there are no results, we can quickly exit
if(false === $results)
{
	echo '</div>';
	exit;
}
?>
	<h3>Results</h3>
	<table class="form-table">
		<tbody>
			<tr valign="top" id="tr-results" style="">
				<td>
					<textarea style="width: 100%; height: 400px;"><?php echo str_replace(array('<','>'), array('&lt;','&gt;'), implode("\n", $results)); ?></textarea>
				</td>
			</tr>
		</tbody>
	</table>


</div>