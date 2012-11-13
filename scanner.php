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
//Check server/plugin support

$errors = array();
$support_md5 = true;
$support_version = true;
$results = false;

//is there a version file?
if(!file_exists(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5'))
{
	$errors[] = 'There is no file database for your version of WP (' . get_bloginfo('version') . '), meaning several of the security scans are unavailable.  Double-check for available <a href="' . admin_url('update-core.php') . '" title="WordPress updates">software updates</a>, as applying them may well fix this problem.';
	$support_version = false;
}
else
{
	//make sure we can read the file database
	$tmp = explode("\n", @file_get_contents(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5'));
	$checksums = array();
	foreach($tmp AS $line)
	{
		$line = trim($line);
		if(strlen($line))
		{
			list($md5, $file) = explode("  ", $line);
			//lightly verify that MD5 and file look plausible before adding
			if(preg_match('/^[a-z0-9]{32}$/', $md5) && strlen(trim($file)))
				$checksums[trim($file)] = $md5;
		}
	}
	ksort($checksums);
	if(!count($checksums))
	{
		$errors[] = 'The file database for your version of WP (' . get_bloginfo('version') . ') could not be loaded, either due to restrictive server configurations or file corruption.  Several scans are unavailable as a result.';
		$support_version = false;
	}
}

//can PHP generate MD5s?
if(!function_exists('md5_file') || false === md5_file(__FILE__))
{
	$errors[] = 'This server does not support MD5 checksum generation, so certain security scans are unavailable.';
	$support_md5 = false;
}



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
		//Verify WordPress core files

		if(intval($_POST["scan_wpcore"]) === 1 && $support_version && $support_md5)
		{
			//keep track of missing files
			$missing = array();
			//keep track of altered files
			$altered = array();

			$results[] = '--------------------------------------------------';
			$results[] = 'Verifying WordPress core files...';

			//cycle through all standard core files
			foreach($checksums AS $f=>$c)
			{
				if(!file_exists(ABSPATH . $f))
					$missing[] = $f;
				elseif($c !== md5_file(ABSPATH . $f))
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
				$results[] = '--------------------------------------------------';
				$results[] = "Scanning $where/ for unexpected files...";
				//extra files?
				$extra = array_diff(looksee_readdir(ABSPATH . $where), array_keys($checksums));

				//compile results of extra files check
				$results[] = "\t" . count($extra) . ' unexpected file' . (count($extra) === 1 ? ' was' : 's were') . ' found.';
				if(count($extra))
				{
					$results[] = "\t**NOTE** User content doesn't belong in $where/, so unexpected files are generally going to be malicious or leftovers from old versions of WordPress, either of which can be safely deleted.";
					foreach($extra AS $f)
						$results[] = "\t\t[???] $f";
				}

				$results[] = "";
				unset($extra);
			}
		}

		//--------------------------------------------------
		//Scripts in wp-content/uploads/

		if(intval($_POST["scan_wpuploads"]) === 1)
		{
			$results[] = '--------------------------------------------------';
			$results[] = "Scanning wp-content/uploads/ for scripts...";

			$scripts = looksee_readdir(ABSPATH . 'wp-content/uploads', array('php','php5','php4','php3','xml','html','js','asp','vb','rb'));

			//compile results of script files check
			$results[] = "\t" . count($scripts) . ' unexpected file' . (count($scripts) === 1 ? ' was' : 's were') . ' found in your uploads directory.';
			if(count($scripts))
			{
				$results[] = "\t**NOTE** It is unusual to intentionally upload non-media files to WordPress, so regard these files with suspicion.";
				foreach($scripts AS $f)
					$results[] = "\t\t[???] $f";
			}

			$results[] = "";
			unset($scripts);
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
					<label for="scan_wpcore">Verify WordPress core files</label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpcore" id="scan_wpcore" value="1" checked=checked /> We know exactly what a clean installation of WordPress is supposed to contain.  This scan searches the file database corresponding to your version of WordPress and reports any files that are missing or altered.  Missing files are indicative of a screwy (e.g. incomplete) installation, while altered files might indicate malware infection.
				</td>
			</tr>
			<?php } ?>
			<?php if($support_version) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpadmin">Extra files in wp-admin/</label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpadmin" id="scan_wpadmin" value="1" checked=checked /> Legitimate user content shouldn't really end up in the wp-admin/ folder.  This scan searches for files which are not part of a clean installation.
				</td>
			</tr>
			<?php } ?>
			<?php if($support_version) { ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpincludes">Extra files in wp-includes/</label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpincludes" id="scan_wpincludes" value="1" checked=checked /> As with the above, wp-includes/ is no place for legitimate user content.  This scan searches for files which are not part of a clean installation.
				</td>
			</tr>
			<?php } ?>
			<tr valign="top">
				<th scope="row">
					<label for="scan_wpuploads">Scripts in wp-content/uploads/</label>
				</th>
				<td>
					<input type="checkbox" name="scan_wpuploads" id="scan_wpuploads" value="1" checked=checked /> The wp-content/uploads folder can quickly become labyrinthine and so is an excellent place for hackers to hide backdoors.  This scan searches the uploads folder for executable scripts.
				</td>
			</tr>
			<tr valign="top">
				<th scope="row">&nbsp;</th>
				<td>
					<input type="submit" value="Scan Now" />
					<p class="description">If the server hosting your web site is slow, it might be best to run these tests one at a time.</p>
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