<?php
//----------------------------------------------------------------------
//  Look-See Configuration Analysis
//----------------------------------------------------------------------
//Check the overall state of things for potential flags
//
// @since 3.5-4



//--------------------------------------------------
//Check permissions

//let's make sure this page is being accessed through WP
if (!function_exists('current_user_can'))
	die('Sorry');
//and let's make sure the current user has sufficient permissions
elseif(!current_user_can('manage_options'))
	wp_die(__('You do not have sufficient permissions to access this page.'));



//-------------------------------------------------
//SCAN!
$results = null;
if(getenv('REQUEST_METHOD') === 'POST')
{
	//store the results in an array so we can access it later
	$results = array('plugins'=>array(), 'themes'=>array());

	//first, let's check the plugins
	$plugins = get_plugins();

	//check the plugins
	foreach($plugins AS $k=>$v)
	{
		//we need the directory name
		$plugin_dir = substr($k, 0, strpos($k, '/'));
		$plugin_name = $v['Name'];

		//maybe we can pull this from cache
		$transient_key = 'looksee_p_' . md5($v['Name']);
		if(false !== ($cache = get_transient($transient_key)))
		{
			$results['plugins'][$plugin_name] = $cache;
			continue;
		}

		$results['plugins'][$plugin_name] = array('success'=>0, 'vulnerabilities'=>array());

		//now send it to WPScan
		try {
			$raw = wp_remote_get("https://wpvulndb.com/api/v1/plugins/$plugin_dir");
			if(!is_wp_error($raw) && is_array($raw))
			{
				$results['plugins'][$plugin_name]['success'] = 1;

				//see if there was anything worth mentioning
				$raw['body'] = trim($raw['body']);
				if(!strlen($raw['body']))
					continue;

				//maybe json is bad
				$json = json_decode($raw['body']);

				if(!is_array($json->plugin->vulnerabilities) || !count($json->plugin->vulnerabilities))
				{
					//save results to cache so we can pull this more quickly next time
					set_transient($transient_key, $results['plugins'][$plugin_name], 3600);
					continue;
				}

				//add any that apply
				foreach($json->plugin->vulnerabilities AS $v)
					$results['plugins'][$plugin_name]['vulnerabilities'][] = array('title'=>$v->title, 'url'=>$v->url, 'fixed'=>$v->fixed_in);

				//save results to cache so we can pull this more quickly next time
				set_transient($transient_key, $results['plugins'][$plugin_name], 3600);
			}//good response
		} catch(Exception $e){}
	}//each plugin

	//now check the themes
	$themes = get_themes();
	foreach($themes AS $k=>$v)
	{
		$theme_name = $k;
		$theme_dir = $v->template;

		$transient_key = 'looksee_t_' . md5($v['Name']);
		if(false !== ($cache = get_transient($transient_key)))
		{
			$results['themes'][$theme_name] = $cache;
			continue;
		}

		$results['themes'][$theme_name] = array('success'=>0, 'vulnerabilities'=>array());

		//now send it to WPScan
		try {
			$raw = wp_remote_get("https://wpvulndb.com/api/v1/themes/$theme_dir");
			if(!is_wp_error($raw) && is_array($raw))
			{
				$results['themes'][$theme_name]['success'] = 1;

				//see if there was anything worth mentioning
				$raw['body'] = trim($raw['body']);
				if(!strlen($raw['body']))
					continue;

				//maybe json is bad
				$json = json_decode($raw['body']);

				if(!is_array($json->theme->vulnerabilities) || !count($json->theme->vulnerabilities))
				{
					//save results to cache so we can pull this more quickly next time
					set_transient($transient_key, $results['themes'][$theme_name], 3600);
					continue;
				}

				//add any that apply
				foreach($json->theme->vulnerabilities AS $v)
					$results['themes'][$theme_name]['vulnerabilities'][] = array('title'=>$v->title, 'url'=>$v->url, 'fixed'=>$v->fixed_in);

				//save results to cache so we can pull this more quickly next time
				set_transient($transient_key, $results['themes'][$theme_name], 3600);
			}//good response
		} catch(Exception $e){}
	}

	//and sort our data
	ksort($results['plugins']);
	ksort($results['themes']);

}//end post



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
		<a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-scanner')); ?>" class="nav-tab" title="Scan files">File system</a>
		<a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-analysis')); ?>" class="nav-tab" title="Analyze configurations">Configuration analysis</a>
		<a href="<?php echo esc_url(admin_url('tools.php?page=looksee-security-vulnerabilities')); ?>" class="nav-tab nav-tab-active" title="Analyze plugins and themes">Plugins/Themes</a>
	</h3>

	<div class="metabox-holder has-right-sidebar">

		<div id="post-body-content" class="has-sidebar">
			<div class="has-sidebar-content">

				<!--start scan history-->
				<div class="postbox">
					<h3 class="hndle">Plugin and Theme Vulnerabilities</h3>
					<div class="inside">

						<?php if(is_null($results)){ ?>
						<!-- basic intro -->
						<p>Look-See will check your themes and plugins against the <a href="https://wpvulndb.com/" title="WPScan Vulnerability Database" target="_blank">WPScan Vulnerability Database</a> and let you know what it finds.</p>
						<p>Depending on the number of themes and plugins uploaded to your site, this might take a little time.  Results are temporarily cached, so if the scan times out, try "reloading" and it might get you there eventually.</p>
						<?php } ?>

						<?php if(!is_null($results)){ ?>

						<p>Below is a listing of <em>potential</em> vulnerabilities that have existed (and might still exist) in the plugins and themes uploaded to your site.  Many of these issues will already have been fixed by the authors (just make sure you are up-to-date).  Links to external sites with additional details are provided whenever possible.</p>

						<!-- results -->
						<ul id="looksee-scan-results">
							<?php
							foreach($results AS $type=>$r)
							{
								echo '<li><h4>' . ucwords($type) . '</h4></li>';
								foreach($r AS $k=>$v)
								{
									$hash = md5($k);
									echo '<li data-scan="' . $hash . '" class="looksee-status looksee-status-' . ($v['success'] === 1 && !count($v['vulnerabilities']) ? 'good' : 'bad') . '">' . esc_html($k) . '</li>';

									$issues = array();

									if($v['success'] !== 1)
										$issues[] = 'We could not query the WPScan database for this item.';

									if(count($v['vulnerabilities']))
									{
										foreach($v['vulnerabilities'] AS $vulnerability)
										{
											$tmp = array();
											//all vulnerabilities have a title
											$tmp[] = esc_html($vulnerability['title']);

											//some might have URLs
											if(count($vulnerability['url']))
											{
												foreach($vulnerability['url'] AS $u)
													$tmp[] = 'See: <a href="' . esc_url($u) . '" target="_blank" title="More Information">' . esc_html($u) . '</a>';
											}

											//some might be fixed
											if(strlen($v['fixed']))
												$tmp[] = 'The issue is reported as FIXED as of ' . esc_html($v['fixed']) . '.';

											$issues[] = implode('<br>', $tmp);
										}
									}

									//print issues, if any
									if(count($issues))
									{
										foreach($issues AS $i)
											echo '<li class="looksee-status-details looksee-status-details-' . $hash . '">' . $i . '</li>';
									}//end issues
								}//each item
							}//each plugin/theme
							?>
						</ul>
						<?php }//end results ?>

						<form method="post" action="<?php echo esc_url(admin_url('tools.php?page=looksee-security-vulnerabilities')); ?>">
							<input type="submit" class="button" value="<?php echo (is_null($results) ? 'Scan' : 'Rescan'); ?>" />
						</form>
					</div>
				</div>

			</div>
		</div>
	</div>

</div>