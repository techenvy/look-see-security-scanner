<?php
/*
Plugin Name: Look-See Security Scanner
Plugin URI: http://wordpress.org/extend/plugins/look-see-security-scanner/
Description: Verify the integrity of a WP installation by scanning for unexpected or modified files.
Version: 13.12
Author: Blobfolio, LLC
Author URI: http://www.blobfolio.com/
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

	Copyright © 2013  Blobfolio, LLC  (email: hello@blobfolio.com)

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/



//----------------------------------------------------------------------
//  Constants, globals, and variable handling
//----------------------------------------------------------------------
//the database version
define('LOOKSEE_DB', '1.0.5');
//the number of files to scan in a single pass
define('LOOKSEE_SCAN_INTERVAL', 250);
//the plugin version
define('LOOKSEE_VERSION', '13.12');

//--------------------------------------------------
//a get_option wrapper that deals with defaults and
//bad data
//
// @since 3.5-3
//
// @param $option option_name
// @return option_value or false
function looksee_get_option($option){

	switch($option)
	{
		//ignore files larger than X
		case 'looksee_max_size':
			$tmp = (int) get_option('looksee_max_size', 10);
			if($tmp < 0)
			{
				$tmp = 10;
				update_option('looksee_max_size', 10);
			}
			return $tmp;
		//details about a scan's progress
		case 'looksee_scan_report':
			return get_option('looksee_scan_report', array('started'=>0,'ended'=>0,'errors'=>array(),'total'=>0,'scanned'=>0,'background'=>false));
		//ignore cache files
		case 'looksee_skip_cache':
			return (bool) get_option('looksee_skip_cache', 1);
	}

	return get_option($option, false);
}
//---------------------------------------------------------------------- end variables



//----------------------------------------------------------------------
//  Database set up
//----------------------------------------------------------------------
//functions relating to the look-see database additions

//--------------------------------------------------
//Create/update tables for scans and anomalies
//
// @since 3.4.2-6
//
// @param n/a
// @return true
function looksee_SQL(){
	global $wpdb;

	//dbdelta won't correctly upgrade to the table layout for 1.0.5
	//so if an old table exists, let's kill it!
	if(get_option('looksee_db_version','0.0.0') < '1.0.5' && get_option('looksee_db_version','0.0.0') !== '0.0.0')
		$wpdb->query("DROP TABLE IF EXISTS `{$wpdb->prefix}looksee_files`");

	//the files to scan go here
	// `id` numeric primary key
	// `file` the relative file path
	// `wp` the wordpress version if a core file, otherwise ''
	// `md5_expected` the expected checksum
	// `md5_found` the discovered checksum
	// `md5_saved` an alternate checksum deemed by the user to be A-OK
	// `queued` is it scheduled to be scanned? 1/0
	// `skipped` was this file check skipped?
	$sql = "CREATE TABLE {$wpdb->prefix}looksee_files (
  id bigint(15) NOT NULL AUTO_INCREMENT,
  file varbinary(300) NOT NULL,
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
);";

	require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
	dbDelta($sql);

	update_option("looksee_db_version", LOOKSEE_DB);

	return true;
}
register_activation_hook(__FILE__,'looksee_SQL');

//--------------------------------------------------
//Check if a database update is required
//
// @since 3.4.2-6
//
// @param n/a
// @return true
function looksee_db_update(){
	//update db structure
	if(get_option('looksee_db_version', '0.0.0') !== LOOKSEE_DB)
		looksee_SQL();

	return true;
}
add_action('plugins_loaded', 'looksee_db_update');

//--------------------------------------------------
//Force deactivation if multi-site is enabled
//
// @since 3.5-6
//
// @param n/a
// @return true
function looksee_deactivate_multisite(){
	if(is_multisite())
	{
		require_once(ABSPATH . '/wp-admin/includes/plugin.php');
		deactivate_plugins(__FILE__);
		echo '<div class="error fade"><p>Look-See Security Scanner is not compatible with WPMU and has been disabled. Sorry!</p></div>';
	}

	return true;
}
add_action('admin_init', 'looksee_deactivate_multisite');

//---------------------------------------------------------------------- end db



//----------------------------------------------------------------------
//  Look-See WP backend
//----------------------------------------------------------------------
//functions relating to the wp-admin pages

//--------------------------------------------------
//Create a Tools->Look-See Security Scanner menu item
//
// @since 3.4.2
//
// @param n/a
// @return true
function looksee_security_scanner_menu(){
	//create the file scanner page
	$page = add_submenu_page('tools.php', 'Look-See Security Scanner', 'Look-See Security Scanner', 'manage_options', 'looksee-security-scanner', 'looksee_security_scanner');
	//attach stylesheet to it
	add_action('admin_print_styles-' . $page, 'looksee_enqueue_css');
	//attach javascript to it
	add_action('admin_print_scripts-' . $page, 'looksee_enqueue_js');

	//create the configuration analysis page
	$page = add_submenu_page(null, 'Look-See Security Scanner: Configuration Analysis', 'Look-See Security Scanner: Configuration Analysis', 'manage_options', 'looksee-security-analysis', 'looksee_security_analysis');
	//attach stylesheet to it
	add_action('admin_print_styles-' . $page, 'looksee_enqueue_css');
	//attach javascript to it
	add_action('admin_print_scripts-' . $page, 'looksee_enqueue_js');

	return true;
}
add_action('admin_menu', 'looksee_security_scanner_menu');

//--------------------------------------------------
//The Tools->Look-See Core Scanner page
//
// this is an external file (scanner.php)
//
// @since 3.4.2
//
// @param n/a
// @return true
function looksee_security_scanner(){
	require_once(dirname(__FILE__) . '/scanner.php');
	return true;
}

//--------------------------------------------------
//The Look-See Configurations Analysis page
//
// this is an external file (analysis.php)
//
// @since 3.5-4
//
// @param n/a
// @return true
function looksee_security_analysis(){
	require_once(dirname(__FILE__) . '/analysis.php');
	return true;
}

//--------------------------------------------------
//Register stylesheet for admin pages
//
// @since 3.5-4
//
// @param n/a
// @return true
function looksee_register_css(){
	wp_register_style('looksee_css', plugins_url('looksee.css', __FILE__));
	return true;
}
add_action('admin_init','looksee_register_css');

//--------------------------------------------------
//Enqueue stylesheet for admin pages
//
// @since 3.5-4
//
// @param n/a
// @return true
function looksee_enqueue_css(){
	wp_enqueue_style('looksee_css');
	return true;
}

//--------------------------------------------------
//Register javascript for admin pages
//
// @since 3.5-4
//
// @param n/a
// @return true
function looksee_register_js(){
	wp_register_script('looksee_js', plugins_url('looksee.js', __FILE__),  array('jquery'), LOOKSEE_VERSION);
	return true;
}
add_action('admin_init','looksee_register_js');

//--------------------------------------------------
//Enqueue javascript for admin pages
//
// @since 3.5-4
//
// @param n/a
// @return true
function looksee_enqueue_js(){
	wp_enqueue_script('looksee_js');
	return true;
}

//----------------------------------------------------------------------  end WP backend stuff



//----------------------------------------------------------------------
//  Scan-related functions
//----------------------------------------------------------------------

//--------------------------------------------------
//Is a scan currently underway?
//
// @since 3.5-3
//
// @param n/a
// @return true/false
function looksee_is_scanning(){
	$scan_report = looksee_get_option('looksee_scan_report');
	return ($scan_report['started'] > 0 && $scan_report['ended'] === 0);
}

//--------------------------------------------------
//Abort a scan
//
// @since 3.5-3
//
// @param $message alternate report message
// @return true/false
function looksee_scan_abort($message=null){
	//if no scan is in progress, there's nothing to abort
	if(!looksee_is_scanning())
		return false;

	//scan details
	$scan_report = looksee_get_option('looksee_scan_report');

	$scan_report['ended'] = looksee_microtime();
	$scan_report['errors'][current_time('timestamp')] = (is_null($message) ? 'Scan aborted by user.' : $message);
	update_option('looksee_scan_report', $scan_report);

	global $wpdb;
	$wpdb->update("{$wpdb->prefix}looksee_files", array('queued'=>0), array('queued'=>1), '%d', '%d');

	return true;
}

//--------------------------------------------------
//Reset the scan report
//
// @since 3.5-3
//
// @param n/a
// @return true/false
function looksee_scan_report_clear(){
	//if a scan is already underway, we cannot clear the report
	if(looksee_is_scanning())
		return false;

	//set the default
	update_option('looksee_scan_report', array('started'=>0, 'ended'=>0, 'errors'=>array(), 'total'=>0, 'scanned'=>0, 'background'=>false));

	return true;
}

//--------------------------------------------------
//Start a scan
//
// @since 3.5-3
//
// @param $background true/false
// @param $core_only true/false
// @return true/false
function looksee_scan_start($background=false, $core_only=false){
	//if a scan is already underway, we cannot start
	if(looksee_is_scanning())
		return false;

	if(!$background && !current_user_can('manage_options'))
		return false;

	global $wpdb;

	//start the scan session!
	looksee_scan_report_clear();
	$scan_report = looksee_get_option('looksee_scan_report');
	$scan_report['started'] = looksee_microtime();

	//core only?  much less perparation...
	if($core_only === true)
	{
		//delete any non-WP entries
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`))");
	}//end core only
	//we're doing a full scan
	else
	{
		//remove entries for custom files that were missing (as of last scan)
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE NOT(LENGTH(`wp`)) AND NOT(LENGTH(`md5_found`))");

		//if we are skipping cache, delete any cache entries too
		if(looksee_get_option('looksee_skip_cache') === true)
			$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE  LEFT(`file`, 17) = 'wp-content/cache/'");

		//update checksums for custom files (using found values from last scan)
		$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_expected`=`md5_found` WHERE NOT(LENGTH(`wp`))");

		//determine whether there are new files to scan
		$files_actual = array();
		looksee_readdir(ABSPATH, $files_actual);
		sort($files_actual);

		//a good place to extend PHP's time limit
		@set_time_limit(0);

		$files_db = array();
		$dbResult = $wpdb->get_results("SELECT `file` FROM `{$wpdb->prefix}looksee_files` ORDER BY `file` ASC", ARRAY_A);
		if($wpdb->num_rows)
		{
			foreach($dbResult AS $Row)
				$files_db[] = $Row["file"];
		}
		$files_new = array_diff($files_actual, $files_db);

		//clear some resources, oof!
		unset($files_actual);
		unset($files_db);

		//if there are new files, add them to the database so they'll get scanned
		if(count($files_new))
		{
			$inserts = array();
			foreach($files_new AS $f)
			{
				//add to the database in blocks
				if(count($inserts) == LOOKSEE_SCAN_INTERVAL)
				{
					$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`) VALUES " . implode(',', $inserts));
					$inserts = array();

					//a good place to extend PHP's time limit
					@set_time_limit(0);
				}
				$inserts[] = "('" . esc_sql($f) . "')";
			}
			//add whatever's left to add
			$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`) VALUES " . implode(',', $inserts));
			unset($inserts);
		}
		unset($files_new);

	}//end full scan

	//queue up the files!
	$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_found`='', `queued`=1, `skipped`=0");

	//how many files are we scanning for?
	$scan_report["total"] = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");

	//save status
	update_option('looksee_scan_report', $scan_report);

	return true;
}

//--------------------------------------------------
//The AJAX handler responsible for actually scanning
//files (in chunks)
//
// @since 3.4.2-6
//
// @param n/a
// @return n/a
function looksee_scan() {
	$xout = array("total"=>0,"completed"=>0,"percent"=>0);

	if(is_user_logged_in())
	{
		global $wpdb;

		//store MD5s in an array so we can update en masse later
		$md5s = array();
		//and store any skipped IDs so we can update those en masse too
		$skipped = array();

		$_POST = stripslashes_deep($_POST);  //take that, magic quotes!
		if(check_ajax_referer( 'l00ks33n0nc3', 'looksee_nonce', false) && intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=1")) > 0)
		{
			//are we limiting by filesize?
			$limit = looksee_get_option('looksee_max_size') * 1024 * 1024;

			//files to check
			$dbResult =  $wpdb->get_results("SELECT `id`, `file` FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=1 ORDER BY `id` ASC LIMIT " . LOOKSEE_SCAN_INTERVAL, ARRAY_A);
			if($wpdb->num_rows)
			{
				foreach($dbResult AS $Row)
				{
					$Row['id'] = (int) $Row['id'];

					//the full file path
					$file = looksee_straighten_windows(ABSPATH . $Row["file"]);

					//are we ignoring based on size?
					if($limit > 0 && @file_exists($file))
					{
						$size = @filesize($file);
						if($size === false || $size > $limit)
						{
							//skip it
							$skipped[] = $Row['id'];

							continue;
						}
					}

					//if the file doesn't exist
					if(!@file_exists($file) || false === ($md5 = md5_file($file)))
						$md5 = '';

					//save the MD5 so we can update the database after the loop
					$md5s[$Row['id']] = $md5;

					//a good place to extend PHP's time limit
					@set_time_limit(0);
				}
			}
			else
				$xout["error"] = -1;

			//skipped anything?
			if(count($skipped))
				$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_found`='', `queued`=0, `skipped`=1 WHERE `id` IN (" . implode(',', $skipped) . ")");

			//any MD5s?
			if(count($md5s))
			{
				$query = "UPDATE `{$wpdb->prefix}looksee_files` SET `md5_found` = CASE `id`";
				foreach($md5s AS $k=>$v)
					$query .= "\nWHEN $k THEN '$v'";
				$query .= "\nEND, `queued`=0 WHERE `id` IN (" . implode(',', array_keys($md5s)) . ")";
				$wpdb->query($query);
			}

			//update counts
			$scan_report = looksee_get_option('looksee_scan_report');
			$xout['total'] = $scan_report['total'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");
			$xout['completed'] = $scan_report['scanned'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=0");
			$xout['percent'] = round(100 * $xout['completed'] / $xout['total'],1);

			//are we done?
			if($xout['total'] === $xout['completed'])
				$scan_report['ended'] = looksee_microtime();

			//save changes
			update_option('looksee_scan_report', $scan_report);
		}
	}

	echo json_encode($xout);
	die();
}
add_action('wp_ajax_looksee_scan', 'looksee_scan');

//----------------------------------------------------------------------  end scan-related functions



//----------------------------------------------------------------------
//  Core definitions
//----------------------------------------------------------------------

//--------------------------------------------------
//Install core definitions
//
// @since 3.5-3
//
// @param $reinstall re-install if already installed?
// @return true/false
function looksee_install_core_definitions($reinstall=false){
	if(!looksee_support_version() || ($reinstall === false && looksee_support_version_installed()))
		return false;

	//if a scan is in progress, we need to kill it:
	if(looksee_is_scanning())
		looksee_scan_abort();

	global $wpdb;

	//the version of wordpress installed
	$wp_version = esc_sql(get_bloginfo('version'));
	//the file containing the core definitions for this version
	$md5_core_file = looksee_straighten_windows(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5');

	//if we are forcing a refresh, let's delete all WP definitions to clear out any garbage that might be there
	if($reinstall === true)
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE LENGTH(`wp`)");

	//load core checksums from file
	$tmp = explode("\n", @file_get_contents($md5_core_file));
	$inserts = array();
	foreach($tmp AS $line)
	{
		//update in chunks!
		if(count($inserts) === LOOKSEE_SCAN_INTERVAL)
		{
			$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`,`wp`,`md5_expected`) VALUES " . implode(',', $inserts) . " ON DUPLICATE KEY UPDATE `wp`='$wp_version', `md5_expected`=VALUES(`md5_expected`), `md5_saved`='',`md5_found`='',`skipped`=0");
			$inserts = array();
		}
		$line = trim($line);
		if(strlen($line) > 34)
		{
			$md5 = substr($line, 0, 32);
			$file = esc_sql(trim(substr($line, 34)));

			//there is an implicit trust that these values are correct, but let's at least make sure the entry looks right-ish
			if(filter_var($md5, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_md5')) && filter_var($file, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_core_file')))
				$inserts[] = "('$file','$wp_version','$md5')";
		}
	}
	//save whatever's left over
	if(count($inserts))
		$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`,`wp`,`md5_expected`) VALUES " . implode(',', $inserts) . " ON DUPLICATE KEY UPDATE `wp`='$wp_version', `md5_expected`=VALUES(`md5_expected`), `md5_saved`='',`md5_found`='',`skipped`=0");

	//clear old files from database, if necessary
	if($reinstall === false)
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE LENGTH(`wp`) AND NOT(`wp`='$wp_version')");

	//and finally, let's clear the results of the last scan
	looksee_scan_report_clear();

	return true;
}

//--------------------------------------------------
//Find "old" files
//
// @since 3.5-4
//
// @param n/a
// @return array
function looksee_get_old_core_definitions(){
	$old = array();
	$old_file = looksee_straighten_windows(dirname(__FILE__) . '/md5sums/.old');

	if(!file_exists($old_file))
		return $old;

	$tmp = explode("\n", @file_get_contents($old_file));
	foreach($tmp AS $line)
	{
		$line = trim($line);
		//there is an implicit trust that the values are correct, but let's at least make sure the entry looks right-ish
		if(filter_var($line, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_core_file')))
			$old[] = $line;
	}

	return $old;
}

//----------------------------------------------------------------------  end core definitions



//----------------------------------------------------------------------
//  What is supported?
//----------------------------------------------------------------------

//--------------------------------------------------
//Support for core version
//
// @since 3.4.2-3
//
// @param n/a
// @return true/false
function looksee_support_version(){
	return @file_exists(looksee_straighten_windows(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5'));
}

//--------------------------------------------------
//Support for md5_file()
//
// @since 3.4.2-3
//
// @param n/a
// @return true/false
function looksee_support_md5(){
	return function_exists('md5_file') && false !== md5_file(__FILE__);
}

//--------------------------------------------------
//Appropriate core definitions installed?
//
// @since 3.5-3
//
// @param n/a
// @return true/false
function looksee_support_version_installed(){
	global $wpdb;
	return $wpdb->get_var("SELECT DISTINCT `wp` FROM `{$wpdb->prefix}looksee_files` WHERE LENGTH(`wp`) ORDER BY `wp` ASC LIMIT 1") === get_bloginfo('version');
}

//----------------------------------------------------------------------  end support functions



//----------------------------------------------------------------------
//  Miscellaneous functions
//----------------------------------------------------------------------
//odds and ends required by this plugin

//--------------------------------------------------
//Recursively find all files in a directory
//
// @since 3.4.2-7
//
// @param $dir directory to search
// @param $files, by reference
// @return array files or false
function looksee_readdir($dir, &$files) {

	//no trailing slash
	if(substr($dir, -1) == '/' || substr($dir, -1) == '\\')
		$dir = substr($dir, 0, strlen($dir)-1);

	//skipping cache?
	if(looksee_get_option('looksee_skip_cache') === true && preg_match('/\/wp\-content\/cache$/', $dir))
		return true;

	if($handle = opendir($dir))
	{
		while(false !== ($file = readdir($handle)))
		{
			if($file != "." && $file != "..")
			{
				$path = looksee_straighten_windows($dir . '/' . $file);
				if(is_dir($path))
					looksee_readdir($path, $files);
				else
					$files[] = str_replace(ABSPATH, '', $path);
			}
		}
		closedir($handle);
	}
	else
		return false;

	return true;
}

//--------------------------------------------------
//filter_var() validation function for MD5 checksums
//
// @since 3.4.2-2
//
// @param $str apparent MD5 checksum
// @return true/false
function looksee_filter_validate_md5($str=''){
	//should be valid hex and 32 chars
	return (bool) preg_match('/^[A-Fa-f0-9]{32}$/', $str);
}

//--------------------------------------------------
//filter_var() validation function for WP core file
//
// @since 3.5-4
//
// param $str apparent file
// @return  true/false
function looksee_filter_validate_core_file($str=''){
	//should not include characters out of the following range
	return (strlen($str) && preg_match('/^[a-zA-Z0-9\/_.-]+$/', $str));
}

//--------------------------------------------------
//Windows' backward slashes cause problems, so let's
//straighten them out!
//
// @since 3.4.2-2
//
// @param $path
// @return path (\ -> /)
function looksee_straighten_windows($path){
	return str_replace('\\','/',$path);
}

//--------------------------------------------------
//The equivalent of WP current_time('microtime')
//
// @since 3.4.2-6
//
// @param n/a
// @return timestamp.microtime
function looksee_microtime(){
	list($sec, $msec) = explode(".", microtime(true));
	if(intval($msec) > 0)
		return round(current_time('timestamp') . '.' . $msec, 5);
	else
		return current_time('timestamp');
}

//----------------------------------------------------------------------  end miscellaneous functions

?>