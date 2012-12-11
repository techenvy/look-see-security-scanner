<?php
/*
Plugin Name: Look-See Security Scanner
Plugin URI: http://wordpress.org/extend/plugins/look-see-security-scanner/
Description: Verify the integrity of a WP installation by scanning for unexpected or modified files.
Version: 3.5
Author: Josh Stoik
Author URI: http://www.blobfolio.com/
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

	Copyright © 2012  Josh Stoik  (email: josh@blobfolio.com)

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
define('LOOKSEE_DB', '1.0.3');
//the number of files to scan in a single pass
define('LOOKSEE_SCAN_INTERVAL', 250);
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

	//the files to scan go here
	// `id` numeric primary key
	// `file` the relative file path
	// `file_hash` a CRC32 hash of `file` to help create a case-sensitive unique key regardless of table charset
	// `wp` the wordpress version if a core file, otherwise ''
	// `md5_expected` the expected checksum
	// `md5_found` the discovered checksum
	// `queued` is it scheduled to be scanned? 1/0
	$sql = "CREATE TABLE {$wpdb->prefix}looksee_files (
  id bigint(15) NOT NULL AUTO_INCREMENT,
  file varchar(300) NOT NULL,
  file_hash char(8) NOT NULL,
  wp varchar(10) DEFAULT '' NOT NULL,
  md5_expected char(32) DEFAULT '' NOT NULL,
  md5_found char(32) DEFAULT '' NOT NULL,
  queued tinyint(1) DEFAULT 0 NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY file2 (file,file_hash),
  KEY wp (wp),
  KEY queued (queued)
);";

	require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
	dbDelta($sql);

	//we have some tidying up to do when upgrading to 1.0.3
	if(get_option('looksee_db_version','0.0.0') < '1.0.3')
	{
		//dbDelta doesn't remove old indexes, apparently
		$wpdb->query("ALTER TABLE `{$wpdb->prefix}looksee_files` DROP INDEX `file`");
		//quickly generate some file_hashes
		$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `file_hash`=CRC32(`file`)");
	}

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

	//some quick variables
	$wp_version = mysql_real_escape_string(get_bloginfo('version'));
	$md5_core_file = looksee_straighten_windows(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5');

	//update core checksums
	if(get_option('looksee_core_version','0.0.0') !== $wp_version && @file_exists($md5_core_file))
	{
		global $wpdb;

		//load core checksums from file
		$tmp = explode("\n", @file_get_contents($md5_core_file));
		foreach($tmp AS $line)
		{
			$line = trim($line);
			if(strlen($line) > 34)
			{
				$md5 = substr($line, 0, 32);
				$file = mysql_real_escape_string(trim(substr($line, 34)));

				//there is an implicit trust that these values are correct, but let's at least make sure the entry looks right-ish
				if(filter_var($md5, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_md5')) && strlen($file))
					$wpdb->query("INSERT INTO `{$wpdb->prefix}looksee_files` (`file`,`file_hash`,`wp`,`md5_expected`,`md5_found`,`queued`) VALUES ('$file','" . hash('crc32',$file) . "','$wp_version','$md5','',0) ON DUPLICATE KEY UPDATE `wp`='$wp_version', `md5_expected`='$md5', `md5_found`='', `queued`=0");
			}
		}

		//clear old checksums from database, if necessary
		$wpdb->query("DELETE FROM `{$wpdb->prefix}looksee_files` WHERE LENGTH(`wp`) AND NOT(`wp`='$wp_version')");

		//if for some reason a scan was running, let's kill it now
		$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `queued`=0");
		update_option('looksee_scan_started',0);
		update_option('looksee_scan_finished',0);

		//save the version
		update_option('looksee_core_version',$wp_version);
	}

    return true;
}
add_action('plugins_loaded', 'looksee_db_update');

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
    add_submenu_page('tools.php', 'Look-See Security Scanner', 'Look-See Security Scanner', 'manage_options', 'looksee-security-scanner', 'looksee_security_scanner');
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

		$_POST = stripslashes_deep($_POST);  //take that, magic quotes!
		if(check_ajax_referer( 'l00ks33n0nc3', 'looksee_nonce', false) && intval($wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=1")) > 0)
		{
			//files to check
			$dbResult =  mysql_query("SELECT `file` FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=1 ORDER BY `id` ASC LIMIT " . LOOKSEE_SCAN_INTERVAL);
			if(mysql_num_rows($dbResult))
			{
				while($Row = mysql_fetch_assoc($dbResult))
				{
					if(!@file_exists(looksee_straighten_windows(ABSPATH . $Row["file"])) || false === ($md5 = md5_file(looksee_straighten_windows(ABSPATH . $Row["file"]))))
						$md5 = '';

					$wpdb->query("UPDATE `{$wpdb->prefix}looksee_files` SET `md5_found`='$md5', `queued`=0 WHERE `file`='" . mysql_real_escape_string($Row["file"]) . "'");
				}
			}
			else
				$xout["error"] = -1;

			//update counts
			$xout["total"] = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files`");
			$xout["completed"] = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$wpdb->prefix}looksee_files` WHERE `queued`=0");
			$xout["percent"] = round(100 * $xout["completed"] / $xout["total"],1);

			//are we done?
			if($xout["total"] === $xout["completed"])
				update_option('looksee_scan_finished', looksee_microtime());
		}
	}

	echo json_encode($xout);
	die();
}
add_action('wp_ajax_looksee_scan', 'looksee_scan');

//----------------------------------------------------------------------  end WP backend stuff



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
	return get_option('looksee_core_version','0.0.0') === get_bloginfo('version');
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