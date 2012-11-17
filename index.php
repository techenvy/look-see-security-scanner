<?php
/*
Plugin Name: Look-See Security Scanner
Plugin URI: http://wordpress.org/extend/plugins/look-see-security-scanner/
Description: Verify the integrity of a WP installation by scanning for unexpected or modified files.
Version: 3.4.2-5
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


define('MD5_CORE_FILE', looksee_straighten_windows(dirname(__FILE__) . '/md5sums/' . get_bloginfo('version') . '.md5'));
define('CRC32_CUSTOM_FILE', looksee_straighten_windows(dirname(__FILE__) . '/md5sums/custom.crc32'));



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

//----------------------------------------------------------------------  end WP backend stuff



//----------------------------------------------------------------------
//  File checksums
//----------------------------------------------------------------------
//functions relating to the core and custom file checksum databases

//--------------------------------------------------
//Load core checksums
//
// @since 3.4.2-3
//
// @param n/a
// @return array checksums or false
function looksee_core_checksums(){
	//if the core file doesn't exist...
	if(!looksee_support_version() || !looksee_support_md5())
		return false;

	$md5_core = array();
	//make sure we can read the file database
	$tmp = explode("\n", @file_get_contents(MD5_CORE_FILE));
	foreach($tmp AS $line)
	{
		$line = trim($line);
		if(strlen($line) > 34)
		{
			$md5 = substr($line, 0, 32);
			$file = trim(substr($line, 34));

			//there is an implicit trust that these values are correct, but let's at least make sure the entry looks right-ish
			if(filter_var($md5, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_md5')) && strlen($file))
				$md5_core[$file] = $md5;
		}
	}
	ksort($md5_core);
	return $md5_core;
}

//--------------------------------------------------
//Load custom checksums
//
// @since 3.4.2-3
//
// @param n/a
// @return array checksums or false
function looksee_custom_checksums(){
	$crc_custom = array();
	//make sure we can read the file database
	$tmp = explode("\n", @file_get_contents(CRC32_CUSTOM_FILE));
	foreach($tmp AS $line)
	{
		$line = trim($line);
		if(strlen($line) > 10)
		{
			$crc = substr($line, 0, 8);
			$file = trim(substr($line, 10));

			//there is an implicit trust that these values are correct, but let's at least make sure the entry looks right-ish:
			//1) CRC32b is formatted correctly; 2) file name has length; 3) file is not the custom checksum file, as that'll never match. :)
			if(filter_var($crc, FILTER_CALLBACK, array('options'=>'looksee_filter_validate_crc32')) && strlen($file) && $file !== looksee_straighten_windows(str_replace(ABSPATH,'',CRC32_CUSTOM_FILE)))
				$crc_custom[$file] = $crc;
		}
	}
	ksort($crc_custom);
	return $crc_custom;
}

//----------------------------------------------------------------------  end file checksum functions



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
	return file_exists(MD5_CORE_FILE);
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
//Support for hash_file crc32
//
// @since 3.4.2-5
//
// @param n/a
// @return true/false
function looksee_support_crc32(){
	return function_exists('hash_file') && false !== hash_file('crc32', __FILE__);
}

//--------------------------------------------------
//Support for custom version
//
// @since 3.4.2-3
//
// @param n/a
// @return true/false
function looksee_support_custom(){
	if(file_exists(CRC32_CUSTOM_FILE))
		return true;

	return false !== file_put_contents(CRC32_CUSTOM_FILE, '', LOCK_EX) && file_exists(CRC32_CUSTOM_FILE);
}

//----------------------------------------------------------------------  end support functions



//----------------------------------------------------------------------
//  Miscellaneous functions
//----------------------------------------------------------------------
//odds and ends required by this plugin

//--------------------------------------------------
//Recursively find all files in a directory
//
// @since 3.4.2
//
// @param $dir directory to search
// @param $ext optional array of extensions to include in search
// @return array files or false
function looksee_readdir($dir, $ext=null) {

	//no trailing slash
	if(substr($dir, -1) == '/' || substr($dir, -1) == '\\')
		$dir = substr($dir, 0, strlen($dir)-1);

	//make sure this is a valid directory
	if(!is_dir($dir))
		return false;

	//if $ext is set, we want to sanitize and compile into a preg_match rule
	if(is_array($ext))
	{
		$tmp = array();
		foreach($ext AS $e)
		{
			$e = preg_replace('/[^a-z0-9]/i', '', $e);
			if(strlen($e))
				$tmp[] = $e;
		}
		if(count($tmp))
			$regext = '/\.(' . implode('|', array_unique($tmp)) . ')$/i';
		else
			$ext = null;
	}
	//make sure it's null if this is a bust
	elseif(!is_null($ext))
		$ext = null;

	$contents = array();

	//scan the directory
	$cdir = scandir($dir);
	foreach ($cdir as $k => $v)
	{
		if(!in_array($v,array(".","..")))
		{
			//recurse if $v is itself a directory
			if(is_dir(looksee_straighten_windows($dir . DIRECTORY_SEPARATOR . $v)))
				$contents = array_merge($contents, looksee_readdir(looksee_straighten_windows($dir . DIRECTORY_SEPARATOR . $v), $ext));
			//if $v is a file (if $ext is specified, a matching file), add it
			//although we want a location relative to WP root, so we remove ABSPATH from the beginning
			elseif(is_null($ext) || preg_match($regext, $v))
				$contents[] = looksee_straighten_windows(str_replace(ABSPATH, '', $dir . DIRECTORY_SEPARATOR . $v));
		}
	}

	return array_unique($contents);
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
//filter_var() validation function for CRC32b checksums
//
// @since 3.4.2-5
//
// @param $str apparent CRC checksum
// @return true/false
function looksee_filter_validate_crc32($str=''){
	//should be valid hex and 8 chars
	return (bool) preg_match('/^[A-Fa-f0-9]{8}$/', $str);
}

//--------------------------------------------------
//A simple timer - start
//
// @since 3.4.2-2
//
// @param n/a
// @return true
$looksee_time = 0;
function looksee_clock_start(){
	global $looksee_time;
	$looksee_time = microtime(true);
	return true;
}

//--------------------------------------------------
//A simple timer - finish
//
// @since 3.4.2-2
//
// @param n/a
// @return seconds since $looksee_time
function looksee_clock_finish(){
	global $looksee_time;
	$difference = round(microtime(true) - $looksee_time, 4);
	$looksee_time = 0;
	return $difference;
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

//----------------------------------------------------------------------  end miscellaneous functions

?>