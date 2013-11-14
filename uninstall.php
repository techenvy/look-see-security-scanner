<?php
//----------------------------------------------------------------------
//  Look-See uninstallation
//----------------------------------------------------------------------
//remove plugin data so as not to needlessly clutter a system that is
//no longer using Apocalypse Meow
//
// @since 3.5-6



//make sure WordPress is calling this page
if (!defined('WP_UNINSTALL_PLUGIN'))
	exit ();

//remove options
foreach(array('looksee_db_version','looksee_max_size','looksee_scan_report','looksee_skip_cache') AS $option)
	delete_option($option);

//try to remove the table... not all db uses will have this privilege
global $wpdb;
$wpdb->query("DROP TABLE IF EXISTS `{$wpdb->prefix}looksee_files`");



return true;
?>