=== Plugin Name ===
Contributors: blobfolio
Donate link: http://www.blobfolio.com
Tags: security, scanner, vulnerabilities, files, validation, auditor, validator, checker
Requires at least: 3.4.2
Tested up to: 3.4.2
Stable tag: 3.4.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Verify the integrity of a WP installation by scanning for unexpected or modified files.

== Description ==

Look-see Security Scanner is a relatively quick and painless way to locate the sorts of file irregularities that turn up when a site is hacked.  This is currently broken down into four types of searches:

  * Verify the integrity of all core WordPress files;
  * Search wp-admin/ for unexpected files;
  * Search wp-includes/ for unexpected files;
  * Search wp-content/uploads/ for unusual file types;

== Installation ==

1. Unzip the archive and upload the entire `look-see` directory to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Find 'Look-See Security Scanner' in the 'Tools' menu to run a search.

== Frequently Asked Questions ==

= Does Look-See correct problems it finds? =

No, Look-See merely points out any irregularities it finds.  It is left to you to manually review any affected files to determine whether or not they pose a threat.

= Can scans be automated? =

Not yet, sorry.  Automated scans will probably be integrated into a future release, so stay tuned!

= How long does it take for new file databases to be released? =

We generally have a new file database ready to go within a day or two of a new WordPress release.

= Is there anything I can do to keep my server from modifying files as I upload them? That is annoying! =

Take a look at your FTP program's settings and change the transfer type from ASCII (or automatic) to Binary.  If your program doesn't support this, try FileZilla: http://filezilla-project.org/.

= If there are no warnings, does that mean I am A-OK? =

Not necessarily. There could still be backdoors elsewhere on the server. As always, we recommend you maintain best security practices and keep regular back-ups.

= Will you continue supporting older versions of WordPress? =

Don't count on it.  As a general rule, you should always be running the latest version of WordPress anyway.  Not doing so is not safe.

== Screenshots ==

1. Easily choose from a list of tests to run and quickly see the results.

== Changelog ==

= 3.4.2 =
* Look-See is born!

== Upgrade Notice ==

N/A