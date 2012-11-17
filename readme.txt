=== Plugin Name ===
Contributors: blobfolio
Donate link: http://www.blobfolio.com
Tags: security, scanner, vulnerabilities, files, validation, auditor, validator, checker
Requires at least: 3.4.2
Tested up to: 3.4.2
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Verify the integrity of a WP installation by scanning for unexpected or modified files.

== Description ==

Look-see Security Scanner is a relatively quick and painless way to locate the sorts of file irregularities that turn up when a site is hacked.  This is broken down into multiple searches:

  * Verify the integrity of all core WordPress files;
  * Search wp-admin/ for unexpected files;
  * Search wp-includes/ for unexpected files;
  * Search wp-content/uploads/ for unusual file types;
  * Compare the current custom file contents of a WP installation to what it looked like the last time it was scanned;

== Installation ==

1. Unzip the archive and upload the entire `look-see` directory to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Find 'Look-See Security Scanner' in the 'Tools' menu to run a search.

== Frequently Asked Questions ==

= Does Look-See correct any problems it finds? =

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

= The custom MD5 checksum file is not writeable... =

The custom scan needs to be able to store the results of the latest scan in a file located in `[the look-see plugin directory]/md5sums/custom.md5` for later comparison; you'll receive an error if WordPress is not allowed to do this.  To correct the problem:

1. Upload a blank text file called `custom.md5` to the aforementioned location and re-run the custom scan.  If it works, great!  If not, move onto #2...
2. Change the file's owner:group to that of the web server (i.e. assign ownership of the file over to the web server). If WP still cannot write to the file or if you are unable to make this change, then as a last resort...
3. Change the file's read/write/execute permissions (CHMOD) to whatever is required by your server to give WP the authority to make changes.  This might have to be 777, though if a lower value works, use that instead.

== Screenshots ==

1. Easily choose from a list of tests to run and quickly see the results.

== Changelog ==

= 3.4.2-5 =
* Switched from MD5 to CRC32 checksums for the custom file database as the former was simply too slow for many users.

= 3.4.2-4 =
* Disable automatic building of custom file database when missing; operation can take a long time on slow servers.

= 3.4.2-3 =
* Automatically build custom file database when missing;

= 3.4.2-2 =
* Fixed a bug affecting wp-content/uploads scan when uploads are split into multiple folders;
* Added custom content scan;
* Scans now report duration spent in execution;
* Improved support for Windows servers;
* Last-run timestamp for each scan;

= 3.4.2 =
* Look-See is born!

== Upgrade Notice ==

= 3.4.2-5 =
This release speeds up custom file scans; if your current setup is too slow, try upgrading.

= 3.4.2-4 =
This release roles back the changes of 3.4.2-3, as it proved too difficult for slow servers.

= 3.4.2-3 =
This release addresses a small bug introducedin 3.4.2-2.

= 3.4.2-2 =
This release fixes a bug affecting the wp-content/uploads scan, and also adds a new custom scan. Everyone should upgrade.