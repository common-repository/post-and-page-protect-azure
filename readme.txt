=== Post and Page Protect with Azure AD ===
Contributors: justingreerbbi
Donate link: http://dash10.digital/
Tags: azure ad, azure oauth, oauth
Requires at least: 5.5
Tested up to: 5.5
Requires PHP: 5.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protects individual pages and posts by using Azure Active Directory OAuth as authorization.

== Description ==

Protect single posts or pages using Azure AD (Active Directory) authorization.

== Installation ==

1. Search for "Azure Protect" in WordPress's plugin manager or Download "Azure Protect" from wordpress.org
1. Install and Activate "Azure Protect".
1. Go to Page or a Post you want to protect and enter the connection information from your Azure AD app.
1. All visitors will be redirected to authorize through Azure AD before viewing the the Page or Post.

== Frequently Asked Questions ==

= Do this plugin authenticate for Azure AD users site wide? =

No. This plugin only protects and authorizes single pages and posts per page load.

== Changelog ==

= 1.2.0 =
* Updated session logic to use options instead of new table

= 1.0.1 =
* Added WP_Session vendor due to WPEngines ability to play nice with sessions and cookies.

= 1.0.0 =
* Initial Build
