<?php
/**
 * The plugin bootstrap file
 *
 * CloudSecure WP Securityは、管理画面とログインURLをサイバー攻撃から守る、国産・日本語対応のセキュリティ対策プラグインです。
 * 簡単な設定だけで、不正アクセスや不正ログインからWordPressを保護し、サイトのセキュリティを高めます。
 * 各機能は有効／無効を切り替えるだけで設定でき、必要な対策をわかりやすく管理できます。シンプルで扱いやすい設計のため、日々のサイト運用にも取り入れやすいプラグインです。
 *
 * @link              https://wpplugin.cloudsecure.ne.jp/cloudsecure_wp_security
 * @package           CloudSecure_WP_Security
 *
 * @wordpress-plugin
 * Plugin Name:   CloudSecure WP Security
 * Plugin URI:    https://wpplugin.cloudsecure.ne.jp/cloudsecure_wp_security
 * Description:   CloudSecure WP Securityは、管理画面とログインURLをサイバー攻撃から守る、国産・日本語対応のセキュリティ対策プラグインです。簡単な設定だけで、不正アクセスや不正ログインからWordPressを保護し、サイトのセキュリティを高めます。各機能は有効／無効を切り替えるだけで設定でき、必要な対策をわかりやすく管理できます。シンプルで扱いやすい設計のため、日々のサイト運用にも取り入れやすいプラグインです。
 * Version:       1.4.12
 * Requires PHP:  7.1
 * Author:        XServer Inc.
 * Author URI:    https://www.xserver.co.jp
 * License:       GPLv2 or later
 * License URI:   http://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:   cloudsecure_wp_security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$cloudsecurewp_info_datas = array(
	'version'     => 'Version',
	'plugin_name' => 'Plugin Name',
	'text_domain' => 'Text Domain',
);

$cloudsecurewp_info                = get_file_data( __FILE__, $cloudsecurewp_info_datas );
$cloudsecurewp_info['plugin_path'] = plugin_dir_path( __FILE__ );
$cloudsecurewp_info['plugin_url']  = plugin_dir_url( __FILE__ );

require_once 'modules/cloudsecure-wp.php';
global $cloudsecurewp;

$cloudsecurewp = new CloudSecureWP( $cloudsecurewp_info );
$cloudsecurewp->run();

// WP-CLI コマンドの読み込み
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once 'modules/cli/class-cloudsecure-wp-cli.php';
}

/**
 * プラグイン有効化時の処理
 */
function cloudsecurewp_activate() {
	global $cloudsecurewp;
	$cloudsecurewp->activate();
}
register_activation_hook( __FILE__, 'cloudsecurewp_activate' );

/**
 * プラグイン無効化時の処理
 */
function cloudsecurewp_deactivate() {
	global $cloudsecurewp;
	$cloudsecurewp->deactivate();
}
register_deactivation_hook( __FILE__, 'cloudsecurewp_deactivate' );
