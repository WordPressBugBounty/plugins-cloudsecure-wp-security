<?php
/**
 * CloudSecure WP Security CLI Commands Registration
 *
 * @package CloudSecure_WP_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

// 各コマンドクラスを読み込み
require_once __DIR__ . '/commands/class-cloudsecure-wp-cli-list.php';
require_once __DIR__ . '/commands/class-cloudsecure-wp-cli-status.php';
require_once __DIR__ . '/commands/class-cloudsecure-wp-cli-disable.php';
require_once __DIR__ . '/commands/class-cloudsecure-wp-cli-enable.php';
require_once __DIR__ . '/commands/class-cloudsecure-wp-cli-disable-restapi.php';

/**
 * CloudSecure WP Security CLI Commands Registration
 * CLI コマンドの登録を管理するクラス
 */
class CloudSecureWP_CLI_Main {

	/**
	 * 各コマンドを登録する
	 */
	public static function register_commands() {
		// 各コマンドを登録
		WP_CLI::add_command( 'cldsec-wp-security list', 'CloudSecureWP_CLI_List' );
		WP_CLI::add_command( 'cldsec-wp-security status', 'CloudSecureWP_CLI_Status' );
		WP_CLI::add_command( 'cldsec-wp-security disable', 'CloudSecureWP_CLI_Disable' );
		WP_CLI::add_command( 'cldsec-wp-security enable', 'CloudSecureWP_CLI_Enable' );
		WP_CLI::add_command( 'cldsec-wp-security disable-restapi', 'CloudSecureWP_CLI_Disable_Restapi' );
	}
}

// コマンド登録
CloudSecureWP_CLI_Main::register_commands();
