<?php
/**
 * CloudSecure WP Security CLI Disable REST API Command
 *
 * @package CloudSecure_WP_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

// ベースクラスを読み込み
require_once dirname( __DIR__ ) . '/class-cloudsecure-wp-cli-base.php';

/**
 * CloudSecure WP Security Disable REST API Command
 * REST API無効化機能専用のコマンドクラス
 */
class CloudSecureWP_CLI_Disable_Restapi extends CloudSecureWP_CLI_Base {

	/**
	 * 機能名
	 */
	private const FEATURE_NAME = 'disable-restapi';

	/**
	 * @var object REST API無効化機能のインスタンス
	 */
	private $feature_instance;

	public function __construct() {
		parent::__construct();
		$this->init_feature_instance();
	}

	/**
	 * REST API無効化機能のインスタンスを初期化
	 */
	private function init_feature_instance() {
		$this->feature_instance = $this->get_feature_instance( self::FEATURE_NAME );

		if ( ! $this->feature_instance ) {
			WP_CLI::error( 'REST API無効化機能のインスタンスを取得できませんでした。' );
		}
	}

	/**
	 * 有効済みプラグインの一覧を取得
	 *
	 * ## DESCRIPTION
	 * REST API無効化機能で除外指定していない有効なプラグインの一覧を取得します。
	 *
	 * ## EXAMPLES
	 * wp cldsec-wp-security disable-restapi list-plugins
	 *
	 * @subcommand list-plugins
	 */
	public function list_plugins( $args = array(), $assoc_args = array() ) {
		try {
			// 機能が存在するかチェック
			if ( ! $this->feature_instance ) {
				$this->output_error_response( array( 'message' => 'REST API無効化機能が利用できません。' ) );
				return;
			}

			// 有効済みプラグインの一覧を取得
			if ( ! method_exists( $this->feature_instance, 'get_active_plugin_names' ) ) {
				$this->output_error_response( array( 'message' => 'get_active_plugin_namesメソッドが見つかりません。' ) );
				return;
			}

			$active_plugins = $this->feature_instance->get_active_plugin_names();

			// プラグイン名をカンマ区切りの文字列に変換
			$plugin_names_string = $this->convert_array_to_string( $active_plugins );

			// 成功レスポンス
			$response_data = array(
				'result' => 'success',
				'data'   => array(
					'active_plugin_names' => $plugin_names_string,
				),
			);

			$this->output_success_response( $response_data );

		} catch ( Exception $e ) {
			$this->output_error_response(
				array(
					'message' => 'コマンド実行中にエラーが発生しました: ' . $e->getMessage(),
				)
			);
		}
	}
}
