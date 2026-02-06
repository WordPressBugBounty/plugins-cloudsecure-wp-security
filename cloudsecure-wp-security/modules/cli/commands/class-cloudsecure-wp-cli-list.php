<?php
/**
 * CloudSecure WP Security List Command
 * 機能一覧表示専用のコマンドクラス
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
 * CloudSecure WP Security List Command
 * 機能一覧表示専用のコマンドクラス
 */
class CloudSecureWP_CLI_List extends CloudSecureWP_CLI_Base {

	/**
	 * 機能一覧を表示する
	 *
	 * ## EXAMPLES
	 * wp cldsec-wp-security list
	 *
	 * @param array $args 位置引数
	 * @param array $assoc_args 関連配列引数
	 */
	public function __invoke( $args = array(), $assoc_args = array() ) {
		try {
			$features_data = array();

			foreach ( self::FEATURE_MAP as $cli_name => $property_name ) {
				// 設定値が存在しない機能を除外
				if ( in_array( $cli_name, self::CONFIG_EXCLUDED_FEATURES, true ) ) {
					WP_CLI::debug( "機能 '{$cli_name}' はCONFIG_EXCLUDED_FEATURESに含まれているためスキップします" );
					continue;
				}

				$feature_instance = $this->get_feature_instance( $cli_name );

				// インスタンスが取得できない場合はエラー終了
				if ( ! $feature_instance ) {
					$this->output_error_response(
						array(
							'message' => "機能 '{$cli_name}' のインスタンスを取得できませんでした。",
						)
					);
				}

				// is_enabled メソッドが存在しない場合はエラー終了
				if ( ! method_exists( $feature_instance, 'is_enabled' ) ) {
					$this->output_error_response(
						array(
							'message' => "機能 '{$cli_name}' の有効無効状態を取得できません。",
						)
					);
				}

				// is_enabledメソッドを実行し機能の状態を取得
				$status      = $feature_instance->is_enabled() ? 'enabled' : 'disabled';
				$description = self::FEATURE_DESCRIPTIONS[ $cli_name ] ?? $cli_name;

				$features_data[] = array(
					'name'        => $cli_name,
					'description' => $description,
					'status'      => $status,
				);
			}

			// 成功レスポンスを出力
			$response_data = array(
				'result' => 'success',
				'data'   => array(
					'features' => $features_data,
				),
			);
			$this->output_success_response( $response_data );
		} catch ( Exception $e ) {
			$this->output_error_response(
				array(
					'message' => $e->getMessage(),
				)
			);
		}
	}
}
