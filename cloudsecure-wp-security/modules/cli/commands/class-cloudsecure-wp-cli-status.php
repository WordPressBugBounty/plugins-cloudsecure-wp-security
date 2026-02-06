<?php
/**
 * CloudSecure WP Security Status Command
 * 機能の設定値表示専用のコマンドクラス
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
 * CloudSecure WP Security Status Command
 * 機能の設定値表示専用のコマンドクラス
 */
class CloudSecureWP_CLI_Status extends CloudSecureWP_CLI_Base {

	/**
	 * 機能の設定値を表示する
	 *
	 * ## EXAMPLES
	 * wp cldsec-wp-security status disable-login
	 * wp cldsec-wp-security status login-notification
	 *
	 * ## OPTIONS
	 * <feature> : 設定値を確認する機能名（必須、単一の機能名のみ受付。複数指定はエラー）
	 *
	 * @param array $args 位置引数
	 * @param array $assoc_args 関連配列引数
	 */
	public function __invoke( $args = array(), $assoc_args = array() ) {
		try {
			// 共通の機能検証処理
			$validation_result = $this->validate_feature_arguments( $args, true );
			if ( ! $validation_result['success'] ) {
				$this->output_error_response(
					array(
						'message' => $validation_result['error'],
					)
				);
				return;
			}

			$feature_name     = $validation_result['feature_name'];
			$description      = $validation_result['description'];
			$feature_instance = $validation_result['feature_instance'];

			// 設定値を取得
			$settings    = $feature_instance->get_settings();
			$feature_key = $feature_instance->get_feature_key();

			// 機能の基本情報（設定値から直接取得）
			$enabled = isset( $settings[ $feature_key ] ) && $settings[ $feature_key ] === 't';
			$status  = $enabled ? 'enabled' : 'disabled';

			// 設定値をフィルタリング（内部設定は除外）
			$configuration = array();
			foreach ( $settings as $key => $value ) {
				// 機能キー自体はスキップ（statusで既に表示済み）
				if ( $key === $feature_key ) {
					continue;
				}

				// 設定キーから機能名プレフィックスを削除
				$display_key = str_replace( $feature_key . '_', '', $key );

				// 内部設定は除外
				if ( $this->is_internal_setting( $feature_name, $display_key ) ) {
					continue;
				}

				// テキストエリア内容の改行コード変換
				if ( $this->is_textarea_setting( $feature_name, $display_key ) ) {
					$value = $this->convert_textarea_to_placeholder( $value );
				}

				// 配列設定の場合はキーを再インデックス（JSON出力の一貫性確保）
				if ( $this->is_array_setting( $feature_name, $display_key ) && is_array( $value ) ) {
					$value = array_values( $value );
				}

				// 表示用の値を正規化（boolean: t→1, f→0、ビットフラグ: 63→sql,xss,command,code,mail）
				$value = $this->normalize_value_for_display( $feature_name, $display_key, $value );

				$configuration[ $display_key ] = $value;
			}

			// 特別な設定を追加（WordPressオプション）
			$this->add_special_configuration_settings( $feature_name, $configuration );

			$response_data = array(
				'result'        => 'success',
				'data'          => array(
					'name'          => $feature_name,
					'description'   => $description,
					'status'        => $status,
					'configuration' => $configuration,
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
