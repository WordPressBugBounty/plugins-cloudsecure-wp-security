<?php
/**
 * CloudSecure WP Security Disable Command
 * 機能の無効化専用のコマンドクラス
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
 * CloudSecure WP Security Disable Command
 * 機能の無効化専用のコマンドクラス
 */
class CloudSecureWP_CLI_Disable extends CloudSecureWP_CLI_Base {

	/**
	 * 機能を無効化する
	 *
	 * ## EXAMPLES
	 * wp cldsec-wp-security disable disable-login
	 * wp cldsec-wp-security disable two-factor-authentication
	 *
	 * ## OPTIONS
	 * <feature> : 無効化する機能名（必須）
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

			// 無効化処理を実行
			$deactivation_result = $this->deactivate_feature( $feature_instance, $feature_name );

			if ( $deactivation_result['success'] ) {
				// 成功レスポンス
				$response_data = array(
					'result'  => 'success',
					'message' => $description . '機能が無効になりました。',
				);

				$this->output_success_response( $response_data );
			} else {
				$error_message = "機能 '{$feature_name}' ({$description}) の無効化に失敗しました。";

				$this->output_error_response(
					array(
						'message'       => $error_message,
						'error_details' => $deactivation_result['error'] ?? '詳細不明',
					)
				);
			}
		} catch ( Exception $e ) {
			$this->output_error_response(
				array(
					'message' => 'コマンド実行中にエラーが発生しました: ' . $e->getMessage(),
				)
			);
		}
	}

	/**
	 * 機能を無効化する
	 *
	 * @param object $feature_instance 機能インスタンス
	 * @param string $feature_name 機能名
	 * @return array 実行結果
	 */
	private function deactivate_feature( $feature_instance, $feature_name ) {
		try {
			// 通常の機能の場合、deactivateメソッドを呼び出し
			if ( method_exists( $feature_instance, 'deactivate' ) ) {
				$feature_instance->deactivate();
				return array(
					'success' => true,
				);
			} else {
				return array(
					'success' => false,
					'error'   => 'deactivateメソッドが見つかりません。',
				);
			}
		} catch ( Exception $e ) {
			return array(
				'success' => false,
				'error'   => $e->getMessage(),
			);
		}
	}
}
