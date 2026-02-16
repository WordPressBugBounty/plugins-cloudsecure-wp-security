<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * リカバリーコード管理クラス
 * 2段階認証のバックアップ用コードを生成・管理
 */
class CloudSecureWP_Recovery_Codes {
	private const CODE_LENGTH = 12;
	private const CODE_COUNT  = 10;

	/**
	 * 単一のリカバリーコードを生成
	 *
	 * @return string
	 */
	private static function create_single_code(): string {
		// 12文字の英数字コードを生成（大文字・小文字両方含む、紛らわしい文字「01oOlI」を除外）
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
		$code  = '';

		for ( $i = 0; $i < self::CODE_LENGTH; $i++ ) {
			$code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}

		return $code;
	}

	/**
	 * リカバリーコードを生成
	 *
	 * @return array ['plain_codes' => array, 'hashed_codes' => array]
	 */
	private static function create_code(): array {
		$plain_codes  = array();
		$hashed_codes = array();

		for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
			// コードを生成
			$code = self::create_single_code();

			// 平文コードを配列に追加（表示用、ハイフン付き）
			$plain_codes[] = substr( $code, 0, 4 ) . '-' . substr( $code, 4, 4 ) . '-' . substr( $code, 8, 4 );

			// ハッシュ化したコードを配列に追加（保存用）
			$hashed_codes[] = wp_hash_password( $code );
		}

		return array(
			'plain_codes'  => $plain_codes,
			'hashed_codes' => $hashed_codes,
		);
	}

	/**
	 * ユーザーのリカバリーコード（ハッシュ）を保存
	 *
	 * @param int   $user_id
	 * @param array $hashed_codes
	 *
	 * @return bool true: 保存成功、false: 保存失敗
	 */
	private static function save_codes( int $user_id, array $hashed_codes ): bool {
		global $wpdb;
		$table_name = $wpdb->prefix . 'cloudsecurewp_2fa_auth';

		// 配列をシリアライズ
		$serialized_codes = serialize( $hashed_codes );

		// レコードが存在するかチェック
		$sql = "SELECT 1 FROM $table_name WHERE user_id = %d";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$exists = $wpdb->get_var( $wpdb->prepare( $sql, $user_id ) );

		if ( $exists ) {
			// 更新
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$result = $wpdb->update(
				$table_name,
				array( 'recovery' => $serialized_codes ),
				array( 'user_id' => $user_id ),
				array( '%s' ),
				array( '%d' )
			);
		} else {
			// ここには入らない想定
			return false;
		}

		return $result !== false;
	}

	/**
	 * リカバリーコードを初期化
	 *
	 * @param int $user_id
	 *
	 * @return array 平文コードの配列（生成・保存に失敗した場合は空配列を返却）
	 */
	public static function initialize_codes( int $user_id ): array {
		// 新しいコードを生成
		$recovery_code = self::create_code();
		if ( count( $recovery_code['plain_codes'] ) === 0 || count( $recovery_code['hashed_codes'] ) === 0 ) {
			return [];
		}

		// ハッシュ化されたコードをDBに保存（既存のコードは上書きされる）
		$result = self::save_codes( $user_id, $recovery_code['hashed_codes'] );
		if ( ! $result ) {
			return [];
		}

		// 平文コードを返却
		return $recovery_code['plain_codes'];
	}

	/**
	 * ユーザーのリカバリーコードを取得
	 *
	 * @param int $user_id
	 *
	 * @return array|false
	 */
	private static function get_codes( int $user_id ) {
		global $wpdb;

		// DBからコードを取得
		$sql = "SELECT recovery FROM {$wpdb->prefix}cloudsecurewp_2fa_auth WHERE user_id = %d";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$serialized_codes = $wpdb->get_var( $wpdb->prepare( $sql, $user_id ) );
		if ( ! $serialized_codes ) {
			return false;
		}

		// シリアライズされた配列をデコード
		$stored_codes = unserialize( $serialized_codes );
		if ( ! $stored_codes || ! is_array( $stored_codes ) ) {
			return false;
		}

		return $stored_codes;
	}

	/**
	 * コードを正規化（ハイフンとスペースを除去）
	 *
	 * @param string $code
	 *
	 * @return string
	 */
	private static function normalize_code( string $code ): string {
		// 両端の空白を除去し、間のハイフンを除去
		$code = trim( $code );
		$code = preg_replace( '/(?<!^)-(?!$)/', '', $code );
		return $code;
	}

	/**
	 * リカバリーコードを検証
	 *
	 * @param int    $user_id
	 * @param string $code
	 *
	 * @return bool true: 検証成功、false: 検証失敗
	 */
	public static function verify_code( int $user_id, string $code ): bool {
		// DBからコードを取得
		$stored_codes = self::get_codes( $user_id );
		if ( ! is_array( $stored_codes ) || count( $stored_codes ) === 0 ) {
			return false;
		}

		// 入力コードを正規化
		$normalized_code = self::normalize_code( $code );

		// 保存されているコードと照合
		foreach ( $stored_codes as $index => $stored_code ) {
			// コードを検証
			if ( wp_check_password( $normalized_code, $stored_code ) ) {
				// コードを使用済みとして削除
				unset( $stored_codes[ $index ] );
				// DBを更新
				self::save_codes( $user_id, $stored_codes );
				return true;
			}
		}

		return false;
	}
}
