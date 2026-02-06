<?php
/**
 * CloudSecure WP Security CLI Base Class
 *
 * @package CloudSecure_WP_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

/**
 * CloudSecure WP Security CLI Base Class
 * 共通機能を提供するベースクラス
 */
abstract class CloudSecureWP_CLI_Base extends WP_CLI_Command {

	/**
	 * @var CloudSecureWP
	 */
	protected $plugin;

	/**
	 * 機能名とクラスのマッピング
	 */
	protected const FEATURE_MAP = array(
		'disable-login'               => 'disable_login',
		'rename-login-page'           => 'rename_login_page',
		'unify-messages'              => 'unify_messages',
		'two-factor-authentication'   => 'two_factor_authentication',
		'captcha'                     => 'captcha',
		'restrict-admin-page'         => 'restrict_admin_page',
		'disable-access-system-file'  => 'disable_access_system_file',
		'disable-author-query'        => 'disable_author_query',
		'disable-xmlrpc'              => 'disable_xmlrpc',
		'disable-restapi'             => 'disable_restapi',
		'waf'                         => 'waf',
		'login-notification'          => 'login_notification',
		'update-notice'               => 'update_notice',
		'server-error-notification'   => 'server_error_notification',
		'login-log'                   => 'login_log',
	);

	/**
	 * 機能の説明
	 */
	protected const FEATURE_DESCRIPTIONS = array(
		'disable-login'               => 'ログイン無効化',
		'rename-login-page'           => 'ログインURL変更',
		'unify-messages'              => 'ログインエラーメッセージ統一',
		'two-factor-authentication'   => '2段階認証',
		'captcha'                     => '画像認証追加',
		'restrict-admin-page'         => '管理画面アクセス制限',
		'disable-access-system-file'  => '設定ファイルアクセス防止',
		'disable-author-query'        => 'ユーザー名漏えい防止',
		'disable-xmlrpc'              => 'XML-RPC無効化',
		'disable-restapi'             => 'REST API無効化',
		'waf'                         => 'シンプルWAF',
		'login-notification'          => 'ログイン通知',
		'update-notice'               => 'アップデート通知',
		'server-error-notification'   => 'サーバーエラー通知',
		'login-log'                   => 'ログイン履歴',
	);

	/**
	 * htaccessを使用する機能のリスト
	 */
	protected const HTACCESS_FEATURES = array(
		'restrict-admin-page',
		'rename-login-page',
		'disable-xmlrpc',
	);

	/**
	 * 設定値が存在しない機能のリスト
	 * （有効無効の切り替えのみで、設定値の表示・変更が不要な機能）
	 */
	protected const CONFIG_EXCLUDED_FEATURES = array(
		'login-log',
	);

	/**
	 * 改行コードの置換文字列
	 */
	protected const NEWLINE_PLACEHOLDER = '__CLDSEC_NEWLINE__';

	/**
	 * WAF攻撃タイプの文字列リスト
	 */
	protected const WAF_ATTACK_TYPES = array( 'sql', 'xss', 'command', 'code', 'mail' );

	/**
	 * WAF攻撃タイプのビットマッピング
	 */
	protected const WAF_ATTACK_TYPE_BITS = array(
		'sql'     => 1,   // SQLインジェクション
		'xss'     => 2,   // クロスサイトスクリプティング
		'command' => 4,   // OSコマンドインジェクション
		'code'    => 8,   // コードインジェクション
		'mail'    => 16,  // メールヘッダインジェクション
	);

	/**
	 * 特別なWordPressオプション保存処理が必要な機能のリスト
	 */
	protected const SPECIAL_PROCESSING_FEATURES = array(
		'two-factor-authentication',
		'server-error-notification',
	);

	/**
	 * 特別なWordPressオプション設定項目の定数定義
	 */
	protected const SPECIAL_SETTING_KEYS = array(
		'TWO_FACTOR_ENABLED_ROLES'        => 'enabled_roles',
		'TWO_FACTOR_USER_REGISTRATIONS'   => 'user_registrations',
		'SERVER_ERROR_EMAIL_NOTIFICATION' => 'email_notification',
	);

	/**
	 * 特別なWordPressオプションの定数定義
	 */
	protected const WORDPRESS_OPTION_NAMES = array(
		'TWO_FACTOR_ROLES'         => 'cloudsecurewp_two_factor_authentication_roles',
		'TWO_FACTOR_REGISTRATIONS' => 'cloudsecurewp_two_factor_authentication_user_registrations',
		'SERVER_ERROR_EMAIL'       => 'cloudsecurewp_enable_email_server_error_notification',
	);

	/**
	 * 設定タイプ定義（各機能・設定キーごとの型情報）
	 */
	protected const SETTING_TYPES = array(
		'textarea' => array(
			'login-notification' => array( 'body' ),
		),
		'array' => array(
			'restrict-admin-page'       => array( 'paths' ),
			'disable-restapi'           => array( 'exclude' ),
			'two-factor-authentication' => array( 'enabled_roles' ),
		),
		'boolean' => array(
			'rename-login-page'         => array( 'disable_redirect' ),
			'login-notification'        => array( 'admin_only' ),
			'server-error-notification' => array( 'email_notification' ),
		),
		'bitflag' => array(
			'waf' => array( 'available_rules' ),
		),
		'internal' => array(
			'waf'           => array( 'send_at' ),
			'update-notice' => array( 'last_notice' ),
		),
	);

	public function __construct() {
		$this->init_plugin();
	}

	/**
	 * 共通の機能検証処理
	 *
	 * @param array $args コマンド引数
	 * @param bool  $check_config_excluded CONFIG_EXCLUDED_FEATURESのチェックを行うかどうか
	 * @return array 検証結果 ['success' => bool, 'error' => string, 'feature_name' => string, 'description' => string, 'feature_instance' => object] (success=trueの場合のみ後半3項目が有効)
	 */
	protected function validate_feature_arguments( $args, $check_config_excluded = true ) {
		// 利用可能な機能一覧を事前に計算（エラーメッセージで使用）
		$available_features = array_keys( self::FEATURE_MAP );
		if ( $check_config_excluded ) {
			$available_features = array_diff( $available_features, self::CONFIG_EXCLUDED_FEATURES );
		}

		// 引数が配列でない場合はエラー
		if ( ! is_array( $args ) ) {
			return array(
				'success' => false,
				'error'   => '引数が正しく渡されていません。',
			);
		}

		// 機能名が指定されていない、または空の場合はエラー
		if ( count( $args ) === 0 || empty( $args[0] ) ) {
			return array(
				'success' => false,
				'error'   => '機能名を指定してください。利用可能な機能: ' . implode( ', ', $available_features ),
			);
		}

		// 複数の機能名が指定されている場合はエラー
		if ( count( $args ) > 1 ) {
			return array(
				'success' => false,
				'error'   => '機能名は1つのみ指定してください。複数の機能を同時に操作することはできません。指定された引数: ' . implode( ', ', $args ),
			);
		}

		// 引数を文字列として取得
		$feature_name = (string) $args[0];

		// 機能名が存在するかチェック
		if ( ! isset( self::FEATURE_MAP[ $feature_name ] ) ) {
			return array(
				'success' => false,
				'error'   => "機能 '{$feature_name}' は存在しません。利用可能な機能: " . implode( ', ', $available_features ),
			);
		}

		// 設定値が存在しない機能を除外（必要な場合のみ）
		if ( $check_config_excluded && in_array( $feature_name, self::CONFIG_EXCLUDED_FEATURES, true ) ) {
			return array(
				'success' => false,
				'error'   => "機能 '{$feature_name}' は設定値が存在しないため、このコマンドでは操作できません。利用可能な機能: " . implode( ', ', $available_features ),
			);
		}

		// 機能の説明を取得
		$description = self::FEATURE_DESCRIPTIONS[ $feature_name ] ?? $feature_name;

		// 機能インスタンスを取得
		$feature_instance = $this->get_feature_instance( $feature_name );

		if ( ! $feature_instance ) {
			return array(
				'success' => false,
				'error'   => "機能 '{$feature_name}' ({$description}) のインスタンスを取得できませんでした。",
			);
		}

		return array(
			'success'          => true,
			'feature_name'     => $feature_name,
			'description'      => $description,
			'feature_instance' => $feature_instance,
		);
	}

	/**
	 * エラーレスポンスを出力して終了
	 *
	 * @param array $data エラーデータ
	 * @param int   $exit_code 終了コード（デフォルト: 1）
	 */
	protected function output_error_response( $data, $exit_code = 1 ) {
		$response = array(
			'result' => 'error',
			'data'   => $data,
		);
		WP_CLI::line( wp_json_encode( $response, JSON_UNESCAPED_UNICODE ) );
		exit( (int) $exit_code );
	}

	/**
	 * 成功レスポンスを出力して終了
	 *
	 * @param array $data レスポンスデータ
	 * @param int   $exit_code 終了コード（デフォルト: 0）
	 */
	protected function output_success_response( $data, $exit_code = 0 ) {
		WP_CLI::line( wp_json_encode( $data, JSON_UNESCAPED_UNICODE ) );
		exit( (int) $exit_code );
	}

	/**
	 * プラグインインスタンスを初期化
	 */
	protected function init_plugin() {
		global $cloudsecurewp;

		// メインプラグインのグローバルインスタンスが存在する場合はそれを使用
		if ( isset( $cloudsecurewp ) && is_object( $cloudsecurewp ) ) {
			WP_CLI::debug( 'CloudSecure WP プラグインのインスタンスを使用します。' );
			$this->plugin = $cloudsecurewp;
			return;
		}

		WP_CLI::debug( 'CloudSecure WP プラグインのインスタンスを新しく作成します。' );

		// 存在しない場合は新しく作成
		$plugin_file = dirname( __DIR__, 2 ) . '/cloudsecure-wp.php';

		// CloudSecureWPクラスが読み込まれていない場合は読み込み
		if ( ! class_exists( 'CloudSecureWP' ) ) {
			require_once dirname( __DIR__ ) . '/cloudsecure-wp.php';
		}

		$cloudsecurewp_info_datas = array(
			'version'     => 'Version',
			'plugin_name' => 'Plugin Name',
			'text_domain' => 'Text Domain',
		);

		$cloudsecurewp_info                = get_file_data( $plugin_file, $cloudsecurewp_info_datas );
		$cloudsecurewp_info['plugin_path'] = plugin_dir_path( $plugin_file );
		$cloudsecurewp_info['plugin_url']  = plugin_dir_url( $plugin_file );

		WP_CLI::debug( 'CloudSecure WP CLI - Plugin Info: ' . wp_json_encode( $cloudsecurewp_info ) );

		$this->plugin = new CloudSecureWP( $cloudsecurewp_info );
	}

	/**
	 * プラグイン機能インスタンスを取得
	 *
	 * @param string $feature_name
	 * @return object|null
	 */
	protected function get_feature_instance( $feature_name ) {
		if ( ! isset( self::FEATURE_MAP[ $feature_name ] ) ) {
			WP_CLI::warning( "機能 '{$feature_name}' がFEATURE_MAPに見つかりません" );
			return null;
		}

		$property_name = self::FEATURE_MAP[ $feature_name ];
		$getter_method = 'get_' . $property_name;

		WP_CLI::debug( "{$getter_method} の呼び出しを試行中" );

		// プラグインインスタンスの存在確認
		if ( ! $this->plugin ) {
			WP_CLI::warning( 'プラグインインスタンスが利用できません' );
			return null;
		}

		// CloudSecureWPクラスにgetterメソッドがある場合はそれを使用
		if ( method_exists( $this->plugin, $getter_method ) ) {
			try {
				return $this->plugin->$getter_method();
			} catch ( Exception $e ) {
				WP_CLI::warning( "{$getter_method} の呼び出しエラー: " . $e->getMessage() );
				return null;
			}
		} else {
			WP_CLI::warning( "getter メソッド '{$getter_method}' が見つかりません" );
			return null;
		}
	}

	/**
	 * 設定タイプを判定する統一メソッド
	 *
	 * @param string $type 判定したい設定タイプ (textarea|array|boolean|bitflag|internal)
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @return bool
	 */
	protected function is_setting_type( $type, $feature_name, $setting_key ) {
		if ( ! isset( self::SETTING_TYPES[ $type ] ) ) {
			return false;
		}

		$type_settings = self::SETTING_TYPES[ $type ];

		if ( ! isset( $type_settings[ $feature_name ] ) ) {
			return false;
		}

		return in_array( $setting_key, $type_settings[ $feature_name ], true );
	}

	/**
	 * テキストエリア設定かどうかを判定
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @return bool
	 */
	protected function is_textarea_setting( $feature_name, $setting_key ) {
		return $this->is_setting_type( 'textarea', $feature_name, $setting_key );
	}

	/**
	 * テキストエリア値を入力用形式に変換（プレースホルダー→実際の改行）
	 *
	 * @param string $text 変換対象のテキスト
	 * @return string 変換後のテキスト
	 */
	protected function convert_placeholder_to_textarea( $text ) {
		return str_replace( self::NEWLINE_PLACEHOLDER, "\n", $text );
	}

	/**
	 * テキストエリア値を表示用形式に変換（実際の改行→プレースホルダー）
	 *
	 * @param string $text 変換対象のテキスト
	 * @return string 変換後のテキスト
	 */
	protected function convert_textarea_to_placeholder( $text ) {
		return str_replace( array( "\r\n", "\n", "\r" ), self::NEWLINE_PLACEHOLDER, $text );
	}

	/**
	 * 配列設定かどうかを判定
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @return bool
	 */
	protected function is_array_setting( $feature_name, $setting_key ) {
		return $this->is_setting_type( 'array', $feature_name, $setting_key );
	}

	/**
	 * 配列値を入力用形式に変換（カンマ区切り文字列→配列）
	 *
	 * @param string $value カンマ区切り文字列
	 * @return array 変換後の配列
	 */
	protected function convert_string_to_array( $value ) {
		$array_values = explode( ',', $value );

		if ( ! is_array( $array_values ) ) {
			return array();
		}

		$validated_values = array();
		foreach ( $array_values as $val ) {
			// 空白を除去
			$val = preg_replace( '|\s|', '', $val );
			if ( ! empty( $val ) ) {
				$validated_values[] = $val;
			}
		}

		// 重複を除去
		$validated_values = array_unique( $validated_values );

		return array_values( $validated_values );
	}

	/**
	 * 配列値を表示用形式に変換（配列→カンマ区切り文字列）
	 *
	 * @param array $value 配列
	 * @return string 変換後のカンマ区切り文字列
	 */
	protected function convert_array_to_string( $value ) {
		// 配列でない場合は空文字列を返す
		if ( ! is_array( $value ) ) {
			return '';
		}

		// 空配列の場合は空文字列を返す
		if ( empty( $value ) ) {
			return '';
		}

		return implode( ',', $value );
	}

	/**
	 * boolean設定かどうかを判定
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @return bool
	 */
	protected function is_boolean_setting( $feature_name, $setting_key ) {
		return $this->is_setting_type( 'boolean', $feature_name, $setting_key );
	}

	/**
	 * boolean値を入力用形式に変換（1→t、0→f）
	 *
	 * @param string $value 入力値
	 * @return string 変換後の値
	 */
	protected function convert_display_to_boolean( $value ) {
		// 文字列として扱う
		$value = (string) $value;

		// 1 → t への変換
		if ( $value === '1' ) {
			return 't';
		}

		// 0 → f への変換
		if ( $value === '0' ) {
			return 'f';
		}

		// その他の値はそのまま返す
		return $value;
	}

	/**
	 * boolean値を表示用形式に変換（t→1、f→0）
	 *
	 * @param string $value 内部値
	 * @return string 変換後の値
	 */
	protected function convert_boolean_to_display( $value ) {
		// 文字列として扱う
		$value = (string) $value;

		// t → 1 への変換
		if ( $value === 't' ) {
			return '1';
		}

		// f → 0 への変換
		if ( $value === 'f' ) {
			return '0';
		}

		// その他の値はそのまま返す
		return $value;
	}

	/**
	 * ビットフラグ設定かどうかを判定
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @return bool
	 */
	protected function is_bitflag_setting( $feature_name, $setting_key ) {
		return $this->is_setting_type( 'bitflag', $feature_name, $setting_key );
	}

	/**
	 * ビットフラグ値を表示用形式に変換（ビット値→文字列配列）
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @param int    $bit_value ビット値
	 * @return array 文字列配列
	 */
	protected function convert_bitflag_to_strings( $feature_name, $setting_key, $bit_value ) {
		if ( $feature_name === 'waf' && $setting_key === 'available_rules' ) {
			$result = array();
			foreach ( self::WAF_ATTACK_TYPE_BITS as $string => $bit ) {
				if ( ( $bit_value & $bit ) > 0 ) {
					$result[] = $string;
				}
			}

			return $result;
		}

		return array();
	}

	/**
	 * ビットフラグ値を入力用形式に変換（文字列配列→ビット値）
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @param array  $strings 文字列配列
	 * @return int ビット値
	 */
	protected function convert_strings_to_bitflag( $feature_name, $setting_key, $strings ) {
		// 配列形式であることを確認
		if ( ! is_array( $strings ) ) {
			return 0;
		}

		if ( $feature_name === 'waf' && $setting_key === 'available_rules' ) {
			$result = 0;
			foreach ( $strings as $attack_type ) {
				if ( isset( self::WAF_ATTACK_TYPE_BITS[ $attack_type ] ) ) {
					$result |= self::WAF_ATTACK_TYPE_BITS[ $attack_type ];
				}
			}

			return $result;
		}

		return 0;
	}

	/**
	 * 内部設定（ユーザーが直接設定すべきでない）かどうかを判定
	 *
	 * @param string $feature_name
	 * @param string $setting_key
	 * @return bool
	 */
	protected function is_internal_setting( $feature_name, $setting_key ) {
		return $this->is_setting_type( 'internal', $feature_name, $setting_key );
	}

	/**
	 * WordPress管理画面と同様のサニタイズ処理を適用
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @param mixed  $value 設定値
	 * @return mixed サニタイズ済み設定値
	 */
	protected function sanitize_setting_value( $feature_name, $setting_key, $value ) {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'sanitize_text_field' ) || ! function_exists( 'sanitize_textarea_field' ) ) {
			// WordPress環境でない場合はそのまま返す
			return $value;
		}

		// テキストエリア設定の場合（bodyのみ）
		if ( $this->is_textarea_setting( $feature_name, $setting_key ) ) {
			return stripslashes( sanitize_textarea_field( $value ) );
		}

		// 配列設定やビットフラグ設定も含め、その他の設定は通常のテキストフィールドとして処理
		return sanitize_text_field( $value );
	}

	/**
	 * 設定値を表示用形式に変換
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @param string $value 設定値
	 * @return string 変換後の値
	 */
	protected function normalize_value_for_display( $feature_name, $setting_key, $value ) {
		// boolean設定の場合、t→1、f→0に変換
		if ( $this->is_boolean_setting( $feature_name, $setting_key ) ) {
			return $this->convert_boolean_to_display( $value );
		}

		// ビットフラグ設定の場合、文字列配列に変換してカンマ区切りで返す
		if ( $this->is_bitflag_setting( $feature_name, $setting_key ) ) {
			$strings = $this->convert_bitflag_to_strings( $feature_name, $setting_key, (int) $value );
			return implode( ',', $strings );
		}

		// その他の設定はそのまま返す
		return $value;
	}

	/**
	 * 設定値を入力用形式に変換
	 *
	 * @param string $feature_name 機能名
	 * @param string $setting_key 設定キー
	 * @param mixed  $value 入力値（文字列または配列）
	 * @return mixed 変換後の値
	 */
	protected function normalize_value_for_input( $feature_name, $setting_key, $value ) {
		// boolean設定の場合、1→t、0→fに変換
		if ( $this->is_boolean_setting( $feature_name, $setting_key ) ) {
			return $this->convert_display_to_boolean( $value );
		}

		// ビットフラグ設定の場合、配列をビット値に変換
		if ( $this->is_bitflag_setting( $feature_name, $setting_key ) ) {
			return (string) $this->convert_strings_to_bitflag( $feature_name, $setting_key, $value );
		}

		// その他の設定はそのまま返す
		return $value;
	}

	/**
	 * 特別な設定（WordPressオプション）を取得して正規化する
	 *
	 * @param string $feature_name 機能名
	 * @param array  $configuration 設定配列（参照渡し）
	 * @return void
	 */
	protected function add_special_configuration_settings( $feature_name, &$configuration ) {
		// 2段階認証の特別な設定
		if ( $feature_name === 'two-factor-authentication' ) {
			$this->add_two_factor_authentication_settings( $configuration );
		}

		// サーバーエラー通知の特別な設定
		if ( $feature_name === 'server-error-notification' ) {
			$this->add_server_error_notification_settings( $feature_name, $configuration );
		}
	}

	/**
	 * 2段階認証の特別な設定を追加
	 *
	 * @param array $configuration 設定配列（参照渡し）
	 * @return void
	 */
	private function add_two_factor_authentication_settings( &$configuration ) {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'wp_roles' ) || ! function_exists( 'get_option' ) ) {
			return;
		}

		$wp_roles = wp_roles();
		if ( ! $wp_roles || ! isset( $wp_roles->roles ) ) {
			return;
		}

		$all_roles                      = array_keys( $wp_roles->roles );
		$enabled_roles                  = get_option( self::WORDPRESS_OPTION_NAMES['TWO_FACTOR_ROLES'], $all_roles );
		$configuration['enabled_roles'] = implode( ',', $enabled_roles );

		// ユーザーの認証キー登録状況を取得（statusコマンドの場合）
		$configuration['user_registrations'] = $this->get_two_factor_user_registrations();
	}

	/**
	 * 2段階認証のユーザー登録状況を取得
	 *
	 * @return string
	 */
	protected function get_two_factor_user_registrations() {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'get_users' ) ) {
			return '';
		}

		$users         = get_users();
		$registrations = array();

		// 2段階認証機能のインスタンスを取得
		$two_factor_instance = $this->get_feature_instance( 'two-factor-authentication' );

			foreach ( $users as $user ) {
				if ( $two_factor_instance && method_exists( $two_factor_instance, 'show_2factor_state_2user_list' ) ) {
					$status = $two_factor_instance->show_2factor_state_2user_list( '', 'is_2factor', $user->ID );

					// "設定済"→1、"未設定"→0 で出力
					$status_num      = ( $status === '設定済' ) ? '1' : '0';
					$registrations[] = $user->user_login . ':' . $status_num;
				}
			}

		return implode( ',', $registrations );
	}

	/**
	 * サーバーエラー通知の特別な設定を追加
	 *
	 * @param string $feature_name 機能名
	 * @param array  $configuration 設定配列（参照渡し）
	 * @return void
	 */
	private function add_server_error_notification_settings( $feature_name, &$configuration ) {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'get_option' ) ) {
			return;
		}

		$enable_email_server_error_notification = get_option( self::WORDPRESS_OPTION_NAMES['SERVER_ERROR_EMAIL'], 't' );
		// boolean値の表示用正規化（t→1、f→0）
		$enable_email_server_error_notification = $this->normalize_value_for_display( $feature_name, 'email_notification', $enable_email_server_error_notification );
		$configuration['email_notification']    = $enable_email_server_error_notification;
	}

}
