<?php
/**
 * CloudSecure WP Security Enable Command
 * 機能の有効化用のコマンドクラス
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
 * CloudSecure WP Security Enable Command
 * 機能の有効化専用のコマンドクラス
 */
class CloudSecureWP_CLI_Enable extends CloudSecureWP_CLI_Base {

	/**
	 * @var array 現在処理中の機能情報
	 */
	private $current_feature = array();

	/**
	 * @var array 表示用設定項目
	 */
	private $available_display_keys = null;

	/**
	 * @var string WordPressロールバリデーション用エラーメッセージ
	 */
	private $wordpress_roles_error_message;

	/**
	 * 機能を有効化する
	 *
	 * ## EXAMPLES
	 * wp cldsec-wp-security enable disable-login
	 * wp cldsec-wp-security enable disable-login --interval=5 --duration=60
	 * wp cldsec-wp-security enable restrict-admin-page --paths="css,images"
	 * wp cldsec-wp-security enable login-notification --body="ログインしました__CLDSEC_NEWLINE__日時: {$date}"
	 *
	 * ## OPTIONS
	 * <feature> : 有効化する機能名（必須）
	 * [--<setting>=<value>] : 設定値（オプション）
	 *
	 * @param array $args 位置引数
	 * @param array $assoc_args 関連配列引数
	 */
	public function __invoke( $args = array(), $assoc_args = array() ) {
		try {
			// 共通の機能検証処理
			$validation_result = $this->validate_feature_arguments( $args, true );

			if ( ! $validation_result['success'] ) {
				$this->output_error_response( array( 'message' => $validation_result['error'] ) );
				return;
			}

			// 機能情報を配列にまとめて格納
			$this->current_feature = array(
				'name'        => $validation_result['feature_name'],
				'instance'    => $validation_result['feature_instance'],
				'description' => $validation_result['description'],
				'key'         => $validation_result['feature_instance']->get_feature_key(),
				'valid_keys'  => $this->get_valid_keys( $validation_result['feature_instance'], $validation_result['feature_name'] ),
			);

			// 表示用設定項目を生成
			$this->available_display_keys = $this->get_available_display_keys();

			// 現在の設定値を取得し新しい設定値を準備
			$current_settings = $this->current_feature['instance']->get_settings();
			$new_settings     = $current_settings;

			// 機能を有効化
			$new_settings[ $this->current_feature['key'] ] = 't';

			// 追加設定値を処理
			if ( ! empty( $assoc_args ) ) {
				// 1. 設定項目の存在確認
				$validation_result = $this->validate_setting_keys( $assoc_args );
				if ( ! $validation_result['success'] ) {
					$this->output_error_response( array( 'message' => $validation_result['error'] ) );
					return;
				}

				// 2. 設定値のバリデーション
				$validation_result = $this->validate_setting_values( $assoc_args );
				if ( ! $validation_result['success'] ) {
					$this->output_error_response( array( 'message' => $validation_result['error'] ) );
					return;
				}

				// 3. 設定値を変換して新しい設定値を作成
				$converted_settings = $this->convert_settings_for_storage( $validation_result['processed_settings'] );

				// 検証済みの設定値をマージ
				$new_settings = array_merge( $new_settings, $converted_settings );
			}

			// 設定を保存
			$activation_result = $this->activate_feature( $new_settings, $current_settings );

			if ( $activation_result['success'] ) {
				// 有効化後の設定値を取得
				$updated_settings = $this->current_feature['instance']->get_settings();
				$enabled          = isset( $updated_settings[ $this->current_feature['key'] ] ) && $updated_settings[ $this->current_feature['key'] ] === 't';
				$status           = $enabled ? 'enabled' : 'disabled';
				$configuration    = array();
				foreach ( $updated_settings as $key => $value ) {
					if ( $key !== $this->current_feature['key'] ) {
						$display_key = $this->storage_key_to_display_key( $key );

						// 内部設定は除外
						if ( $this->is_internal_setting( $this->current_feature['name'], $display_key ) ) {
							continue;
						}

						// テキストエリア内容の改行コード変換
						if ( $this->is_textarea_setting( $this->current_feature['name'], $display_key ) ) {
							$value = $this->convert_textarea_to_placeholder( $value );
						}

						// 表示用の値を正規化（boolean: t→1, f→0、ビットフラグ: 63→sql,xss,command,code,mail）
						$value = $this->normalize_value_for_display( $this->current_feature['name'], $display_key, $value );

						$configuration[ $display_key ] = $value;
					}
				}

				// 特別な設定を追加（WordPressオプションを使用するものと２段階認証のユーザー設定状況）
				$this->add_special_configuration_settings( $this->current_feature['name'], $configuration );

				// 成功メッセージを生成
				$success_message = $this->generate_success_message( $new_settings );

				// 成功レスポンス
				$response_data = array(
					'result' => 'success',
					'data'   => array(
						'message'       => $success_message,
						'status'        => $status,
						'configuration' => $configuration,
					),
				);

				$this->output_success_response( $response_data );
			} else {
				$this->output_error_response(
					array(
						'message'       => "機能 '{$this->current_feature['name']}' ({$this->current_feature['description']}) の有効化に失敗しました。",
						'error_details' => $activation_result['error'] ?? '詳細不明',
					)
				);
			}
		} catch ( Exception $e ) {
			$this->output_error_response( array( 'message' => 'コマンド実行中にエラーが発生しました: ' . $e->getMessage() ) );
		}
	}

	/**
	 * 機能インスタンスから有効な設定キーを取得
	 *
	 * @param object $feature_instance 機能インスタンス
	 * @param string $feature_name 機能名
	 * @return array 有効な設定キーの配列
	 */
	private function get_valid_keys( $feature_instance, $feature_name ) {
		$valid_keys = array_keys( $feature_instance->get_default() );

		// 特別処理が必要な機能の場合のみ特別なキーを追加
		if ( in_array( $feature_name, self::SPECIAL_PROCESSING_FEATURES, true ) ) {
			switch ( $feature_name ) {
				case 'two-factor-authentication':
					$valid_keys[] = 'enabled_roles';
					break;

				case 'server-error-notification':
					$valid_keys[] = 'email_notification';
					break;
			}
		}

		return $valid_keys;
	}

	/**
	 * 表示用の利用可能設定項目一覧を生成
	 *
	 * @return array
	 */
	private function get_available_display_keys() {
		$available_keys = array();
		foreach ( $this->current_feature['valid_keys'] as $valid_key ) {

			if ( $valid_key !== $this->current_feature['key'] ) { // 機能キー自体は除外
				$display_key = $this->storage_key_to_display_key( $valid_key );

				// 内部設定は除外
				if ( ! $this->is_internal_setting( $this->current_feature['name'], $display_key ) ) {
					$available_keys[] = $display_key;
				}
			}
		}

		return $available_keys;
	}

	/**
	 * 表示用キーから保存用キーに変換
	 *
	 * @param string $display_key 表示用キー（例: 'interval'）
	 * @return string 保存用キー（例: 'cloudsecurewp_disable_login_interval'）
	 */
	private function display_key_to_storage_key( $display_key ) {
		// 特別設定の場合はそのまま返す
		if ( $this->is_special_setting_key( $display_key ) ) {
			return $display_key;
		}

		// 通常設定の場合は機能プレフィックスを付加
		return $this->current_feature['key'] . '_' . $display_key;
	}

	/**
	 * 保存用キーから表示用キーに変換
	 *
	 * @param string $storage_key 保存用キー（例: 'cloudsecurewp_disable_login_interval'）
	 * @return string 表示用キー（例: 'interval'）
	 */
	private function storage_key_to_display_key( $storage_key ) {
		// 特別設定の場合はそのまま返す
		if ( $this->is_special_setting_key( $storage_key ) ) {
			return $storage_key;
		}

		// 通常設定の場合は機能プレフィックスを除去
		$prefix = $this->current_feature['key'] . '_';

		if ( strpos( $storage_key, $prefix ) === 0 ) {
			return substr( $storage_key, strlen( $prefix ) );
		}

		return $storage_key;
	}

	/**
	 * 特別設定キーかどうかを判定
	 *
	 * @param string $key 設定キー
	 * @return bool 特別設定の場合true
	 */
	private function is_special_setting_key( $key ) {
		return in_array( $key, array_values( self::SPECIAL_SETTING_KEYS ), true );
	}

	/**
	 * 設定項目の存在確認
	 *
	 * @param array $input_settings 入力された設定値
	 * @return array バリデーション結果
	 */
	private function validate_setting_keys( $input_settings ) {
		foreach ( $input_settings as $key => $value ) {
			// 機能の設定情報と比較のため保存用キーに変換
			$target_key = $this->display_key_to_storage_key( $key );

			// 有効な設定キーかチェック
			if ( ! in_array( $target_key, $this->current_feature['valid_keys'], true ) ) {
				$available_list = empty( $this->available_display_keys ) ? 'なし' : implode( ', ', $this->available_display_keys );

				return array(
					'success' => false,
					'error'   => "機能 '{$this->current_feature['name']}' には設定項目 '{$key}' は存在しません。利用可能な設定項目: {$available_list}",
				);
			}
		}

		return array( 'success' => true );
	}

	/**
	 * 設定値のバリデーション
	 *
	 * @param array $input_settings 入力された設定値
	 * @return array バリデーション結果（成功時は処理済み設定値も含む）
	 */
	private function validate_setting_values( $input_settings ) {
		$processed_settings = array();

		foreach ( $input_settings as $key => $value ) {
			$converted_value = (string) $value;

			// WordPress管理画面と同様のサニタイズ処理を適用
			$converted_value = $this->sanitize_setting_value( $this->current_feature['name'], $key, $converted_value );

			// 改行コードの変換
			if ( $this->is_textarea_setting( $this->current_feature['name'], $key ) ) {
				$converted_value = $this->convert_placeholder_to_textarea( $converted_value );
			}

			// 配列系設定の処理
			if ( $this->is_array_setting( $this->current_feature['name'], $key ) || $this->is_bitflag_setting( $this->current_feature['name'], $key ) ) {
				$converted_value = $this->convert_string_to_array( $converted_value );
			}

			// バリデーション実行
			$validation_result = $this->validate_setting_value( $key, $converted_value );
			if ( ! $validation_result['success'] ) {
				return array(
					'success' => false,
					'error'   => $validation_result['error'],
				);
			}

			// 処理済み設定値を保存
			$processed_settings[ $key ] = $converted_value;
		}

		return array(
			'success'            => true,
			'processed_settings' => $processed_settings,
		);
	}

	/**
	 * 設定値を保存用形式に変換
	 *
	 * @param array $processed_settings 処理済み設定値
	 * @return array 変換済み設定値
	 */
	private function convert_settings_for_storage( $processed_settings ) {
		$converted_settings = array();

		foreach ( $processed_settings as $key => $value ) {
			if ( $this->is_special_setting_key( $key ) ) {
				$converted_value            = $this->normalize_value_for_input( $this->current_feature['name'], $key, $value );
				$converted_settings[ $key ] = $converted_value;

			} else {
				// 通常設定の場合は機能プレフィックスを付加
				$full_key                        = $this->display_key_to_storage_key( $key );
				$converted_value                 = $this->normalize_value_for_input( $this->current_feature['name'], $key, $value );
				$converted_settings[ $full_key ] = $converted_value;
			}
		}

		return $converted_settings;
	}

	/**
	 * 機能を有効化する
	 *
	 * @param array $settings 新しい設定値
	 * @param array $old_data 元の設定値（ロールバック用）
	 * @return array 実行結果
	 */
	private function activate_feature( $settings, $old_data ) {
		try {
			// 設定を保存
			if ( method_exists( $this->current_feature['instance'], 'save_settings' ) ) {
				$this->current_feature['instance']->save_settings( $settings );
			} else {
				return array(
					'success' => false,
					'error'   => 'save_settingsメソッドが見つかりません。',
				);
			}

			// htaccessを使用する機能の場合は更新処理を実行
			if ( in_array( $this->current_feature['name'], self::HTACCESS_FEATURES, true ) ) {
				$update_result = $this->handle_htaccess_feature_activation( $settings, $old_data );
				if ( ! $update_result['success'] ) {
					return $update_result;
				}
			}

			// 特別なWordPressオプション保存が必要な機能の場合のみ実行
			if ( in_array( $this->current_feature['name'], self::SPECIAL_PROCESSING_FEATURES, true ) ) {
				$special_result = $this->handle_special_feature_settings( $settings, $old_data );
				if ( ! $special_result['success'] ) {
					return array(
						'success' => false,
						'error'   => $special_result['error'],
					);
				}
			}

			return array(
				'success' => true,
			);

		} catch ( Exception $e ) {
			return array(
				'success' => false,
				'error'   => $e->getMessage(),
			);
		}
	}

	/**
	 * htaccess使用機能の有効化処理
	 *
	 * @param array $settings 新しい設定値
	 * @param array $old_data 古い設定値
	 * @return array 実行結果
	 */
	private function handle_htaccess_feature_activation( $settings, $old_data ) {
		try {
			switch ( $this->current_feature['name'] ) {
				case 'restrict-admin-page':
					if ( method_exists( $this->current_feature['instance'], 'update' ) ) {
						if ( ! $this->current_feature['instance']->update() ) {
							$this->rollback_settings( $old_data );
							return array(
								'success' => false,
								'error'   => 'htaccessの更新に失敗しました。機能を無効にしました。',
							);
						}
					}
					break;

				case 'rename-login-page':
					if ( method_exists( $this->current_feature['instance'], 'update_htaccess' ) ) {
						if ( ! $this->current_feature['instance']->update_htaccess() ) {
							$this->rollback_settings( $old_data );
							return array(
								'success' => false,
								'error'   => 'htaccessの更新に失敗しました。機能を無効にしました。',
							);
						}
					}
					break;

				case 'disable-xmlrpc':
					$type_key = $this->current_feature['key'] . '_type';

					if ( ! isset( $settings[ $type_key ] ) ) {
						$this->rollback_settings( $old_data );
						return array(
							'success' => false,
							'error'   => 'XML-RPC無効化機能の無効化タイプ設定が見つかりません。',
						);
					}

					$type_value = $settings[ $type_key ];

					if ( $type_value === '1' ) {
						if ( method_exists( $this->current_feature['instance'], 'remove_htaccess' ) ) {
							if ( ! $this->current_feature['instance']->remove_htaccess() ) {
								$this->rollback_settings( $old_data );
								return array(
									'success' => false,
									'error'   => 'htaccessの更新に失敗しました。機能を無効にしました。',
								);
							}
						}
					} elseif ( $type_value === '2' ) {
						if ( method_exists( $this->current_feature['instance'], 'update_htaccess' ) ) {
							if ( ! $this->current_feature['instance']->update_htaccess() ) {
								$this->rollback_settings( $old_data );
								return array(
									'success' => false,
									'error'   => 'htaccessの更新に失敗しました。機能を無効にしました。',
								);
							}
						}
					}
					break;
			}

			return array( 'success' => true );

		} catch ( Exception $e ) {
			$this->rollback_settings( $old_data );
			return array(
				'success' => false,
				'error'   => 'htaccess更新中にエラーが発生しました: ' . $e->getMessage() . ' 機能を無効にしました。',
			);
		}
	}

	/**
	 * 設定のロールバック処理（機能を無効化）
	 *
	 * @param array $old_data 元の設定値
	 */
	private function rollback_settings( $old_data ) {
		try {
			// 機能を無効にした設定値を作成
			$disabled_settings                                  = $old_data;
			$disabled_settings[ $this->current_feature['key'] ] = 'f';

			$this->current_feature['instance']->save_settings( $disabled_settings );
		} catch ( Exception $e ) {
			// ロールバック中にエラーが発生した場合は警告として出力
			WP_CLI::warning( 'ロールバック中にエラーが発生しました: ' . $e->getMessage() );
		}
	}

	/**
	 * 特別な機能の設定処理
	 *
	 * @param array $settings
	 * @param array $old_data 元の設定値（ロールバック用）
	 * @return array 処理結果
	 */
	private function handle_special_feature_settings( $settings, $old_data ) {
		// 特別設定を抽出
		$special_settings = $this->process_special_settings( $settings );

		// 特別設定をWordPressオプションとして保存
		if ( ! empty( $special_settings ) ) {
			$save_results = $this->save_special_settings( $special_settings );

			// 失敗した設定があるかチェック
			$failed_settings = array();
			foreach ( $save_results as $key => $result ) {
				if ( ! $result['success'] ) {
					$failed_settings[] = $key . ': ' . $result['message'];
				}
			}

			if ( ! empty( $failed_settings ) ) {
				// htaccess処理と同様に機能を無効化
				$this->rollback_settings( $old_data );
				return array(
					'success' => false,
					'error'   => '設定の保存に失敗しました。機能を無効にしました: ' . implode( ', ', $failed_settings ),
				);
			}
		}

		return array( 'success' => true );
	}

	/**
	 * 特別設定値をWordPressオプションとして保存
	 *
	 * @param array $special_settings 特別設定の配列
	 * @return array 保存結果の配列
	 */
	private function save_special_settings( $special_settings ) {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'update_option' ) ) {
			$results = array();
			foreach ( $special_settings as $key => $value ) {
				$results[ $key ] = array(
					'success' => false,
					'message' => 'update_option関数が利用できません',
				);
			}
			return $results;
		}

		$option_mapping = array(
			self::SPECIAL_SETTING_KEYS['TWO_FACTOR_ENABLED_ROLES'] => self::WORDPRESS_OPTION_NAMES['TWO_FACTOR_ROLES'],
			self::SPECIAL_SETTING_KEYS['TWO_FACTOR_USER_REGISTRATIONS'] => self::WORDPRESS_OPTION_NAMES['TWO_FACTOR_REGISTRATIONS'],
			self::SPECIAL_SETTING_KEYS['SERVER_ERROR_EMAIL_NOTIFICATION'] => self::WORDPRESS_OPTION_NAMES['SERVER_ERROR_EMAIL'],
		);

		$results = array();

		foreach ( $special_settings as $key => $value ) {
			if ( ! isset( $option_mapping[ $key ] ) ) {
				$results[ $key ] = array(
					'success' => false,
					'message' => "未知の特別設定キー: {$key}",
				);
				continue;
			}

			$option_name = $option_mapping[ $key ];

			// 現在の値を事前にチェック
			$current_value = get_option( $option_name, null );
			if ( $current_value === $value ) {
				// 値が同じ場合はupdate_optionを実行せずに成功として扱う
				$results[ $key ] = array(
					'success' => true,
					'message' => "WordPressオプション '{$option_name}' は既に設定済みです",
				);
				continue;
			}

			// 値が異なる場合のみupdate_optionを実行
			$result = update_option( $option_name, $value );

			if ( $result !== false ) {
				$results[ $key ] = array(
					'success' => true,
					'message' => "WordPressオプション '{$option_name}' を更新しました",
				);

			} else {
				$results[ $key ] = array(
					'success' => false,
					'message' => "WordPressオプション '{$option_name}' の更新に失敗しました",
				);
			}
		}

		return $results;
	}

	/**
	 * 特別設定の処理を実行
	 *
	 * @param array $settings バリデーション済みの設定値
	 * @return array 特別設定値の配列
	 */
	private function process_special_settings( $settings ) {
		$special_settings = array();

		foreach ( $settings as $key => $value ) {
			if ( in_array( $key, array_values( self::SPECIAL_SETTING_KEYS ), true ) ) {
				$special_settings[ $key ] = $value;
			}
		}

		return $special_settings;
	}

	/**
	 * 設定値のバリデーション
	 *
	 * @param string $setting_key 設定キー
	 * @param mixed  $value 設定値
	 * @return array バリデーション結果
	 */
	private function validate_setting_value( $setting_key, $value ) {
		// カスタムロジックが必要なバリデーション
		$custom_rules = $this->get_custom_validation_rules( $setting_key );

		if ( $custom_rules ) {
			return $this->apply_validation_rule( $custom_rules, $value );
		}

		// 機能インスタンスから定数設定を使用したバリデーション
		if ( method_exists( $this->current_feature['instance'], 'get_constant_settings' ) ) {
			$constant_rules = $this->get_constant_based_validation_rules( $setting_key );
			if ( $constant_rules ) {
				return $this->apply_validation_rule( $constant_rules, $value );
			}
		}

		WP_CLI::debug( "No specific validation rules for setting '{$setting_key}'. Skipping validation." );

		// どちらにも該当しない場合は成功
		return array( 'success' => true );
	}

	/**
	 * 定数設定に基づくバリデーションルールを取得
	 *
	 * @param string $setting_key
	 * @return array|null
	 */
	private function get_constant_based_validation_rules( $setting_key ) {
		$constant_settings = $this->current_feature['instance']->get_constant_settings();
		$full_key          = $this->display_key_to_storage_key( $setting_key );

		if ( isset( $constant_settings[ $full_key ] ) && is_array( $constant_settings[ $full_key ] ) ) {
			// 許可値を文字列型に変換（コマンドライン入力は文字列のため）
			$allowed_values = array_map( 'strval', $constant_settings[ $full_key ] );

			return array(
				'type'           => 'select',
				'allowed_values' => $allowed_values,
				'error_message'  => "{$setting_key}は次のいずれかの値を指定してください: " . implode( ', ', $allowed_values ),
			);
		}

		return null;
	}

	/**
	 * カスタムロジックが必要なバリデーションルールを取得
	 *
	 * @param string $setting_key
	 * @return array|null
	 */
	private function get_custom_validation_rules( $setting_key ) {
		$static_rules = array(
			'rename-login-page' => array(
				'name' => array(
					'type'          => 'custom',
					'validator'     => 'validate_login_name',
					'error_message' => '変更後のログインURLは半角英小文字、半角数字、ハイフン、アンダースコアのいずれかを使用し、4文字以上12文字以下で指定してください。',
				),
				'disable_redirect' => array(
					'type'           => 'select',
					'allowed_values' => array( '0', '1' ),
					'error_message'  => 'リダイレクト設定には 0 または 1 のいずれかの値を指定してください。',
				),
			),
			'login-notification' => array(
				'admin_only' => array(
					'type'           => 'select',
					'allowed_values' => array( '0', '1' ),
					'error_message'  => '受信者設定には 0 または 1 のいずれかの値を指定してください。',
				),
			),
			'server-error-notification' => array(
				'email_notification' => array(
					'type'           => 'select',
					'allowed_values' => array( '0', '1' ),
					'error_message'  => '通知設定には 0 または 1 のいずれかの値を指定してください。',
				),
			),
			'two-factor-authentication' => array(
				'enabled_roles' => array(
					'type'          => 'custom',
					'validator'     => 'validate_wordpress_roles',
					'error_message' => '2段階認証が有効な権限グループには有効なWordPressユーザー権限を指定してください。',
				),
			),
			'waf' => array(
				'available_rules' => array(
					'type'          => 'custom',
					'validator'     => 'validate_waf_bitflag_strings',
					'error_message' => '検知する攻撃種別には有効な攻撃タイプを指定してください。利用可能な値: ' . implode( ', ', self::WAF_ATTACK_TYPES ),
				),
			),
		);

		if ( isset( $static_rules[ $this->current_feature['name'] ][ $setting_key ] ) ) {
			return $static_rules[ $this->current_feature['name'] ][ $setting_key ];
		}

		return null;
	}

	/**
	 * バリデーションルールを適用
	 *
	 * @param array $rule
	 * @param mixed $value
	 * @return array
	 */
	private function apply_validation_rule( $rule, $value ) {
		switch ( $rule['type'] ) {
			case 'select':
				if ( ! in_array( $value, $rule['allowed_values'], true ) ) {
					return array(
						'success' => false,
						'error'   => $rule['error_message'],
					);
				}
				break;

			case 'custom':
				if ( isset( $rule['validator'] ) && method_exists( $this, $rule['validator'] ) ) {
					$validator_method = $rule['validator'];
					if ( ! $this->$validator_method( $value ) ) {
						// WordPressロールバリデーションの場合、カスタムエラーメッセージを使用
						if ( $validator_method === 'validate_wordpress_roles' && ! empty( $this->wordpress_roles_error_message ) ) {
							$error_message                       = $this->wordpress_roles_error_message;
							$this->wordpress_roles_error_message = null; // リセット
						} else {
							$error_message = $rule['error_message'];
						}

						return array(
							'success' => false,
							'error'   => $error_message,
						);
					}
				}
				break;
		}

		return array( 'success' => true );
	}

	/**
	 * ログインページ名のバリデーション
	 *
	 * @param string $name
	 * @return bool
	 */
	private function validate_login_name( $name ) {
		// 4文字以上12文字以下
		if ( strlen( $name ) < 4 || strlen( $name ) > 12 ) {
			return false;
		}

		// 半角英小文字、半角数字、ハイフン、アンダースコアのみ
		if ( ! preg_match( '/^[a-z0-9_-]+$/', $name ) ) {
			return false;
		}

		return true;
	}

	/**
	 * WordPressロールのバリデーション
	 *
	 * @param array $roles
	 * @return bool
	 */
	private function validate_wordpress_roles( $roles ) {
		// WordPress関数の存在チェック
		if ( ! function_exists( 'wp_roles' ) ) {
			$this->wordpress_roles_error_message = 'wp_roles関数が利用できません';
			return false;
		}

		// WordPressから動的にロール一覧を取得（管理画面と同様の処理）
		$wp_roles_obj = wp_roles();
		if ( ! $wp_roles_obj || ! isset( $wp_roles_obj->roles ) ) {
			$this->wordpress_roles_error_message = 'WordPressロール情報を取得できませんでした';
			return false;
		}

		$valid_roles = array_keys( $wp_roles_obj->roles );

		// 配列でない場合は単一値として扱う
		if ( ! is_array( $roles ) ) {
			$roles = array( $roles );
		}

		// 各ロールが有効かチェック
		foreach ( $roles as $role ) {
			if ( ! in_array( $role, $valid_roles, true ) ) {
				// 無効なロールが見つかった場合、エラーメッセージに有効なロール一覧を含める
				$this->wordpress_roles_error_message = 'enabled_rolesには有効なWordPressユーザー権限を指定してください。有効な権限: ' . implode( ', ', $valid_roles ) . "。無効な値: {$role}";
				return false;
			}
		}

		return true;
	}

	/**
	 * WAFビットフラグ文字列のバリデーション
	 *
	 * @param array $value
	 * @return bool
	 */
	private function validate_waf_bitflag_strings( $value ) {
		// 配列でない場合は無効
		if ( ! is_array( $value ) ) {
			return false;
		}

		// 空配列の場合は有効（0値として扱う）
		if ( empty( $value ) ) {
			return true;
		}

		// 各文字列が有効かチェック
		foreach ( $value as $string ) {
			if ( ! empty( $string ) && ! in_array( $string, self::WAF_ATTACK_TYPES, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * 成功メッセージを生成する
	 *
	 * @param array $settings 設定値
	 * @return string 成功メッセージ
	 */
	private function generate_success_message( array $settings ): string {
		// disable-xmlrpcの場合は特別処理
		if ( $this->current_feature['name'] === 'disable-xmlrpc' ) {
			return $this->generate_disable_xmlrpc_message( $settings );
		}

		// その他の機能は統一フォーマット
		return $this->current_feature['description'] . '機能が有効になりました。';
	}

	/**
	 * disable-xmlrpc機能の成功メッセージを生成する
	 *
	 * @param array $settings 設定値
	 * @return string 成功メッセージ
	 */
	private function generate_disable_xmlrpc_message( array $settings ): string {
		// disable-xmlrpc機能インスタンスから定数設定を取得
		if ( method_exists( $this->current_feature['instance'], 'get_constant_settings' ) ) {
			$constant_settings   = $this->current_feature['instance']->get_constant_settings();
			$full_type_key       = $this->current_feature['key'] . '_type';
			$disable_xmlrpc_type = $settings[$full_type_key] ?? '';

			// 無効化種別に応じてメッセージを分岐
			if ( isset( $constant_settings['disable_xmlrpc_type'] ) ) {
				$type_values = $constant_settings['disable_xmlrpc_type'];

				if ( $disable_xmlrpc_type === $type_values[0] ) {
					// ピンバック無効
					return 'ピンバック無効化機能が有効になりました。';
				} elseif ( $disable_xmlrpc_type === $type_values[1] ) {
					// XML-RPC無効
					return 'XML-RPC無効化機能が有効になりました。';
				}
			}
		}

		return $this->current_feature['description'] . '機能が有効になりました。';
	}
}
