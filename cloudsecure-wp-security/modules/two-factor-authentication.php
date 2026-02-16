<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Two_Factor_Authentication extends CloudSecureWP_Common {
	private const KEY_FEATURE              = 'two_factor_authentication';
	private const OPTION_PREFIX            = 'cloudsecurewp_2fa_data_';
	private const SESSION_EXPIRY           = 300;
	private const CLEANUP_TIMEOUT          = 60;
	private const CLEANUP_BATCH_SIZE       = 1000;
	private const LOGIN_TABLE_NAME         = 'cloudsecurewp_2fa_login';
	private const AUTH_TABLE_NAME          = 'cloudsecurewp_2fa_auth';
	private const LATE_LIMIT_TIME_LIST     = array(
		3  => 60,  // 3回で1分間
		6  => 300, // 6回で5分間
		9  => 600, // 9回で10分間
		12 => 900, // 12回で15分間
	);
	private const LATE_LIMIT_TIME_MAX      = 1200; // 最大20分間
	public const USER_AUTH_METHOD_NONE     = 0;
	public const USER_AUTH_METHOD_APP      = 1;
	public const USER_AUTH_METHOD_EMAIL    = 2;
	public const USER_AUTH_METHOD_RECOVERY = 3;
	public const AUTH_APP_INTERVAL         = 30;
	public const AUTH_EMAIL_INTERVAL       = 60;
	public const TWO_FACTOR_SECRET_KEY     = 'wp_cloudsecurewp_two_factor_authentication_secret';
	public const TWO_FACTOR_EMAIL_SEND     = 'wp_cloudsecurewp_two_factor_authentication_email_send';
	public const EMAIL_SEND_LIMIT_TIME     = 30;

	private $config;

	/**
	 * @var CloudSecureWP_Disable_Login
	 */
	private $disable_login;

	/**
	 * @var CloudSecureWP_Login_Log
	 */
	private $login_log;

	function __construct( array $info, CloudSecureWP_Config $config, CloudSecureWP_Disable_Login $disable_login, CloudSecureWP_Login_Log $login_log ) {
		parent::__construct( $info );
		$this->config        = $config;
		$this->disable_login = $disable_login;
		$this->login_log     = $login_log;
	}

	/**
	 * 機能毎のKEY取得
	 *
	 * @return string
	 */
	public function get_feature_key(): string {
		return self::KEY_FEATURE;
	}

	/**
	 *  有効無効判定
	 *
	 * @return bool
	 */
	public function is_enabled(): bool {
		return $this->config->get( $this->get_feature_key() ) === 't';
	}

	/**
	 * 初期設定値取得
	 *
	 * @return array
	 */
	public function get_default(): array {
		return array( self::KEY_FEATURE => 'f' );
	}

	/**
	 * 設定値key取得
	 */
	public function get_keys(): array {
		return array( self::KEY_FEATURE );
	}

	/**
	 * 設定値取得
	 */
	public function get_settings(): array {
		$settings = array();
		$keys     = $this->get_keys();

		foreach ( $keys as $key ) {
			$settings[ $key ] = $this->config->get( $key );
		}

		return $settings;
	}

	/**
	 * 設定値保存
	 *
	 * @param array $settings
	 *
	 * @return void
	 */
	public function save_settings( array $settings ): void {
		$keys = $this->get_keys();

		foreach ( $keys as $key ) {
			$this->config->set( $key, $settings[ $key ] ?? '' );
		}
		$this->config->save();
	}

	/**
	 * 有効化
	 *
	 * @return void
	 */
	public function activate(): void {
		$settings = $this->get_default();
		$this->save_settings( $settings );
		$this->create_auth_table();
		$this->create_login_table();
	}

	/**
	 * 無効化
	 *
	 * @return void
	 */
	public function deactivate(): void {
		$settings                      = $this->get_settings();
		$settings[ self::KEY_FEATURE ] = 'f';
		$this->save_settings( $settings );
	}

	/**
	 * 管理画面上での有効無効判定
	 * 2段階認証の管理画面で「変更を保存」ボタンを押下時、
	 * is_enabled()のみを使うとデバイス登録のメニューが正しく表示されない。
	 *
	 * @return bool
	 */
	public function is_enabled_on_screen(): bool {
		if ( isset( $_POST['two_factor_authentication'] ) && ! empty( $_POST['two_factor_authentication'] ) ) {
			return $this->check_environment() && sanitize_text_field( $_POST['two_factor_authentication'] ) === 't';
		}

		return $this->is_enabled();
	}

	/**
	 * 有効な権限グループに含まれるかどうか
	 *
	 * @param $role
	 *
	 * @return bool
	 */
	private function is_role_enabled( $role ): bool {
		return in_array( $role, get_option( 'cloudsecurewp_two_factor_authentication_roles', array() ) );
	}

	/**
	 * 2段階認証のメッセージを出力
	 *
	 * @param string $message メッセージ
	 *
	 * @return void
	 */
	private function login_message( string $message ) {
		if ( empty( $message ) ) {
			return;
		}
		echo '<div class="notice notice-success">' . esc_html( apply_filters( 'login_messages', $message ) ) . "</div>\n";
	}

	/**
	 * 2段階認証のエラーを出力
	 *
	 * @param string $error エラーメッセージ
	 *
	 * @return void
	 */
	private function login_error( string $error ) {
		if ( empty( $error ) ) {
			return;
		}
		echo '<div id="login_error" class="notice notice-error">' . esc_html( apply_filters( 'login_errors', $error ) ) . "</div>\n";
	}

	/**
	 * 画面表示用のメールアドレスを生成
	 *
	 * @param int $user_id ユーザーID
	 *
	 * @return string
	 */
	public function mask_email( int $user_id ): string {
		$email = get_userdata( $user_id )->user_email;

		list( $user, $full_domain ) = explode( '@', $email );

		$last_dot_pos = strrpos( $full_domain, '.' );
		$domain_name  = substr( $full_domain, 0, $last_dot_pos );
		$tld          = substr( $full_domain, $last_dot_pos );

		[ $masked_user, $masked_domain ] = array_map(
			function( $str ) {
				$showVisible = ( mb_strlen( $str ) > 2 ) ? 2 : 1;
				return mb_substr( $str, 0, $showVisible ) . '*****';
			},
			[ $user, $domain_name ]
		);

		$masked_address = $masked_user . '@' . $masked_domain . $tld;

		return $masked_address;
	}

	/**
	 * 2段階認証のログインフォームを出力
	 *
	 * @param string $login_token
	 * @param int    $auth_method
	 * @param bool   $has_recovery
	 * @param string $email_address
	 * @param int    $remaining_seconds
	 *
	 * @return void
	 */
	private function login_form( string $login_token, int $auth_method, bool $has_recovery, string $email_address, int $remaining_seconds ) {
		?>
		<form name="loginform" id="loginform"
				action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
				<?php wp_nonce_field( $this->get_feature_key() . '_csrf' ); ?>
			<div class="two-fa-form">
				<?php if ( array_key_exists( 'rememberme', $_REQUEST ) && 'forever' === sanitize_text_field( $_REQUEST['rememberme'] ) ) : ?>
					<input name="rememberme" type="hidden" id="rememberme" value="forever"/>
				<?php endif; ?>
				<input type="hidden" name="login_token" value="<?php echo esc_attr( $login_token ); ?>">
				<input type="hidden" name="redirect_to"
						value="<?php echo esc_attr( sanitize_text_field( $_REQUEST['redirect_to'] ?? admin_url() ) ); ?>"/>
				<input type="hidden" name="testcookie" value="1"/>
				<?php if ( $auth_method === self::USER_AUTH_METHOD_RECOVERY ) : ?>
					<!-- リカバリーコード入力フォーム -->
					<input type="hidden" name="recovery_code" value="1">
					<div class="text-area">
						<p>バックアップとして保存したリカバリーコードを入力してください。</p>
					</div>
					<div class="input-area">
						<p>
							<label for="authenticator_code">リカバリーコード</label>
							<input type="text" name="authenticator_code" id="authenticator_code" class="input two-fa-input"
									value="" size="20" autocomplete="off"/>
						</p>
					</div>
					<script type="text/javascript">document.getElementById("authenticator_code").focus();</script>
				<?php else : ?>
					<!-- 通常の認証コード入力フォーム -->
					<div class="two-fa-text-area">
						<?php if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) : ?>
							<p><strong><?php echo esc_html( $email_address ); ?></strong>に送信された認証コードを入力してください。</p>
							<p>※メールが届かない場合、コードを再送信してください。</p>
						<?php else : ?>
							<p>デバイスのGoogle Authenticator に表示されている認証コードを入力してください。</p>
						<?php endif; ?>
					</div>
					<div class="two-fa-input-area">
						<p>
							<label for="authenticator_code">認証コード（6桁）</label>
							<input type="text" name="authenticator_code" id="authenticator_code" class="input two-fa-input"
									value="" size="20" autocomplete="one-time-code"/>
						</p>
					</div>
					<script type="text/javascript">document.getElementById("authenticator_code").focus();</script>					
				<?php endif; ?>
				<div>
					<div class="two-fa-btn-area">
							<button type="submit" name="wp-submit" id="wp-submit" class="button button-primary two-fa-btn" style="order: 2;">
								<?php esc_attr_e( 'Log In' ); ?>
							</button>
						<?php if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) : ?>
							<button type="submit" name="resend_2fa_email" value="1" id="resend_2fa_email_btn" class="button two-fa-btn" data-cooldown="30" data-remaining_seconds="<?php echo esc_attr( $remaining_seconds ); ?>" style="order: 1;">
								再送信
							</button>
						<?php endif; ?>
					</div>
					<?php if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) : ?>
						<div id="resend_cooldown_message" class="two-fa-cooldown-message" style="display: none;"></div>
					<?php endif; ?>
				</div>
				<div class="two-fa-link-area">
					<?php if ( $auth_method === self::USER_AUTH_METHOD_RECOVERY ) : ?>
						<!-- 通常の認証コード入力に戻るボタン -->
						<button type="submit" name="back_to_auth_code" value="1" class="two-fa-link">
							← 認証コード入力に戻る
						</button>
					<?php elseif ( $has_recovery ) : ?>
						<!-- リカバリーコード入力へのボタン -->
						<div class="separator">
							または
						</div>
						<button type="submit" name="use_recovery_code" value="1" class="two-fa-link">
							リカバリーコードを使用する
						</button>
					<?php endif; ?>
				</div>
			</div>
		</form>
		<style>
			.two-fa-form {
				display: flex;
				flex-direction: column;
				gap: 24px;
			}
			.two-fa-text-area {
				display: flex;
				flex-direction: column;
				gap: 3px;
			}
			.two-fa-input {
				margin: 0 !important;
			}
			.two-fa-btn-area {
				display: flex;
				gap: 16px;
				justify-content: center;
				align-items: center;
			}
			.two-fa-btn {
				padding: 0 !important;
				margin: 0 !important;
				width: 50%;
				height: 36px;
			}
			.two-fa-link-area {
				display: flex;
				flex-direction: column;
				gap: 16px;
				text-align: center;
			}
			.two-fa-link {
				padding: 0;
				border: none;
				background: none;
				color: #2271b1;
				text-decoration: underline;
				cursor: pointer;
			}
			.separator {
				display: flex;
				align-items: center;
				color: #646970;
				font-size: 14px;
			}
			.separator::before,
			.separator::after {
				content: "";
				flex: 1;
				height: 1px;
				background: #B2B2B2;
			}
			.separator::before {
				margin-right: 8px;
			}

			.separator::after {
				margin-left: 8px;
			}
			.two-fa-cooldown-message {
				font-size: 12px;
				text-align: left;
				color: #646970;
			}
		</style>
		<script type="text/javascript">
			(function() {
				let emailAbleSendTime = null;

				const resendBtn       = document.getElementById('resend_2fa_email_btn');
				const cooldownMessage = document.getElementById('resend_cooldown_message');
				if (!resendBtn || !cooldownMessage) return;

				// サーバーから受け取った残り秒数を使って送信可能時刻を計算
				const remainingSeconds = parseInt(resendBtn.getAttribute('data-remaining_seconds') || '0', 10);
				emailAbleSendTime = Date.now() + (remainingSeconds * 1000);

				function updateTimerDisplay() {
					// 現在時刻と送信可能時刻を比較して残り秒数を計算
					const now = Date.now();
					const remainingTime = Math.ceil((emailAbleSendTime - now) / 1000);

					if (remainingTime > 0) {
						resendBtn.disabled = true;
						cooldownMessage.style.display = 'block';
						cooldownMessage.textContent = remainingTime + '秒後 再送信できます';
						setTimeout(updateTimerDisplay, 1000);
					} else {
						resendBtn.disabled = false;
						cooldownMessage.style.display = 'none';
					}
				}

				// 表示時にタイマーを開始
				<?php if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) : ?>
					updateTimerDisplay();
				<?php endif; ?>
			})();
		</script>
		<?php
	}

	/**
	 * デバイス登録がまだのユーザーは、デバイス登録画面にリダイレクト
	 *
	 * @param $user_login
	 * @param $user
	 *
	 * @return void
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function redirect_if_not_two_factor_authentication_registered( $user_login, $user ) {
		$auth_info = $this->get_2fa_auth_info( $user->ID );
		$secret    = ( count( $auth_info ) > 0 && isset( $auth_info['secret'] ) ) ? true : false;

		if ( isset( $user->roles[0] ) ) {
			if ( $this->is_enabled() && $this->is_role_enabled( $user->roles[0] ) && ! $secret && $_SERVER['REQUEST_URI'] !== '/wp-admin/admin.php?page=cloudsecurewp_two_factor_authentication_registration' ) {
				wp_redirect( admin_url( 'admin.php?page=cloudsecurewp_two_factor_authentication_registration' ) );
				exit;
			}
		}
	}

	/**
	 * WordPress標準機能のユーザー一覧に表示するcolumnを追加
	 */
	public function add_2factor_state_2user_list( $columns ) {
		$new_columns = [];

		foreach ( $columns as $key => $value ) {
			$new_columns[ $key ] = $value;

			if ( $key === 'role' ) {
				$new_columns['is_2factor'] = '2段階認証';
			}
		}

		return $new_columns;
	}

	/**
	 * WordPress標準機能のユーザー一覧に表示する二段階認証の設定状態を指定
	 */
	public function show_2factor_state_2user_list( $value, $column_name, $user_id ) {
		if ( $column_name === 'is_2factor' ) {
			$auth_info = $this->get_2fa_auth_info( $user_id );
			if ( count( $auth_info ) === 0 ) {
				// データ移行漏れ対応
				$auth_info = $this->repair_migration_gaps( $user_id );
			}
			$value = '未設定';
			if ( count ( $auth_info ) > 0 ) {
				$value = '設定済';
			}
			return $value;
		}
		return $value;
	}

	/**
	 * option keyを作成
	 *
	 * @param string $token
	 *
	 * @return string
	 */
	private function create_option_key( string $token ): string {
		return self::OPTION_PREFIX . $token;
	}

	/**
	 * option dataを登録
	 *
	 * @param string $key
	 * @param mixed  $data
	 *
	 * @return void
	 */
	private function set_option_data( string $key, $data ): void {
		update_option( $key, $data, false );
	}

	/**
	 * option dataを取得
	 *
	 * @param string $key
	 *
	 * @return array|false データが存在しないまたは、有効期限切れの場合FALSEを返却
	 */
	private function get_option_data( string $key ) {

		$data = get_option( $key );

		// データが存在しない
		if ( ! $data || ! is_array( $data ) ) {
			return false;
		}

		// 有効期限切れ
		if ( ! isset( $data['expires'] ) || $data['expires'] <= time() ) {
			return false;
		}

		// 有効なデータを返却
		return $data;
	}

	/**
	 * option dataを削除
	 *
	 * @param string $key
	 *
	 * @return void
	 */
	private function delete_option_data( string $key ): void {
		delete_option( $key );
	}

	/**
	 * 2段階認証が必要かどうか判定処理
	 *
	 * @param mixed $user
	 *
	 * @return bool
	 */
	private function is_2fa_required( $user ): bool {

		// 2段階認証が無効な場合
		if ( ! $this->is_enabled() ) {
			return false;
		}

		// 有効な権限グループに含まれない場合
		if ( ! isset( $user->roles[0] ) || ! $this->is_role_enabled( $user->roles[0] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * 2段階認証画面を表示
	 *
	 * @param string $login_token
	 * @param int    $auth_method
	 * @param bool   $has_recovery
	 * @param string $email_address
	 * @param bool   $is_send_email
	 *
	 * @return void
	 */
	private function show_two_factor_form( string $login_token, int $auth_method, bool $has_recovery, string $email_address, bool $is_send_email ): void {
		$message           = '';
		$error             = '';
		$remaining_seconds = 0;

		// 再送信メッセージ
		if ( array_key_exists( 'resend_2fa_email', $_REQUEST ) ) {
			if ( $is_send_email ) {
				$message = '認証コードを再送信しました。';
			} else {
				$error = '認証コードの再送信は30秒に1回までです。しばらく時間をおいてから再度お試しください。';
			}
		}

		// エラーメッセージ
		if ( array_key_exists( 'wp-submit', $_REQUEST ) && array_key_exists( 'authenticator_code', $_REQUEST ) ) {
			if ( sanitize_text_field( $_REQUEST['authenticator_code'] ) ) {
				$error = '認証コードが間違っているか、有効期限が切れています。';
			} else {
				$error = '認証コードが入力されていません。';
			}
		}

		if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) {
			// メール認証の場合、送信可能になるまでの残り秒数を計算
			$able_send_time    = $this->get_email_able_send_time( $this->get_option_data( $this->create_option_key( $login_token ) )['user_id'] );
			$remaining_seconds = max( 0, $able_send_time - time() );
		}

		// 2FA画面を表示
		login_header( '2段階認証画面' );
		$this->login_message( $message );
		$this->login_error( $error );
		$this->login_form( $login_token, $auth_method, $has_recovery, $email_address, $remaining_seconds );
		login_footer();
		exit;
	}

	/**
	 * メール認証コードの再送信処理
	 *
	 * @param int    $user_id
	 * @param string $secret
	 *
	 * @return bool true: 送信成功、false: 送信制限中
	 */
	private function send_2fa_email( int $user_id, string $secret = '' ): bool {
		// 送信制限チェック（30秒間）
		$current_time   = time();
		$able_sent_time = $this->get_email_able_send_time( $user_id );

		if ( $current_time < $able_sent_time ) {
			// 30秒以内の再送信は処理しない（エラーは表示しない）
			return false;
		}

		// シークレットキーを取得
		if ( $secret === '' ) {
			$auth_info = $this->get_2fa_auth_info( $user_id );
			$secret    = $auth_info['secret'];
		}
		// 新しいコードを生成して送信
		$code = CloudSecureWP_Time_Based_One_Time_Password::create_code_for_email( $secret, self::AUTH_EMAIL_INTERVAL );
		$this->send_code( $user_id, $code, self::AUTH_EMAIL_INTERVAL, 'login' );

		// 最終送信時刻を更新
		$this->update_email_able_send_time( $user_id );

		return true;
	}

	/**
	 * 2段階認証コード検証処理
	 *
	 * @param int    $user_id
	 * @param string $code
	 * @param int    $auth_method
	 *
	 * @return bool
	 */
	private function verify_2fa_code( int $user_id, string $code, int $auth_method ): bool {
		// リカバリーコードでの認証の場合
		if ( $auth_method === self::USER_AUTH_METHOD_RECOVERY ) {
			return CloudSecureWP_Recovery_Codes::verify_code( $user_id, $code );
		}

		// シークレットキーを取得
		$auth_info = $this->get_2fa_auth_info( $user_id );
		if ( ! $auth_info || ! isset( $auth_info['secret'] ) ) {
			return false;
		}
		$secret_key = $auth_info['secret'];

		// メール認証の場合（60秒間隔）
		if ( $auth_method === self::USER_AUTH_METHOD_EMAIL ) {
			return CloudSecureWP_Time_Based_One_Time_Password::verify_code( $secret_key, $code, self::AUTH_EMAIL_INTERVAL );
		}

		// アプリ認証の場合（30秒間隔）
		return CloudSecureWP_Time_Based_One_Time_Password::verify_code( $secret_key, $code, self::AUTH_APP_INTERVAL );
	}

	/**
	 * 認証フック: ユーザ名復元処理
	 *
	 * @param string $username
	 * @param bool   $strict
	 *
	 * @return string
	 */
	public function restore_login_name( string $username, $strict = false ): string {

		// 初回アクセス・または初回認証の場合、何もしない
		if ( ! isset( $_POST['authenticator_code'] ) ) {
			return $username;
		}

		// ログイントークンを取得
		$login_token = sanitize_text_field( $_POST['login_token'] ?? '' );

		// ログイン情報を取得
		$option_key  = $this->create_option_key( $login_token );
		$option_data = $this->get_option_data( $option_key );

		// ログイン情報が存在しない場合、何もしない
		if ( $option_data === false ) {
			return $username;
		}

		// ユーザ名を返却
		return $option_data['user_login'];
	}

	/**
	 * 認証フック: ログインデータ復元処理
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 *
	 * @return mixed
	 */
	public function restore_login_session( $user, $username, $password ) {
		// 初回アクセス・または初回認証の場合、何もしない
		if ( ! isset( $_POST['authenticator_code'] ) ) {
			return $user;
		}

		// CSRFトークンを検証（失敗すると「辿ったリンクは期限が切れています。」のエラー画面を表示し処理終了）
		check_admin_referer( $this->get_feature_key() . '_csrf' );

		// ログイントークンを取得
		$login_token = sanitize_text_field( $_POST['login_token'] ?? '' );

		// ログイン情報を取得
		$option_key  = $this->create_option_key( $login_token );
		$option_data = $this->get_option_data( $option_key );

		// ログインが有効期限切れの場合
		// ログイン成功時にまとめてクリーンアップ処理を実行するため、ここでは消さない
		if ( $option_data === false ) {
			return new WP_Error( 'empty_username', 'セッションの有効期限が切れました。再度ログインしてください。' );
		}

		// ユーザーオブジェクト取得
		$user = get_user_by( 'id', $option_data['user_id'] );
		if ( ! $user ) {
			$this->delete_option_data( $option_key );
			return new WP_Error( 'empty_username', 'ユーザー情報が見つかりません。再度ログインしてください。' );
		}

		// 認証方法の設定
		$auth_method = intVal( $option_data['auth_method'] );

		// 認証コード再送信
		if ( isset( $_POST['resend_2fa_email'] ) ) {
			// メール再送信
			$result = $this->send_2fa_email( $option_data['user_id'] );

			$this->show_two_factor_form(
				$login_token,
				$auth_method,
				$option_data['has_recovery'],
				$option_data['email_address'],
				$result
			);
		}

		// リカバリーコード入力画面への切り替え
		if ( isset( $_POST['use_recovery_code'] ) ) {
			$this->show_two_factor_form(
				$login_token,
				self::USER_AUTH_METHOD_RECOVERY,
				$option_data['has_recovery'],
				$option_data['email_address'],
				false
			);
		}

		// 認証コード入力画面への切り替え
		if ( isset( $_POST['back_to_auth_code'] ) ) {
			$this->show_two_factor_form(
				$login_token,
				$auth_method,
				$option_data['has_recovery'],
				$option_data['email_address'],
				false
			);
		}

		// リカバリコードでの認証の場合
		if ( isset( $_POST['recovery_code'] ) ) {
			$auth_method = self::USER_AUTH_METHOD_RECOVERY;
		}

		// ログイン情報の復元
		$_POST['log']           = $option_data['user_login'];
		$_POST['auth_method']   = $auth_method;
		$_POST['has_recovery']  = $option_data['has_recovery'];
		$_POST['email_address'] = $option_data['email_address'];

		return $user;
	}

	/**
	 * 認証フック: 2段階認証ログイン無効チェック
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 *
	 * @return mixed
	 */
	public function two_factor_disable_login_check( $user, $username, $password ) {
		// レートリミットの無効時間を取得
		$limit_time = $this->two_factor_rate_limit();
		if ( $limit_time > 0 ) {
			// ログインログに記録
			$this->write_log( self::LOGIN_STATUS_DISABLED );

			return new WP_Error( 'empty_username', "失敗回数が上限に達したため、{$limit_time}分間ログインできません。しばらく待ってから再度お試しください。" );
		}
		return $user;
	}


	/**
	 * 認証フック: 2段階認証処理
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 *
	 * @return mixed
	 */
	public function authenticate_with_two_factor( $user, $username, $password ) {
		// 初回アクセス、または初回認証時
		if ( ! isset( $_POST['authenticator_code'] ) ) {
			// 認証失敗の場合
			if ( is_wp_error( $user ) ) {
				return $user;
			}

			// 2段階認証が不要な場合
			if ( ! $this->is_2fa_required( $user ) ) {
				return $user;
			}

			// 認証情報の取得
			$auth_info = $this->get_2fa_auth_info( $user->ID );
			// 認証情報が存在しない場合
			if ( count( $auth_info ) === 0 ) {
				// データ移行漏れ対応
				$auth_info = $this->repair_migration_gaps( $user->ID );
				if ( count ( $auth_info ) === 0 ) {
					return $user;
				}
			}

			// リカバリーコードの有無
			$has_recovery   = true;
			$recovery_codes = $auth_info['recovery'];
			if ( ! $recovery_codes || ! is_array( $recovery_codes ) || count( $recovery_codes ) === 0 ) {
				$has_recovery = false;
			}

			// option key生成
			$session_token = bin2hex( random_bytes( 16 ) );
			$option_key    = $this->create_option_key( $session_token );

			// 保存用ログインデータ作成
			$option_data = array(
				'user_id'         => $user->ID,
				'user_login'      => sanitize_text_field( $_POST['log'] ?? '' ),
				'auth_method'     => intVal( $auth_info['method'] ),
				'expires'         => time() + self::SESSION_EXPIRY,
				'created'         => time(),
				'has_recovery'    => $has_recovery,
				'email_address'   => $this->mask_email( $user->ID ),
			);

			// データを保存
			$this->set_option_data( $option_key, $option_data );

			// メール認証の場合、コードを生成して送信
			if ( intVal( $auth_info['method'] ) === self::USER_AUTH_METHOD_EMAIL ) {
				$this->send_2fa_email( $user->ID, $auth_info['secret'] );
			}

			// 2FA画面を表示して、処理終了
			$this->show_two_factor_form(
				$session_token,
				intVal( $auth_info['method'] ),
				$has_recovery,
				$option_data['email_address'],
				false
			);
		}

		// 2FA関連のPOSTデータ取得
		$login_token = sanitize_text_field( $_POST['login_token'] ?? '' );
		$auth_code   = sanitize_text_field( $_POST['authenticator_code'] ?? '' );

		// option key取得
		$option_key = $this->create_option_key( $login_token );

		// $userがWP_Errorの場合は処理をスキップ
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		// 2段階認証成功の場合
		if ( $this->verify_2fa_code( $user->ID, $auth_code, $_POST['auth_method'] ) ) {
			// 失敗回数をリセット
			$this->reset_fail_count();
			// セッションデータを削除
			$this->delete_option_data( $option_key );
			// メール認証の送信可能時間をリセット
			$this->delete_email_able_send_time( $user->ID );
			return $user;
		}

		// 2段階認証失敗の場合
		// 失敗回数をインクリメント
		$this->increment_fail_count();

		// レートリミットの確認
		$limit_time = $this->two_factor_rate_limit();

		$this->write_log( self::LOGIN_STATUS_FAILED );

		if ( $limit_time > 0 ) {
			// ステータス無効状態の場合
			return new WP_Error( 'empty_username', "失敗回数が上限に達したため、{$limit_time}分間ログインできません。しばらく待ってから再度お試しください。" );
		}

		// 2FA画面を再表示して、処理終了
		$this->show_two_factor_form(
			$login_token,
			$_POST['auth_method'],
			$_POST['has_recovery'],
			$_POST['email_address'],
			false
		);
	}

	/**
	 * 2FAセッションデータを取得
	 *
	 * @param int $last_option_id
	 * @param int $limit
	 *
	 * @return array
	 */
	private function fetch_2fa_sessions( int $last_option_id, int $limit ): array {
		global $wpdb;

		// セッションキーの接頭辞でLIKE検索
		$like = $wpdb->esc_like( self::OPTION_PREFIX ) . '%';

		// SQL実行（LIKE検索を行うため、意図的に直接クエリを実行する）
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT
					option_id,
					option_name,
					option_value
				FROM
					{$wpdb->options} 
				WHERE TRUE
					AND option_name LIKE %s
					AND %d < option_id
				ORDER BY
					option_id ASC
				LIMIT
					%d",
				$like,
				$last_option_id,
				$limit
			)
		);

		return $options ?? array();
	}

	/**
	 * 期限切れセッションデータを収集
	 *
	 * @param array $options
	 *
	 * @return array ['log_data' => array, 'delete_option_names' => array]
	 */
	private function collect_expired_session_data( array $options ): array {
		// ログ登録用データリスト初期化
		$log_data = array();
		// 削除対象のoption_nameリスト
		$delete_option_names = array();

		foreach ( $options as $option ) {
			// option_valueを連想配列に変換
			$data = maybe_unserialize( $option->option_value );

			// 配列でない場合はスキップ
			if ( ! is_array( $data ) ) {
				continue;
			}

			// 有効期限が切れている場合
			if ( isset( $data['expires'] ) && $data['expires'] <= time() ) {

				// ログ登録用データを収集
				$log_data[] = array(
					'name'     => $data['user_login'],
					'ip'       => $this->get_client_ip(),
					'status'   => self::LOGIN_STATUS_FAILED,
					'method'   => self::METHOD_PAGE,
					'login_at' => wp_date( 'Y-m-d H:i:s', $data['created'] ), // WPのタイムゾーンに変更して登録
				);

				// 削除対象のoption_nameを収集
				$delete_option_names[] = $option->option_name;
			}
		}

		return array(
			'log_data'            => $log_data,
			'delete_option_names' => $delete_option_names,
		);
	}

	/**
	 * ログイン失敗ログを一括登録
	 * (呼び出し元でトランザクションを管理すること)
	 *
	 * @param array $log_data
	 *
	 * @return void
	 * @throws Exception SQLエラー発生時.
	 */
	private function insert_login_failed_logs( array $log_data ): void {
		if ( empty( $log_data ) ) {
			return;
		}

		global $wpdb;

		// プレースホルダーと値の準備
		$values       = array();
		$placeholders = array();

		// 収集したログデータを一括登録用に変換
		foreach ( $log_data as $log ) {
			$values[]       = $log['name'];
			$values[]       = $log['ip'];
			$values[]       = $log['status'];
			$values[]       = $log['method'];
			$values[]       = $log['login_at'];
			$placeholders[] = '(%s, %s, %d, %d, %s)';
		}

		// SQL実行（一括登録を行うため、意図的に直接クエリを実行する）
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO `{$wpdb->prefix}cloudsecurewp_login_log` 
				(`name`, `ip`, `status`, `method`, `login_at`) 
				VALUES " . implode( ', ', $placeholders ),
				$values
			)
		);

		// SQLエラーチェック
		if ( $result === false || ! empty( $wpdb->last_error ) ) {
			throw new Exception( 'Failed to insert login logs: ' . $wpdb->last_error );
		}
	}

	/**
	 * 指定されたオプションを一括削除
	 * (呼び出し元でトランザクションを管理すること)
	 *
	 * @param array $option_names
	 *
	 * @return void
	 * @throws Exception SQLエラー発生時.
	 */
	private function delete_options( array $option_names ): void {
		if ( empty( $option_names ) ) {
			return;
		}

		global $wpdb;

		// プレースホルダー作成
		$placeholders = implode( ', ', array_fill( 0, count( $option_names ), '%s' ) );

		// SQL実行（一括削除を行うため、意図的に直接クエリを実行する）
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM
					{$wpdb->options}
				WHERE
					option_name IN ($placeholders)",
				$option_names
			)
		);

		// SQLエラーチェック
		if ( $result === false || ! empty( $wpdb->last_error ) ) {
			throw new Exception( 'Failed to delete options: ' . $wpdb->last_error );
		}
	}

	/**
	 * 期限切れログイン情報セッションのクリーンアップ処理本体
	 *
	 * @return void
	 */
	private function process_cleanup_expired_sessions(): void {
		global $wpdb;

		$last_option_id = 0;

		while ( true ) {
			try {
				// 2FAセッションデータを取得
				$options = $this->fetch_2fa_sessions( $last_option_id, self::CLEANUP_BATCH_SIZE );

				// 取得するレコードがなくなったら終了
				if ( empty( $options ) ) {
					break;
				}

				// 最後に取得したoption_idを更新
				$last_option_id = end( $options )->option_id;

				// 期限切れセッションデータを収集
				$result              = $this->collect_expired_session_data( $options );
				$log_data            = $result['log_data'];
				$delete_option_names = $result['delete_option_names'];

				if ( empty( $delete_option_names ) && empty( $log_data ) ) {
					continue;
				}

				// トランザクション開始
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'START TRANSACTION' );

				// ログデータを一括登録
				$this->insert_login_failed_logs( $log_data );

				// オプションを一括削除
				$this->delete_options( $delete_option_names );

				// トランザクションコミット
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'COMMIT' );

			} catch ( Exception $e ) {
				// エラー発生時はロールバック
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'ROLLBACK' );
				break;
			}
		}
	}

	/**
	 * 期限切れの2FAセッションをクリーンアップ
	 *
	 * @return void
	 */
	public function cleanup_expired_sessions(): void {
		global $wpdb;

		// ロック名
		$lock_name = 'cloudsecurewp_2fa_cleanup_lock';
		// クリーンアップ処理の完了を待つ最大秒数
		$timeout = self::CLEANUP_TIMEOUT;

		// ロックを取得
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$get_lock = $wpdb->get_var(
			$wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', $lock_name )
		);

		if ( $get_lock === '1' ) {
			// ロック取得成功（クリーンアップ実行者）

			try {
				// クリーンアップ処理実行
				$this->process_cleanup_expired_sessions();
			} catch ( Exception $e ) {
				// クリーンアップ処理実行で失敗しても内部でロールバックするため、ここでは何もしない
			} finally {
				// ロック解放
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query(
					$wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name )
				);
			}
		} else {
			// ロック取得失敗（待機者）

			// リーダーのクリーンアップ完了を待機
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$acquired_signal = $wpdb->get_var(
				$wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $lock_name, $timeout )
			);

			if ( $acquired_signal === '1' ) {
				// ロック取得成功（クリーンアップ処理終了）
				// 即座にロック解放（待機完了の合図として使うだけ）
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query(
					$wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name )
				);
			}
		}
	}

	/**
	 * ユーザの2faログイン情報取得
	 *
	 * @param string $ip
	 *
	 * @return array $login_info
	 */
	private function get_2fa_login_info( string $ip ): array {
		global $wpdb;

		$table_name = $wpdb->prefix . self::LOGIN_TABLE_NAME;
		$sql        = "SELECT * FROM {$table_name} WHERE ip = %s";

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$row = $wpdb->get_row( $wpdb->prepare( $sql, $ip ), ARRAY_A );

		return $row ?? array();
	}

	/**
	 * ユーザの2fa認証情報取得
	 *
	 * @param int $user_id
	 *
	 * @return array $auth_info
	 */
	public function get_2fa_auth_info( int $user_id ): array {
		global $wpdb;

		$table_name = $wpdb->prefix . self::AUTH_TABLE_NAME;
		$sql        = "SELECT * FROM {$table_name} WHERE user_id = %d";

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$row = $wpdb->get_row( $wpdb->prepare( $sql, $user_id ), ARRAY_A );

		if ( ! empty( $row ) && isset( $row['recovery'] ) ) {
			$row['recovery'] = maybe_unserialize( $row['recovery'] );
		}

		return $row ?? array();
	}

	/**
	 * リカバリーコードの登録状況取得
	 *
	 * @param int $user_id
	 *
	 * @return bool true:登録済み、false:未登録
	 */
	public function has_recovery_codes( int $user_id ): bool {
		$auth_info = $this->get_2fa_auth_info( $user_id );

		if ( empty( $auth_info ) || is_null( $auth_info['recovery'] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * ユーザの2fa認証方法設定
	 *
	 * @param int    $user_id
	 * @param int    $method
	 * @param string $secret
	 *
	 * @return void
	 */
	public function setting_2fa_auth_info( int $user_id, int $method, string $secret ): void {
		// 認証情報取得
		$auth_info = $this->get_2fa_auth_info( $user_id );

		if ( ! empty( $auth_info ) ) {
			// 既に登録されている場合は更新
			$this->update_2fa_auth_method( $user_id, $method, $secret );
		} else {
			// 登録されていない場合は新規登録
			$this->insert_2fa_auth_method( $user_id, $method, $secret );
		}
	}

	/**
	 * ユーザの2fa認証方法更新
	 *
	 * @param int    $user_id
	 * @param int    $method
	 * @param string $secret
	 * @return void
	 */
	private function update_2fa_auth_method( int $user_id, int $method, string $secret ): void {
		global $wpdb;

		// 認証情報を更新
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->update(
			$wpdb->prefix . 'cloudsecurewp_2fa_auth',
			array(
				'method' => $method,
				'secret' => $secret,
			),
			array( 'user_id' => $user_id )
		);
	}

	/**
	 * ユーザの2fa認証方法登録
	 *
	 * @param int    $user_id
	 * @param int    $method
	 * @param string $secret
	 *
	 * @return void
	 */
	private function insert_2fa_auth_method( int $user_id, int $method, string $secret ): void {
		global $wpdb;

		// 認証情報を新規登録
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . 'cloudsecurewp_2fa_auth',
			array(
				'user_id'  => $user_id,
				'secret'   => $secret,
				'recovery' => null,
				'method'   => $method,
			)
		);
	}

	/**
	 * ログイン失敗回数インクリメント処理
	 *
	 * @return void
	 * @throws Exception SQLエラー発生時.
	 */
	private function increment_fail_count(): void {
		global $wpdb;

		// テーブル名取得
		$table_name = $wpdb->prefix . self::LOGIN_TABLE_NAME;

		// 登録データ作成
		$ip           = $this->get_client_ip();
		$now_datetime = current_time( 'mysql' );
		$data         = array(
			'ip'           => $ip,
			'status'       => self::LOGIN_STATUS_FAILED,
			'failed_count' => 1,
			'login_at'     => $now_datetime,
		);

		$row = $this->get_2fa_login_info( $ip );

		if ( empty( $row ) ) {
			// レコードが存在していない場合は新規登録
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert( $table_name, $data );
		} else {
			// レコードが存在している場合はカウントアップ
			$data['failed_count'] = (int) $row['failed_count'] + 1;

			// 3回失敗ごとにステータスを無効化に更新
			if ( $data['failed_count'] % 3 === 0 ) {
				$data['status'] = self::LOGIN_STATUS_DISABLED;
			}

			// 失敗回数とステータスを更新
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->update( $table_name, $data, array( 'ip' => $ip ) );
		}
	}

	/**
	 * ログインログ記録処理（失敗時）
	 *
	 * @param int $status ログインステータス
	 *
	 * @return void
	 */
	private function write_log( int $status ): void {
		global $wpdb;

		// ログインログに記録
		$name   = sanitize_text_field( $_POST['log'] ?? '' );
		$ip     = $this->get_client_ip();
		$method = $this->login_log->is_xmlrpc() ? self::METHOD_XMLRPC : self::METHOD_PAGE;
		$this->login_log->write_log( $name, $ip, $status, $method );
	}

	/**
	 * ログイン失敗回数リセット処理
	 *
	 * @return void
	 */
	private function reset_fail_count(): void {
		global $wpdb;

		// テーブル名取得
		$table_name = $wpdb->prefix . self::LOGIN_TABLE_NAME;

		// 登録データ作成
		$ip           = $this->get_client_ip();
		$now_datetime = current_time( 'mysql' );
		$data         = array(
			'ip'           => $ip,
			'status'       => self::LOGIN_STATUS_SUCCESS,
			'failed_count' => 0,
			'login_at'     => $now_datetime,
		);

		$row = $this->get_2fa_login_info( $ip );

		if ( empty( $row ) ) {
			// レコードが存在していない場合は新規登録
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert( $table_name, $data );
		} else {
			if ( $row['status'] === self::LOGIN_STATUS_SUCCESS ) {
				// 既に成功状態の場合は何もしない
				return;
			}
			// 失敗回数とステータスを更新
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->update( $table_name, $data, array( 'ip' => $ip ) );

		}
	}

	/**
	 * レートリミットの無効時間を取得
	 * 無効ではない場合は0を返す
	 *
	 * @return int レートリミットの残り時間（分）
	 */
	private function two_factor_rate_limit(): int {
		// 現在のクライアントIPアドレスでレコードを取得
		$ip  = $this->get_client_ip();
		$row = $this->get_2fa_login_info( $ip );

		if ( ! empty( $row ) && (int) $row['status'] === self::LOGIN_STATUS_DISABLED ) {
			// 無効時間チェック
			$limit_time = self::LATE_LIMIT_TIME_LIST[ (int) $row['failed_count'] ] ?? self::LATE_LIMIT_TIME_MAX;
			$now_time   = strtotime( current_time( 'mysql' ) );
			$block_time = strtotime( $row['login_at'] ) + $limit_time;

			if ( $now_time < $block_time ) {
				return (int) ceil( ( $block_time - $now_time ) / 60 );
			}
		}

		return 0;
	}

	/**
	 * メール最終送信時刻更新処理
	 *
	 * @param int $user_id
	 *
	 * @return void
	 */
	private function update_email_able_send_time( int $user_id ): void {
		// 送信可能時刻を更新
		$able_send_time = time() + self::EMAIL_SEND_LIMIT_TIME;
		update_user_meta( $user_id, self::TWO_FACTOR_EMAIL_SEND, $able_send_time );
	}

	/**
	 * メール最終送信時刻リセット処理
	 *
	 * @param int $user_id
	 *
	 * @return void
	 */
	private function delete_email_able_send_time( int $user_id ): void {
		// 送信可能時刻をリセット
		update_user_meta( $user_id, self::TWO_FACTOR_EMAIL_SEND, 0 );
	}

	/**
	 * メール最終送信時刻取得処理
	 *
	 * @param int $user_id
	 *
	 * @return int 最終送信時刻（unixタイムスタンプ）
	 */
	private function get_email_able_send_time( int $user_id ): int {
		// 最終送信時刻を取得
		$last_send = get_user_meta( $user_id, self::TWO_FACTOR_EMAIL_SEND, true );

		if ( ! $last_send ) {
			return 0;
		}

		return (int) $last_send;
	}

	/**
	 * wp_usermetaから2fa関連データを取得
	 *
	 * @param int $last_umeta_id
	 * @param int $batch_size
	 *
	 * @return array
	 */
	private function fetch_user_metas( int $last_umeta_id, int $batch_size ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$user_metas = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT umeta_id, user_id, meta_value 
				FROM {$wpdb->usermeta} 
				WHERE meta_key = %s 
					AND umeta_id > %d
				ORDER BY umeta_id ASC 
				LIMIT %d",
				self::TWO_FACTOR_SECRET_KEY,
				$last_umeta_id,
				$batch_size
			),
			ARRAY_A
		);

		return $user_metas ?? array();
	}

	/**
	 * usermeta データをバルクインサート用データに変換
	 *
	 * @param array $user_metas
	 *
	 * @return array ['insert_data' => array, 'umeta_ids_map' => array]
	 */
	private function convert_user_metas_to_insert_data( array $user_metas ): array {
		$insert_data   = array();
		$umeta_ids_map = array();

		foreach ( $user_metas as $user_meta ) {
			$user_id    = (int) $user_meta['user_id'];
			$umeta_id   = (int) $user_meta['umeta_id'];
			$meta_value = $user_meta['meta_value'];

			// Base32デコードしてバイナリに変換
			$binary_secret = CloudSecureWP_Time_Based_One_Time_Password::base32_decode( $meta_value );

			// バイナリデータを16進数に変換
			$hex_secret = bin2hex( $binary_secret );

			// データを蓄積
			$insert_data[] = array(
				'user_id'  => $user_id,
				'secret'   => $hex_secret,
				'recovery' => null,
				'method'   => self::USER_AUTH_METHOD_APP,
			);

			// umeta_idとuser_idのマッピングを保存
			$umeta_ids_map[ $user_id ] = $umeta_id;
		}

		return array(
			'insert_data'   => $insert_data,
			'umeta_ids_map' => $umeta_ids_map,
		);
	}

	/**
	 * 2fa認証データのバルクインサート
	 * (呼び出し元でトランザクションを管理すること)
	 *
	 * @param array $data_list
	 *
	 * @return array 失敗したuser_idのリスト
	 * @throws Exception SQLエラー発生時.
	 */
	private function bulk_insert_2fa_auth( array $data_list ): array {
		if ( empty( $data_list ) ) {
			return array();
		}

		global $wpdb;

		$table_name = $wpdb->prefix . self::AUTH_TABLE_NAME;

		// 挿入を試みるuser_idのリスト
		$target_user_ids = array_column( $data_list, 'user_id' );

		// プレースホルダーと値の準備
		$values       = array();
		$placeholders = array();

		foreach ( $data_list as $data ) {
			$values[]       = $data['user_id'];
			$values[]       = $data['secret'];
			$values[]       = $data['method'];
			$placeholders[] = '(%d, %s, null, %d)';
		}

		// SQL実行（INSERT IGNOREで重複などのエラーを無視）
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$table_name} 
				(`user_id`, `secret`, `recovery`, `method`) 
				VALUES " . implode( ', ', $placeholders ),
				$values
			)
		);

		// SQLエラーチェック（INSERT IGNOREは重複エラーを返さないが、その他のエラーはチェック）
		if ( $result === false || ! empty( $wpdb->last_error ) ) {
			throw new Exception( 'Failed to bulk insert 2fa auth data: ' . $wpdb->last_error );
		}

		// 失敗したuser_id（挿入されなかったID）を特定
		// INSERT IGNOREは重複時に0行を挿入するため、
		// 挿入されなかった数 = 試行数 - 実際に挿入された行数
		$failed_count = count( $target_user_ids ) - $result;

		// 失敗したIDを特定したい場合は、挿入後に存在確認が必要
		if ( $failed_count > 0 ) {
			// 挿入後に実際に存在するuser_idを確認
			$placeholders_check = implode( ', ', array_fill( 0, count( $target_user_ids ), '%d' ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$inserted_user_ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT user_id FROM {$table_name} WHERE user_id IN ($placeholders_check)",
					$target_user_ids
				)
			);

			// 失敗したuser_idを特定
			$failed_user_ids = array_diff( $target_user_ids, $inserted_user_ids );
			return array_values( $failed_user_ids );
		}

		return array();
	}

	/**
	 * wp_usermetaから指定されたレコードを削除
	 * (呼び出し元でトランザクションを管理すること)
	 *
	 * @param array $umeta_ids
	 *
	 * @return void
	 * @throws Exception SQLエラー発生時.
	 */
	private function delete_user_metas( array $umeta_ids ): void {
		if ( empty( $umeta_ids ) ) {
			return;
		}

		global $wpdb;

		$delete_placeholders = implode( ', ', array_fill( 0, count( $umeta_ids ), '%d' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE umeta_id IN ($delete_placeholders)",
				$umeta_ids
			)
		);

		// 削除エラーチェック
		if ( $result === false || ! empty( $wpdb->last_error ) ) {
			throw new Exception( 'Failed to delete usermeta: ' . $wpdb->last_error );
		}
	}

	/**
	 * 2fa既存ユーザーデータの移行処理
	 *
	 * @return void
	 */
	public function migrate_2fa_user_data(): void {
		global $wpdb;

		$batch_size    = self::CLEANUP_BATCH_SIZE;
		$last_umeta_id = 0;

		while ( true ) {
			try {
				// wp_usermetaからシークレットキーをバッチサイズごとに取得
				$user_metas = $this->fetch_user_metas( $last_umeta_id, $batch_size );

				// 取得するレコードがなくなったら終了
				if ( empty( $user_metas ) ) {
					break;
				}

				// 最後に取得したumeta_idを更新
				$last_umeta_id = end( $user_metas )['umeta_id'];

				// バルクインサート用のデータを準備
				$conversion_result = $this->convert_user_metas_to_insert_data( $user_metas );
				$insert_data       = $conversion_result['insert_data'];
				$umeta_ids_map     = $conversion_result['umeta_ids_map'];

				// 登録するデータがない場合は次のバッチへ
				if ( empty( $insert_data ) ) {
					continue;
				}

				// トランザクション開始
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'START TRANSACTION' );

				// バルクインサート実行（失敗したuser_idのリストを取得）
				$failed_user_ids = $this->bulk_insert_2fa_auth( $insert_data );

				// 成功したuser_idを特定
				$target_user_ids     = array_column( $insert_data, 'user_id' );
				$successful_user_ids = array_diff( $target_user_ids, $failed_user_ids );

				// 成功したレコードのumeta_idを取得
				$successful_umeta_ids = array();
				foreach ( $successful_user_ids as $user_id ) {
					if ( isset( $umeta_ids_map[ $user_id ] ) ) {
						$successful_umeta_ids[] = $umeta_ids_map[ $user_id ];
					}
				}

				// 成功したレコードのみwp_usermetaから削除
				$this->delete_user_metas( $successful_umeta_ids );

				// トランザクションコミット
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'COMMIT' );

			} catch ( Exception $e ) {
				// エラー発生時はロールバック
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->query( 'ROLLBACK' );
				break;
			}
		}
	}

	/**
	 * 2faログインテーブル作成
	 *
	 * @return void
	 */
	private function create_login_table(): void {
		global $wpdb;
		$table_name = $wpdb->prefix . self::LOGIN_TABLE_NAME;
		$table      = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );

		if ( is_null( $table ) ) {
			$charset_collate = $wpdb->get_charset_collate();

			$sql = "CREATE TABLE {$table_name} ( 
				ip varchar( 39 ) NOT NULL DEFAULT '', 
				status int NOT NULL DEFAULT 0, 
				failed_count int NOT NULL DEFAULT 0, 
				login_at datetime NOT NULL, 
				PRIMARY KEY  (ip) 
				) {$charset_collate}";

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			dbDelta( $sql );
		}
	}

	/**
	 * 2fa認証テーブル作成
	 *
	 * @return void
	 */
	private function create_auth_table(): void {
		global $wpdb;
		$table_name = $wpdb->prefix . self::AUTH_TABLE_NAME;
		$table      = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );

		if ( is_null( $table ) ) {
			$charset_collate = $wpdb->get_charset_collate();

			$sql = "CREATE TABLE {$table_name} (
				user_id bigint(20) UNSIGNED NOT NULL,
				secret varchar(255) NOT NULL,
				recovery longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
				method int(11) UNSIGNED NOT NULL DEFAULT 1,
				PRIMARY KEY  (user_id)
				) {$charset_collate}";

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			dbDelta( $sql );
		}
	}

	/**
	 * 2段階認証のテーブル作成とデータ移行を一括実行
	 *
	 * @return void
	 */
	public function setup_2fa_tables(): void {
		$this->create_login_table();
		$this->create_auth_table();
		$this->migrate_2fa_user_data();
	}

	/**
	 * データ移行漏れ修復処理
	 *
	 * @param int $user_id
	 *
	 * @return array
	 */
	public function repair_migration_gaps( int $user_id ): array {
		global $wpdb;

		// 2fa認証テーブルが存在しない場合は作成
		$this->create_auth_table();
		// 2faログインテーブルが存在しない場合は作成
		$this->create_login_table();

		// 2fa認証情報を取得
		$auth_info = $this->get_2fa_auth_info( $user_id );
		if ( count( $auth_info ) !== 0 ) {
			// 既に認証情報が存在する場合は何もしない
			return $auth_info;
		}

		// wp_usermetaからシークレットキーを取得
		$secret = get_user_meta( $user_id, self::TWO_FACTOR_SECRET_KEY, true );
		if ( ! $secret ) {
			// シークレットキーが存在しない場合は何もしない
			return [];
		}

		try {
			// トランザクション開始
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'START TRANSACTION' );

			// 登録データ作成
			// Base32デコードしてバイナリに変換
			$binary_secret = CloudSecureWP_Time_Based_One_Time_Password::base32_decode( $secret );
			// バイナリデータを16進数に変換
			$hex_secret = bin2hex( $binary_secret );

			// 2fa認証情報を登録
			$this->insert_2fa_auth_method( $user_id, self::USER_AUTH_METHOD_APP, $hex_secret );

			// シークレットキーをwp_usermetaから削除
			delete_user_meta( $user_id, self::TWO_FACTOR_SECRET_KEY );

			// トランザクションコミット
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'COMMIT' );
			$auth_info = $this->get_2fa_auth_info( $user_id );
			return $auth_info;
		} catch ( Exception $e ) {
			// エラー発生時はロールバック
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'ROLLBACK' );
			return [];
		}
	}

	/**
	 * AJAX: 秘密鍵を生成（アプリ認証時に使用）
	 *
	 * @return void
	 */
	public function ajax_generate_key(): void {
		// nonceチェック
		check_ajax_referer( $this->get_feature_key() . '_csrf', 'nonce', true );

		// 秘密鍵を生成
		$secret_key_data = CloudSecureWP_Time_Based_One_Time_Password::generate_secret_key();

		wp_send_json_success( $secret_key_data );
	}

	/**
	 * AJAX: 秘密鍵を生成してメール送信（メール認証時に使用）
	 *
	 * @return void
	 */
	public function ajax_generate_key_and_send_email(): void {
		// nonceチェック
		check_ajax_referer( $this->get_feature_key() . '_csrf', 'nonce', true );

		// 返却JSONレスポンス初期化
		$json_response = [
			'is_send_email'     => false,
			'remaining_seconds' => 0,
		];

		$user_id = get_current_user_id();

		// 最終送信時刻から30秒以内ならそのまま返す
		$able_send_time    = $this->get_email_able_send_time( $user_id );
		$now_time          = time();
		$remaining_seconds = $able_send_time - $now_time;
		if ( $remaining_seconds > 0 ) {
			$json_response['remaining_seconds'] = $remaining_seconds;
			wp_send_json_success( $json_response );
		}

		try {
			// 秘密鍵を生成
			$secret_key_data = CloudSecureWP_Time_Based_One_Time_Password::generate_secret_key();
			// 認証コードを生成
			$code = CloudSecureWP_Time_Based_One_Time_Password::create_code_for_email( $secret_key_data['hex'], self::AUTH_EMAIL_INTERVAL );
			// メール送信
			$this->send_code( $user_id, $code, self::AUTH_EMAIL_INTERVAL, 'setting' );
			// 最終送信時刻を更新
			$this->update_email_able_send_time( $user_id );

			// 秘密鍵を保存
			$transient_key = '2fa_setup_secret_' . $user_id;
			set_transient( $transient_key, $secret_key_data['hex'], 180 );

			$json_response['is_send_email']     = true;
			$json_response['remaining_seconds'] = self::EMAIL_SEND_LIMIT_TIME;
			wp_send_json_success( $json_response );

		} catch ( Exception $e ) {
			wp_send_json_error( $json_response );
		}
	}

	/**
	 * AJAX: 認証コードの検証と保存
	 *
	 * @return void
	 */
	public function ajax_verify_auth_code(): void {
		// nonceチェック
		check_ajax_referer( $this->get_feature_key() . '_csrf', 'nonce', true );

		// 返却JSONレスポンス初期化
		$json_response = [
			'has_recovery' => false,
		];

		$user_id = get_current_user_id();

		$method      = sanitize_text_field( $_POST['method'] );
		$interval    = ( $method === 'app' ) ? self::AUTH_APP_INTERVAL : self::AUTH_EMAIL_INTERVAL;
		$auth_method = ( $method === 'app' ) ? self::USER_AUTH_METHOD_APP : self::USER_AUTH_METHOD_EMAIL;
		$code        = isset( $_POST['code'] ) ? sanitize_text_field( $_POST['code'] ) : '';

		if ( $method === 'app' ) {
			$secret_key = isset( $_POST['secret_key'] ) ? sanitize_text_field( $_POST['secret_key'] ) : '';
		} else {
			$transient_key = '2fa_setup_secret_' . $user_id;
			$secret_key    = get_transient( $transient_key );
			if ( ! $secret_key ) {
				wp_send_json_error( $json_response );
			}
		}

		if ( ! CloudSecureWP_Time_Based_One_Time_Password::verify_code( $secret_key, $code, $interval ) ) {
			wp_send_json_error( $json_response );
		}

		// 認証成功 - データベースに保存
		try {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'START TRANSACTION' );

			// 2fa認証情報を設定
			$this->setting_2fa_auth_info( $user_id, $auth_method, $secret_key );

			// メール認証の場合
			if ( $method === 'email' ) {
				// 一時保存していた秘密鍵を削除
				delete_transient( $transient_key );
				// メール認証の送信可能時間をリセット
				$this->delete_email_able_send_time( $user_id );
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'COMMIT' );

			// リカバリーコードの設定状況を取得
			$has_recovery                  = $this->has_recovery_codes( $user_id );
			$json_response['has_recovery'] = $has_recovery;
			wp_send_json_success( $json_response );
		} catch ( Exception $e ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->query( 'ROLLBACK' );

			wp_send_json_error( $json_response );
		}
	}

	/**
	 * AJAX: リカバリーコード生成
	 *
	 * @return void
	 */
	public function ajax_generate_recovery_codes(): void {
		// nonceチェック
		check_ajax_referer( $this->get_feature_key() . '_csrf', 'nonce', true );

		// 返却JSONレスポンス初期化
		$json_response = [
			'codes' => [],
		];

		// 2段階認証が設定されているかチェック
		try {
			$user_id   = get_current_user_id();
			$auth_info = $this->get_2fa_auth_info( $user_id );
			if ( count( $auth_info ) === 0 ) {
				wp_send_json_error( $json_response );
			}

			// リカバリーコードを生成
			$codes = CloudSecureWP_Recovery_Codes::initialize_codes( $user_id );
			if ( count( $codes ) === 0 ) {
				wp_send_json_error( $json_response );
			}

			// 平文コードを返却（これは1度だけ表示される）
			$json_response['codes'] = $codes;
			wp_send_json_success( $json_response );

		} catch ( Exception $e ) {
			wp_send_json_error( $json_response );
		}
	}

	/**
	 * ユーザーに認証コードをメール送信
	 *
	 * @param int    $user_id
	 * @param string $code
	 * @param int    $time_step 時間間隔（秒）
	 * @param string $status 'login' または 'setting'
	 *
	 * @return void
	 */
	private function send_code( int $user_id, string $code, int $time_step, string $status ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$expire  = $time_step / 60;
		$to      = $user->user_email;
		$subject = '2段階認証コード';

		if ( $status === 'login' ) {
			$body  = "ユーザー {$user->user_login} が" . get_bloginfo( 'name' ) . " にログインしようとしています。\n";
			$body .= "ログインを完了するには、以下の2段階認証コードを入力してください。\n\n";
		} else {
			$body  = "ユーザー {$user->user_login} が" . get_bloginfo( 'name' ) . "で2段階認証を設定しています。\n";
			$body .= "セットアップを完了するには、以下の2段階認証コードを入力してください。\n\n";
		}

		$body .= "2段階認証コード: {$code}\n\n";
		$body .= "このコードは{$expire}分間有効です。\n";
		$body .= "もしこのメールに心当たりがない場合は、第三者があなたのパスワードを使用してログインを試みた可能性があります。\n";
		$body .= "速やかにパスワードを変更することをお勧めします。\n\n";
		$body .= "--\n";
		$body .= "CloudSecure WP Security\n";

		$this->wp_send_mail( $to, esc_html( $subject ), esc_html( $body ) );
	}
}
