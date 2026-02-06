<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Two_Factor_Authentication extends CloudSecureWP_Common {
	private const KEY_FEATURE        = 'two_factor_authentication';
	private const OPTION_PREFIX      = 'cloudsecurewp_2fa_data_';
	private const SESSION_EXPIRY     = 300;
	private const CLEANUP_TIMEOUT    = 60;
	private const CLEANUP_BATCH_SIZE = 1000;

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
	 * 2段階認証のエラーを出力
	 *
	 * @return void
	 */
	private function login_error() {
		if ( array_key_exists( 'google_authenticator_code', $_REQUEST ) ) {
			if ( sanitize_text_field( $_REQUEST['google_authenticator_code'] ) ) {
				$errors = '認証コードが間違っているか、有効期限が切れています。';
			} else {
				$errors = '認証コードが入力されていません。';
			}
			echo '<div id="login_error">' . esc_html( apply_filters( 'login_errors', $errors ) ) . "</div>\n";
		}
	}

	/**
	 * 2段階認証のログインフォームを出力
	 *
	 * @param string $login_token
	 *
	 * @return void
	 */
	private function login_form( $login_token ) {
		?>
		<form name="loginform" id="loginform"
				action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
			<?php if ( array_key_exists( 'rememberme', $_REQUEST ) && 'forever' === sanitize_text_field( $_REQUEST['rememberme'] ) ) : ?>
				<input name="rememberme" type="hidden" id="rememberme" value="forever"/>
			<?php endif; ?>
			<input type="hidden" name="login_token" value="<?php echo esc_attr( $login_token ); ?>">
			<p>
				<label for="google_authenticator_code">認証コード</label>
				<input type="text" name="google_authenticator_code" id="google_authenticator_code" class="input"
						value="" size="20" autocomplete="one-time-code"/>
			</p>
			<script type="text/javascript">document.getElementById("google_authenticator_code").focus();</script>
			<p>デバイスのGoogle Authenticator アプリケーションに表示されている6桁の認証コードを入力してください。</p>
			<p class="submit">
				<?php wp_nonce_field( $this->get_feature_key() . '_csrf' ); ?>
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
						value="<?php esc_attr_e( 'Log In' ); ?>"/>
				<input type="hidden" name="redirect_to"
						value="<?php echo esc_attr( sanitize_text_field( $_REQUEST['redirect_to'] ?? admin_url() ) ); ?>"/>
				<input type="hidden" name="testcookie" value="1"/>
			</p>
		</form>
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
		$secret = get_user_option( 'cloudsecurewp_two_factor_authentication_secret', $user->ID );

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
			$value = get_user_meta( $user_id, 'wp_cloudsecurewp_two_factor_authentication_secret', true );
			return $value !== '' ? '設定済' : '未設定';
		}
		return $value;
	}

	/**
	 * ユーザの2faシークレットキー取得
	 *
	 * @param int $user_id
	 *
	 * @return mixed
	 */
	private function get_2fa_secret_key( int $user_id ) {
		return get_user_option( 'cloudsecurewp_two_factor_authentication_secret', $user_id );
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

		// 2faシークレットキーが存在しない場合
		if ( ! $this->get_2fa_secret_key( $user->ID ) ) {
			return false;
		}

		return true;
	}

	/**
	 * 2段階認証画面を表示
	 *
	 * @param string $login_token
	 *
	 * @return void
	 */
	private function show_two_factor_form( string $login_token ) {
		// 2FA画面を表示
		login_header( '2段階認証画面' );
		$this->login_error();
		$this->login_form( $login_token );
		login_footer();
		exit;
	}

	/**
	 * POSTデータから2FA関連の値を安全に取得
	 *
	 * @return array
	 */
	private function get_2fa_post_data(): array {
		return array(
			'login_token'                => sanitize_text_field( $_POST['login_token'] ?? '' ),
			'google_authenticator_code'  => sanitize_text_field( $_POST['google_authenticator_code'] ?? '' ),
		);
	}

	/**
	 * 2段階認証コード検証処理
	 *
	 * @param int    $user_id
	 * @param string $code
	 *
	 * @return bool
	 */
	private function verify_2fa_code( int $user_id, string $code ): bool {

		// 2faシークレットキー取得
		$secret_key = $this->get_2fa_secret_key( $user_id );

		// 2faシークレットキーが存在しない場合
		if ( ! $secret_key ) {
			return true;
		}

		// 2段階認証コードが有効な場合
		if ( CloudSecureWP_Time_Based_One_Time_Password::verify_code( $secret_key, $code, 2 ) ) {
			return true;
		}

		// 認証失敗
		return false;
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
		if ( ! isset( $_POST['google_authenticator_code'] ) ) {
			return $username;
		}

		// 2FA関連のPOSTデータ取得
		$post_data = $this->get_2fa_post_data();

		// ログイン情報を取得
		$option_key  = $this->create_option_key( $post_data['login_token'] );
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
		if ( ! isset( $_POST['google_authenticator_code'] ) ) {
			return $user;
		}

		// CSRFトークンを検証（失敗すると「辿ったリンクは期限が切れています。」のエラー画面を表示し処理終了）
		check_admin_referer( $this->get_feature_key() . '_csrf' );

		// 2FA関連のPOSTデータ取得
		$post_data = $this->get_2fa_post_data();

		// ログイン情報を取得
		$option_key  = $this->create_option_key( $post_data['login_token'] );
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

		// ログイン情報のPOSTデータ復元
		$_POST['log'] = $option_data['user_login'];

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
		if ( ! isset( $_POST['google_authenticator_code'] ) ) {

			// 認証失敗の場合
			if ( is_wp_error( $user ) ) {
				return $user;
			}

			// 2段階認証が不要な場合
			if ( ! $this->is_2fa_required( $user ) ) {
				return $user;
			}

			// option key生成
			$session_token = bin2hex( random_bytes( 16 ) );
			$option_key    = $this->create_option_key( $session_token );

			// 保存用認証データ作成
			$option_data = array(
				'user_id'    => $user->ID,
				'user_login' => sanitize_text_field( $_POST['log'] ?? '' ),
				'expires'    => time() + self::SESSION_EXPIRY,
				'created'    => time(),
			);

			// データを保存
			$this->set_option_data( $option_key, $option_data );

			// 2FA画面を表示して、処理終了
			$this->show_two_factor_form( $session_token );
		}

		// 2FA関連のPOSTデータ取得
		$post_data = $this->get_2fa_post_data();

		// option key取得
		$option_key = $this->create_option_key( $post_data['login_token'] );

		// $userがWP_Errorの場合は処理をスキップ
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		// 2段階認証成功の場合
		if ( $this->verify_2fa_code( $user->ID, $post_data['google_authenticator_code'] ) ) {
			$this->delete_option_data( $option_key );
			return $user;
		}

		// ログイン失敗時の処理を実行（ログイン回数・ログインログ）
		do_action( 'wp_login_failed', $_POST['log'], $user );

		// 2FA画面を再表示して、処理終了
		$this->show_two_factor_form( $post_data['login_token'] );
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
					'ip'       => $this->get_client_ip( '' ),
					'status'   => self::LOGIN_STATUS_FAILED,
					'method'   => 1,
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
}
