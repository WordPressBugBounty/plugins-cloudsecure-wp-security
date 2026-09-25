<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Rename_Login_Page extends CloudSecureWP_Common {
	private const KEY_FEATURE          = 'rename_login_page';
	private const KEY_NAME             = self::KEY_FEATURE . '_name';
	private const KEY_DISABLE_REDIRECT = self::KEY_FEATURE . '_disable_redirect';
	private $config;
	private $htaccess;
	private $login_allowed = false;

	function __construct( array $info, CloudSecureWP_Config $config, CloudSecureWP_Htaccess $htaccess ) {
		parent::__construct( $info );
		$this->config   = $config;
		$this->htaccess = $htaccess;
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
		return $this->config->get( $this->get_feature_key() ) === 't' ? true : false;
	}

	/**
	 * 初期設定値取得
	 *
	 * @return array
	 */
	public function get_default(): array {
		$ret = array(
			self::KEY_FEATURE          => 'f',
			self::KEY_NAME             => $this->get_new_name(),
			self::KEY_DISABLE_REDIRECT => 'f',
		);
		return $ret;
	}

	/**
	 * 設定値key取得
	 */
	public function get_keys(): array {
		$ret = array(
			self::KEY_FEATURE,
			self::KEY_NAME,
			self::KEY_DISABLE_REDIRECT,
		);
		return $ret;
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
	 * @return void
	 */
	public function save_settings( $settings ): void {
		$keys = $this->get_keys();

		foreach ( $keys as $key ) {
			$this->config->set( $key, $settings[ $key ] ?? '' );
		}

		$this->config->save();
	}

	/**
	 * ランダム値を含んだ新しいログインページ名を取得
	 *
	 * @return string $name
	 */
	public function get_new_name(): string {
		$name  = '';
		$chars = '0123456789abcdefghijklmnopqrstuvwxyz-_';
		$max   = strlen( $chars ) - 1;

		for ( $ii = 0; $ii < 8; $ii ++ ) {
			try {
				$index = random_int( 0, $max );
			} catch ( Exception $e ) {
				$index = wp_rand( 0, $max );
			}
			$name .= $chars[ $index ];
		}

		return $name;
	}

	/**
	 * ファイル名重複判定
	 *
	 * @param string $name
	 */
	public function is_duplicat_file( string $name ): bool {
		$files = array_diff( scandir( ABSPATH ), array( '.', '..' ) );

		if ( in_array( $name, $files ) ) {
			return true;
		}

		return false;
	}

	/**
	 * htaccessに書き出す設定を取得
	 *
	 * @return string
	 */
	private function get_htaccess_settings(): string {
		$parse   = parse_url( site_url() );
		$base    = ( $parse['path'] ?? '' ) . '/';
		$name    = $this->config->get( self::KEY_NAME );
		$page404 = self::PAGE_404;

		$setting  = "<IfModule mod_rewrite.c>" . "\n";
		$setting .= "    RewriteEngine on" . "\n";
		$setting .= "    RewriteBase {$base}" . "\n";
		$setting .= "    RewriteRule ^wp-activate\.php {$page404} [L]" . "\n";
		$setting .= "    RewriteRule ^wp-signup\.php {$page404} [L]" . "\n";
		$setting .= "    RewriteRule ^{$name}(.*)$ wp-login.php$1 [L]" . "\n";
		$setting .= "</IfModule>" . "\n";

		return $setting;
	}

	/**
	 * htaccessに書き出す設定を更新
	 *
	 * @return bool
	 */
	public function update_htaccess(): bool {
		$plugin_tag = $this->htaccess->get_plugin_settings_tag();
		$tag        = $this->get_feature_key();

		if ( $this->htaccess->setting_tag_exists( $plugin_tag ) ) {
			if ( $this->htaccess->setting_tag_exists( $tag ) ) {
				if ( ! $this->remove_htaccess() ) {
					return false;
				}
			}
		} else {
			$this->htaccess->add_plugin_settings_tag();
		}

		$setting = $this->get_htaccess_settings();
		$ret     = $this->htaccess->add_feature_setting( $tag, $setting );

		return $ret;
	}

	/**
	 * htaccessから設定を削除
	 *
	 * @return bool
	 */
	public function remove_htaccess(): bool {
		return $this->htaccess->remove_settings( array( $this->get_feature_key() ) );
	}

	/**
	 * login_init
	 */
	public function login_init() {
		// 他プラグインが自前ページで login_init を発火させる場合は対象外
		if ( $this->is_other_script() ) {
			return;
		}

		$name = $this->get_valid_login_name();

		if ( '' !== $name ) {
			if ( $this->is_login_url_path( $this->get_request_path(), $name ) ) {
				$this->login_allowed = true;
				return;
			}

			if ( $this->is_login_url_path( $this->get_referer_path(), $name ) ) {
				wp_safe_redirect( $this->get_login_url_path( $name ) . $this->get_request_query() );
				exit;
			}
		}

		$this->page404();
		exit;
	}

	/**
	 * 実行中のスクリプトが wp-login.php 以外か（wp-login.php は login_init より前に login_header() を定義する）
	 *
	 * @return bool
	 */
	private function is_other_script(): bool {
		return ! function_exists( 'login_header' );
	}

	/**
	 * 設定されたログイン名を検証して取得（不正な場合は空文字）
	 *
	 * @return string
	 */
	private function get_valid_login_name(): string {
		$name = $this->config->get( self::KEY_NAME );

		if ( ! is_string( $name ) || 1 !== preg_match( '/\A[a-z0-9_\-]{4,12}\z/', $name ) ) {
			return '';
		}

		return $name;
	}

	/**
	 * パスが新しいログインURL（site_url のパス + /{ログイン名}。site_url のパス外なら /{ログイン名} 単独も可）で始まるか
	 *
	 * @param string $path クエリを除いたパス
	 * @param string $name ログイン名（検証済み）
	 * @return bool
	 */
	private function is_login_url_path( string $path, string $name ): bool {
		if ( '' === $path ) {
			return false;
		}

		$segments = $this->get_path_segments( $path );
		$base     = $this->get_path_segments( (string) wp_parse_url( site_url(), PHP_URL_PATH ) );
		$expected = array_merge( $base, array( $name ) );

		if ( array_slice( $segments, 0, count( $expected ) ) === $expected ) {
			return true;
		}

		// site_url のパスで始まるのに上で一致しなかったものは不許可（ディレクトリ名とログイン名が同じ場合の /{dir}/wp-login.php 等）
		if ( array() !== $base && array_slice( $segments, 0, count( $base ) ) === $base ) {
			return false;
		}

		// プロキシ等で接頭辞が除去される構成向けに /{ログイン名}... 単独も許可
		return array( $name ) === array_slice( $segments, 0, 1 );
	}

	/**
	 * パスをデコードしてスラッシュ区切りの配列にする（空要素と「.」は除き、「..」は解決する）
	 *
	 * @param string $path
	 * @return array
	 */
	private function get_path_segments( string $path ): array {
		$segments = array();

		foreach ( explode( '/', rawurldecode( $path ) ) as $segment ) {
			if ( '' === $segment || '.' === $segment ) {
				continue;
			}

			if ( '..' === $segment ) {
				array_pop( $segments );
				continue;
			}

			$segments[] = $segment;
		}

		return $segments;
	}

	/**
	 * URLからクエリを除いたパスを取得（絶対URLならパス部分のみ）
	 *
	 * @param string $url
	 * @return string
	 */
	private function extract_path( string $url ): string {
		$path = explode( '?', $url, 2 )[0];

		if ( 1 === preg_match( '#\A[a-z][a-z0-9+.\-]*://#i', $path ) ) {
			$path = (string) wp_parse_url( $path, PHP_URL_PATH );
		}

		return $path;
	}

	/**
	 * REQUEST_URI のパス取得
	 *
	 * @return string
	 */
	private function get_request_path(): string {
		$request_uri = $_SERVER['REQUEST_URI'] ?? '';

		if ( ! is_string( $request_uri ) ) {
			return '';
		}

		return $this->extract_path( wp_unslash( $request_uri ) );
	}

	/**
	 * REQUEST_URI のクエリ取得（「?」付き。無ければ空文字）
	 *
	 * @return string
	 */
	private function get_request_query(): string {
		$request_uri = $_SERVER['REQUEST_URI'] ?? '';

		if ( ! is_string( $request_uri ) ) {
			return '';
		}

		$parts = explode( '?', wp_unslash( $request_uri ), 2 );

		return isset( $parts[1] ) && '' !== $parts[1] ? '?' . $parts[1] : '';
	}

	/**
	 * リファラのパス取得（検証済みリファラ。文字列以外は空文字）
	 *
	 * @return string
	 */
	private function get_referer_path(): string {
		if ( isset( $_REQUEST['_wp_http_referer'] ) && ! is_string( $_REQUEST['_wp_http_referer'] ) ) {
			return '';
		}

		$referer = wp_get_referer();

		if ( ! is_string( $referer ) ) {
			return '';
		}

		return $this->extract_path( $referer );
	}

	/**
	 * 新しいログインURLの相対パス取得（誘導先）
	 *
	 * @param string $name ログイン名（検証済み）
	 * @return string
	 */
	private function get_login_url_path( string $name ): string {
		$path = (string) wp_parse_url( site_url( '/' . $name ), PHP_URL_PATH );

		return '' === $path ? '/' . $name : $path;
	}

	/**
	 * site_url
	 */
	public function site_url( $url, $path, $scheme, $blog_id ) {
		return $this->replace_wp_login( $url );
	}

	/**
	 * network_site_url
	 */
	public function network_site_url( $url, $path, $scheme ) {
		return $this->replace_wp_login( $url );
	}

	/**
	 * wp_redirect
	 * 新ログインURL経由のログインページ処理中だけ置換する（それ以外のリダイレクト先に含まれる wp-login.php はそのまま）
	 */
	public function wp_redirect( $location, $status ) {
		if ( ! $this->login_allowed ) {
			return $location;
		}

		return $this->replace_wp_login( $location );
	}

	/**
	 * register
	 */
	public function register( $link ) {
		return $this->replace_wp_login( $link );
	}

	/**
	 * auth_redirect_scheme
	 */
	public function auth_redirect_scheme( $scheme ) {
		if ( 't' === $this->config->get( self::KEY_DISABLE_REDIRECT ) ) {
			if ( ! wp_validate_auth_cookie( '', $scheme ) ) {
				wp_safe_redirect( home_url( self::PAGE_404 ) );
				exit;
			}
		}
		return $scheme;
	}

	/**
	 * wp-register.phpのアクセスを404にリダイレクト
	 */
	public function wp_register_404() {
		$request_uri = sanitize_url( $_SERVER['REQUEST_URI'] ?? '' );

		if ( false !== strpos( $request_uri, 'wp-register.php' ) ) {
			wp_safe_redirect( home_url( self::PAGE_404 ) );
			exit;
		}
	}

	/**
	 * ログインページ名を書き換え
	 *
	 * @param string $uri
	 * @return string $new_uri
	 */
	private function replace_wp_login( $uri ) {
		$uri = str_replace( 'wp-login.php', $this->config->get( self::KEY_NAME ), $uri );
		return $uri;
	}

	/**
	 * 管理画面に通知表示
	 */
	public function admin_notices() {
		$feature = 'ログインURL変更';
		$this->prepare_admin_notices( self::KEY_FEATURE, $feature );
	}

	/**
	 * メール通知
	 *
	 * @return void
	 */
	public function notification( $name ) {
		$login_url = site_url() . '/' . $name;
		$subject   = 'ログインURL変更';

		$body  = "新しいログインURLは、以下のとおりです。" . "\n";
		$body .= "必要に応じてブックマークをお願いいたします。" . "\n";
		$body .= "" . "\n";
		$body .= "{$login_url}" . "\n";
		$body .= "" . "\n";
		$body .= "--" . "\n";
		$body .= "CloudSecure WP Security" . "\n";

		$admins = $this->get_admin_users();

		foreach ( $admins as $admin ) {
			$this->wp_send_mail( $admin->user_email, esc_html( $subject ), esc_html( $body ) );
		}
	}

	/**
	 * 有効化
	 *
	 * @return void
	 */
	public function activate(): void {
		$settings = $this->get_default();
		$this->save_settings( $settings );

		if ( $this->is_enabled() ) {
			if ( ! $this->update_htaccess() ) {
				$settings[ $this->get_feature_key() ] = 'f';
			}
		}
		$this->save_settings( $settings );

		if ( 't' === $this->config->get( $this->get_feature_key() ) ) {
			$this->notification( $settings[ self::KEY_NAME ] );
		}
	}

	/**
	 * 無効化
	 *
	 * @return void
	 */
	public function deactivate(): void {
		$this->remove_htaccess();
		$this->config->set( self::KEY_FEATURE, 'f' );
		$this->config->save();
	}
}
