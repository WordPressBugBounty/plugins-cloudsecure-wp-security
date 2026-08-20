<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Disable_RESTAPI extends CloudSecureWP_Common {
	private const KEY_FEATURE     = 'disable_rest_api';
	private const KEY_EXCLUDE     = self::KEY_FEATURE . '_exclude';
	private const DEFAULT_EXCLUDE = array( 'oembed', 'contact-form-7', 'akismet' );

	/**
	 * 除外名から追加で許可するルートプレフィックスへの読み替え表
	 *
	 * テーマ名・プラグイン名とREST APIの名前空間が一致しないものを登録する。
	 * 素の「/除外名/」前方一致に加えて、ここで定義したプレフィックスも許可される。
	 * ※テーマ側のアップデートで名前空間が変わると除外が壊れるため、対象テーマの
	 *   register_rest_route() を確認してから変更すること。
	 */
	private const EXCLUDE_ALIASES = array(
		// プラグイン
		'snow-monkey-forms' => array( '/snow-monkey-form/' ),
		'woocommerce'       => array( '/wc/' ),
		// テーマ
		'swell'             => array( '/wp/v2/swell-' ),
		'snow-monkey'       => array( '/wp-oembed-blog-card/' ),
		'emanon'            => array( '/emanon-ai/' ),
		'nishiki_pro'       => array( '/nishiki-pro/' ),
	);
	private $config;

	function __construct( array $info, CloudSecureWP_Config $config ) {
		parent::__construct( $info );
		$this->config = $config;
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
			self::KEY_FEATURE => 'f',
			self::KEY_EXCLUDE => self::DEFAULT_EXCLUDE,
		);
		return $ret;
	}

	/**
	 * 設定値取得
	 */
	public function get_settings(): array {
		$settings = array();
		$default  = $this->get_default();

		foreach ( $default as $key => $val ) {
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
		$default = $this->get_default();

		foreach ( $default as $key => $val ) {
			$this->config->set( $key, $settings[ $key ] ?? '' );
		}

		$this->config->save();
	}

	/**
	 * 除外指定していない有効なプラグイン名リスト取得
	 *
	 * @return array
	 */
	public function get_active_plugin_names(): array {
		$plugin_names    = array();
		$plugins         = get_plugins();
		$exclude_plugins = $this->config->get( self::KEY_EXCLUDE );

		if ( ! is_array( $exclude_plugins ) ) {
			$exclude_plugins = array();
		}
		$exclude_plugins = $this->normalize_exclude_names( $exclude_plugins );

		if ( ! empty( $plugins ) ) {
			foreach ( $plugins as $plugin_path => $plugin ) {
				// プラグイン名取得
				$plugin_name = $plugin['TextDomain'];
				if ( $plugin['Name'] === 'Hello Dolly' ) {
					// Hello Dolly対応
					$plugin_name = 'hello-dolly';
				}

				if ( is_plugin_active( $plugin_path ) ) {
					if ( false === in_array( strtolower( $plugin_name ), $exclude_plugins, true ) && $plugin_name !== $this->info['text_domain'] ) {
						$plugin_names[] = $plugin_name;
					}
				}
			}
		}

		return $plugin_names;
	}

	/**
	 * 除外指定していない有効なテーマ名リスト取得
	 *
	 * 子テーマが有効な場合はREST APIを提供する親テーマを対象にする。
	 * テーマ名はText Domainを使用し、未定義の場合はテーマディレクトリ名を使用する。
	 *
	 * @return array
	 */
	public function get_active_theme_names(): array {
		$theme = wp_get_theme();

		// 子テーマの場合は親テーマを対象にする
		$parent = $theme->parent();
		if ( false !== $parent ) {
			$theme = $parent;
		}

		$theme_name = (string) $theme->get( 'TextDomain' );
		if ( '' === $theme_name ) {
			$theme_name = (string) $theme->get_stylesheet();
		}

		if ( '' === $theme_name ) {
			return array();
		}

		$exclude_names = $this->config->get( self::KEY_EXCLUDE );
		if ( ! is_array( $exclude_names ) ) {
			$exclude_names = array();
		}

		if ( in_array( strtolower( $theme_name ), $this->normalize_exclude_names( $exclude_names ), true ) ) {
			return array();
		}

		return array( $theme_name );
	}

	/**
	 * テキストから配列に変換
	 *
	 * @param string $text
	 * @return array
	 */
	public function text2Array( string $text ): array {
		$searchs    = array( "\r\n", "\r" );
		$text       = str_replace( $searchs, "\n", $text );
		$text_array = explode( "\n", $text );

		foreach ( $text_array as &$name ) {
			$name = trim( $name );
		}
		unset( $name );

		$text_array = array_filter( $text_array, 'strlen' );
		$text_array = array_unique( $text_array );

		return $text_array;
	}

	/**
	 * 除外名リストの正規化
	 *
	 * 候補一覧の除外済み判定を、実際の除外判定（rest_pre_dispatch）と同じ
	 * 規則（strtolower + trim）で行うために使用する。規則が食い違うと、
	 * 大文字・空白付きで保存された除外名が「除外は効くのに候補一覧へ出続ける」状態になる。
	 *
	 * @param array $names
	 * @return array
	 */
	private function normalize_exclude_names( array $names ): array {
		$normalized = array();

		foreach ( $names as $name ) {
			if ( ! is_string( $name ) ) {
				continue;
			}

			$name = strtolower( trim( $name ) );
			if ( '' !== $name ) {
				$normalized[] = $name;
			}
		}

		return $normalized;
	}

	/**
	 * ルート文字列の正規化
	 *
	 * コアのルートマッチングは preg_match( '@^' . $route . '$@i', $path ) で行われるため、
	 * それより厳格な一致で判定すると除外指定がすり抜けて過剰ブロックになる。判定前に正規化する。
	 * - strtolower: コアの正規表現は大文字小文字を区別しない（`i`）ため
	 * - trim: コアの正規表現は D 修飾子が無く、末尾の `$` が末尾改行の直前にもマッチするため
	 * - untrailingslashit: 末尾スラッシュを正規化する
	 *
	 * @param string $route
	 * @return string
	 */
	private function normalize_route( string $route ): string {
		return strtolower( untrailingslashit( trim( $route ) ) );
	}

	/**
	 * rest_pre_dispatch
	 */
	function rest_pre_dispatch( $result, $server, $request ) {

		if ( current_user_can( 'edit_pages' ) || current_user_can( 'edit_posts' ) ) {
			return $result;
		}

		$setting       = $this->get_settings();
		$exclude_names = $setting[ self::KEY_EXCLUDE ];
		$route         = $this->normalize_route( (string) $request->get_route() );

		if ( ! is_array( $exclude_names ) ) {
			$exclude_names = array();
		}

		foreach ( $exclude_names as $name ) {
			if ( ! is_string( $name ) ) {
				continue;
			}

			$name = strtolower( trim( $name ) );
			if ( '' === $name ) {
				continue;
			}

			// 素の名前空間前方一致に加え、読み替え表のプレフィックスも許可する
			$prefixes = array_merge( array( "/{$name}/" ), self::EXCLUDE_ALIASES[ $name ] ?? array() );

			foreach ( $prefixes as $prefix ) {
				if ( strpos( $route, $prefix ) === 0 ) {
					return $result;
				}
			}
		}

		return new WP_Error( $this->get_feature_key(), 'REST API が無効化されています', array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * 有効化
	 *
	 * @return void
	 */
	public function activate(): void {
		$this->save_settings( $this->get_default() );
	}

	/**
	 * 無効化
	 *
	 * @return void
	 */
	public function deactivate(): void {
		$this->config->set( $this->get_feature_key(), 'f' );
		$this->config->save();
	}
}
