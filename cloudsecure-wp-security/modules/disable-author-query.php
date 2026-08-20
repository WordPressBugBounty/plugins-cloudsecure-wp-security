<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Disable_Author_Query extends CloudSecureWP_Common {
	private const KEY_FEATURE = 'disable_author_query';
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
			self::KEY_FEATURE => $this->check_environment() ? 't' : 'f',
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
	 * author_query
	 *
	 * @param WP_Query $query
	 * @return void
	 */
	public function pre_get_posts( $query ) {
		if ( is_admin() || ! $query->is_main_query() ) {
			return;
		}

		// URL クエリ（?author=）由来で、WordPress が数値 author として作者アーカイブに解決したものだけを遮断する。
		if ( $query->is_author() && isset( $_GET['author'] ) && '' !== $_GET['author'] && '' !== $query->get( 'author' ) ) {
			wp_safe_redirect( home_url( self::PAGE_404 ) );
			exit;
		}
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
