<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Htaccess extends CloudSecureWP_Common {
	private const FILE_PATH           = ABSPATH . '.htaccess';
	private const TAG_PLUGIN_SETTINGS = 'CloudSecure WP Security Settings';
	private const TAG_WP_SETTINGS     = 'WordPress';
	private const TAG_PREFIX_START    = '# BEGIN ';
	private const TAG_PREFIX_END      = '# END ';
	private $htaccess_enabled         = null;

	function __construct( array $info ) {
		parent::__construct( $info );
	}

	/**
	 * .htaccessファイルの存在確認
	 *
	 * @return bool
	 */
	private function is_exists(): bool {
		if ( false !== file_exists( self::FILE_PATH ) ) {
			return true;
		}
		return false;
	}

	/**
	 * .htaccessファイルコンテンツ取得
	 *
	 * @return string
	 */
	private function load_contents(): string {
		if ( $this->is_exists() ) {

			$contents = file_get_contents( self::FILE_PATH );

			if ( false !== $contents ) {
				return $contents;
			}
		}
		return '';
	}

	/**
	 * .htaccessファイルコンテンツを上書き
	 *
	 * @param string $contents
	 * @return bool
	 */
	public function save_contents( string $contents ): bool {
		if ( ! empty( $contents ) ) {
			if ( @file_put_contents( self::FILE_PATH, $contents ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * .htaccessファイルの有効判定
	 *
	 * @return bool
	 */
	public function is_enabled(): bool {
		if ( is_null( $this->htaccess_enabled ) ) {
			if ( is_writable( self::FILE_PATH ) ) {
				$this->htaccess_enabled = true;
			} else {
				$this->htaccess_enabled = false;
			}
		}

		return $this->htaccess_enabled;
	}

	/**
	 * htaccess用設定のマッチパターンを取得
	 *
	 * @param string $tag
	 * @return string
	 */
	private function get_setting_pattern( string $tag ): string {
		return '/' . self::TAG_PREFIX_START . $tag . '.*?' . self::TAG_PREFIX_END . $tag . '\r?\n/s';
	}

	/**
	 * プラグイン設定タグ取得
	 */
	public function get_plugin_settings_tag(): string {
		return self::TAG_PLUGIN_SETTINGS;
	}

	/**
	 * .htaccessプラグイン設定の存在確認
	 *
	 * @param string $tag
	 * @return bool
	 */
	public function setting_tag_exists( string $tag ): bool {
		$contents = $this->load_contents();
		if ( ! empty( $contents ) ) {

			$pattern = $this->get_setting_pattern( $tag );
			if ( preg_match( $pattern, $contents ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * プラグイン設定を.htaccessから削除
	 *
	 * @param array<string> $tags
	 * @return bool
	 */
	public function remove_settings( array $tags ): bool {
		$contents = $this->load_contents();
		if ( ! empty( $contents ) ) {
			$old = $tmp = $contents;

			foreach ( $tags as $tag ) {
				$pattern = $this->get_setting_pattern( $tag );
				$tmp     = preg_replace( $pattern, '', $tmp );
			}

			if ( $old === $tmp ) {
				return true;

			} else {
				$contents = $tmp;

				if ( false !== $this->save_contents( $contents ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * プラグイン用htaccess設定タグ追加
	 */
	public function add_plugin_settings_tag(): bool {
		$contents = $this->load_contents();

		if ( ! empty( $contents ) ) {
			$plugin_setting  = self::TAG_PREFIX_START . $this->get_plugin_settings_tag() . "\n";
			$plugin_setting .= self::TAG_PREFIX_END . $this->get_plugin_settings_tag() . "\n";
			$wp_tag_start    = self::TAG_PREFIX_START . self::TAG_WP_SETTINGS;
			$new_contents    = preg_replace(
				'/' . preg_quote( $wp_tag_start, '/' ) . '/',
				addcslashes( $plugin_setting . $wp_tag_start, '\\$' ),
				$contents,
				1,
				$count
			);

			if ( 0 === $count ) {
				return false;
			}

			if ( false !== $this->save_contents( $new_contents ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 各機能用htaccess設定追加
	 *
	 * @param string $tag
	 * @param string $setting
	 * @return bool
	 */
	public function add_feature_setting( string $tag, string $setting ): bool {
		$contents = $this->load_contents();

		if ( ! empty( $contents ) ) {
			$add_setting    = self::TAG_PREFIX_START . $tag . "\n";
			$add_setting   .= $setting;
			$add_setting   .= self::TAG_PREFIX_END . $tag . "\n";
			$plugin_tag_end = self::TAG_PREFIX_END . $this->get_plugin_settings_tag();
			$new_contents   = preg_replace(
				'/' . preg_quote( $plugin_tag_end, '/' ) . '/',
				addcslashes( $add_setting . $plugin_tag_end, '\\$' ),
				$contents,
				1,
				$count
			);

			if ( 0 === $count ) {
				return false;
			}

			if ( false !== $this->save_contents( $new_contents ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CloudSecure WP Security Settingsブロックを再配置
	 *
	 * @return void
	 */
	public function reorganize_plugin_settings_blocks(): void {
		// .htaccessファイルの内容を取得
		$contents = $this->load_contents();
		if ( empty( $contents ) ) {
			return;
		}

		// CloudSecure WP Security Settingsブロックをすべて取得
		$plugin_pattern = $this->get_setting_pattern( self::TAG_PLUGIN_SETTINGS );
		$matches        = array();

		$result = preg_match_all( $plugin_pattern, $contents, $matches );
		if ( false === $result || 0 === $result ) {
			// ブロックを取得できなかった場合
			return;
		}

		// 見つかったブロックから1番目のブロックを取得
		$found_blocks = $matches[0];
		$first_block  = $found_blocks[0];

		// すべてのCloudSecure WP Security Settingsブロックを削除
		$contents_without_blocks = preg_replace(
			$plugin_pattern,
			'',
			$contents,
			-1,
			$count
		);
		if ( is_null( $contents_without_blocks ) || 0 === $count ) {
			// ブロックを削除できなかった場合
			return;
		}

		// WordPressブロックの開始タグを探して、その直前にプラグインブロックを挿入
		$wp_tag_start = self::TAG_PREFIX_START . self::TAG_WP_SETTINGS;
		$new_contents = preg_replace(
			'/' . preg_quote( $wp_tag_start, '/' ) . '/',
			addcslashes( $first_block . $wp_tag_start, '\\$' ),
			$contents_without_blocks,
			1,
			$count
		);
		if ( is_null( $new_contents ) || 0 === $count ) {
			// ブロックを挿入できなかった場合
			return;
		}

		// .htaccessファイルに保存
		$this->save_contents( $new_contents );
	}
}
