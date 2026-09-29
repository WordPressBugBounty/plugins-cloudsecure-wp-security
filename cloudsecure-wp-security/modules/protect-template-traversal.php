<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * テンプレート候補からパストラバーサルを含むものを除外する（WordPressコア脆弱性の緩和パッチ）
 */
class CloudSecureWP_Protect_Template_Traversal extends CloudSecureWP_Common {
	/**
	 * 検査するテンプレート種別（コアが名前を urldecode() して候補を作る種別）
	 */
	public const TEMPLATE_TYPES = array( 'page', 'single', 'category', 'tag', 'taxonomy' );

	/**
	 * パス要素が ".." （ドット・スペース変種を含む）であるかを判定する正規表現
	 */
	private const TRAVERSAL_PATTERN = '#(?:^|/)\.\.[. ]*(?:/|$)#';

	function __construct( array $info ) {
		parent::__construct( $info );
	}

	/**
	 * {$type}_template_hierarchy（優先度1）: パストラバーサルを含む候補を除外する
	 */
	public function template_hierarchy( $templates ) {
		if ( ! is_array( $templates ) ) {
			return $templates;
		}

		$kept    = array();
		$removed = false;
		foreach ( $templates as $template ) {
			if ( $this->has_traversal( $template ) ) {
				$removed = true;
				continue;
			}
			$kept[] = $template;
		}

		return $removed ? $kept : $templates;
	}

	/**
	 * {$type}_template_hierarchy（PHP_INT_MAX）: ".." を含む候補のうち、実在しテーマ等の配下に解決するものだけ残す
	 */
	public function template_hierarchy_final( $templates ) {
		if ( ! is_array( $templates ) ) {
			return $templates;
		}

		$kept    = array();
		$removed = false;
		foreach ( $templates as $template ) {
			if ( ! is_string( $template ) || 1 !== preg_match( self::TRAVERSAL_PATTERN, wp_normalize_path( $template ) ) ) {
				$kept[] = $template;
				continue;
			}

			$template_path = $this->locate_template_candidate( $template );
			if ( '' === $template_path || ! $this->is_template_path_allowed( $template_path ) ) {
				$removed = true;
				continue;
			}

			$kept[] = $template;
		}

		return $removed ? $kept : $templates;
	}

	/**
	 * locate_template() と同じ探索順で候補の既存ファイルのパスを返す（無ければ空文字列）
	 */
	private function locate_template_candidate( $template ): string {
		if ( ! is_string( $template ) || '' === $template ) {
			return '';
		}

		global $wp_stylesheet_path, $wp_template_path;

		if ( ! isset( $wp_stylesheet_path, $wp_template_path ) ) {
			if ( function_exists( 'wp_set_template_globals' ) ) {
				wp_set_template_globals();
			} else {
				$wp_stylesheet_path = STYLESHEETPATH;
				$wp_template_path   = TEMPLATEPATH;
			}
		}

		$directories = array( $wp_stylesheet_path );
		if ( is_child_theme() ) {
			$directories[] = $wp_template_path;
		}
		$directories[] = ABSPATH . WPINC . '/theme-compat';

		foreach ( $directories as $directory ) {
			$path = $directory . '/' . $template;
			if ( file_exists( $path ) ) {
				return $path;
			}
		}

		return '';
	}

	/**
	 * 既存テンプレートの実パスが許可ディレクトリ（テーマ・theme-compat）配下にあるか
	 */
	private function is_template_path_allowed( string $path ): bool {
		if ( 0 === preg_match( self::TRAVERSAL_PATTERN, wp_normalize_path( $path ) ) ) {
			return true;
		}

		$real_path = realpath( $path );
		if ( false === $real_path ) {
			return false;
		}
		$real_path = trailingslashit( wp_normalize_path( $real_path ) );

		global $wp_stylesheet_path, $wp_template_path;
		$directories = array(
			$wp_stylesheet_path,
			$wp_template_path,
			ABSPATH . WPINC . '/theme-compat',
		);

		if ( false !== strpos( get_stylesheet(), '/' ) ) {
			$directories[] = dirname( $wp_stylesheet_path );
		}
		if ( false !== strpos( get_template(), '/' ) ) {
			$directories[] = dirname( $wp_template_path );
		}

		foreach ( $directories as $directory ) {
			$real_directory = realpath( $directory );
			if ( false === $real_directory ) {
				continue;
			}

			$allowed_path = trailingslashit( wp_normalize_path( $real_directory ) );
			if ( 0 === strpos( $real_path, $allowed_path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * 候補名がパストラバーサルとして拒否されるか（文字列以外は false）
	 */
	public function has_traversal( $template ): bool {
		if ( ! is_string( $template ) ) {
			return false;
		}
		$template = wp_normalize_path( $template );

		return 0 !== validate_file( $template )
			|| 1 === preg_match( self::TRAVERSAL_PATTERN, $template );
	}
}
