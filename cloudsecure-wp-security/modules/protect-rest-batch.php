<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST APIバッチエンドポイント（/batch/v1）への未認証アクセスを拒否する
 *
 * WordPressコアの脆弱性 wp2shell（CVE-2026-63030: バッチAPIのルート混同 + CVE-2026-60137: SQLi）
 * による未認証RCEの緩和パッチ。設定を持たず、対応環境（非マルチサイト・競合プラグインなし）で
 * プラグインが動作していれば常時有効。根本対策はWordPressコアの更新（6.8.6以上 / 6.9.5以上 / 7.0.2以上）。
 */
class CloudSecureWP_Protect_REST_Batch extends CloudSecureWP_Common {
	private const ERROR_CODE  = 'protect_rest_batch';
	private const BATCH_ROUTE = '/batch/v1';

	function __construct( array $info ) {
		parent::__construct( $info );
	}

	/**
	 * rest_pre_dispatch
	 * バッチエンドポイントへの未認証アクセスを拒否する
	 */
	function rest_pre_dispatch( $result, $server, $request ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		if ( ! $this->is_batch_route( $request->get_route() ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		return new WP_Error( self::ERROR_CODE, 'REST APIバッチ機能への未認証アクセスは許可されていません', array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * バッチエンドポイントのルート判定
	 *
	 * コアのルートマッチングとのズレを埋めるため、判定前に3点の正規化を行う。
	 * - strtolower: コアの正規表現は大文字小文字を区別しない（`@...@i`）ため、`/BATCH/V1` 等を取りこぼさない
	 * - trim: コアの正規表現は D 修飾子が無く、末尾の `$` が末尾改行の直前にもマッチする。このため
	 *   `/batch/v1\n`（例: `?rest_route=/batch/v1%0a`）はコアではバッチにディスパッチされるが、
	 *   厳格な文字列一致では取りこぼす。末尾の空白・制御文字を除去してこのバイパスを防ぐ
	 * - untrailingslashit: 末尾スラッシュ（`/batch/v1/`）を正規化する
	 *
	 * @param string $route
	 * @return bool
	 */
	public function is_batch_route( string $route ): bool {
		$route = strtolower( untrailingslashit( trim( $route ) ) );

		if ( self::BATCH_ROUTE === $route ) {
			return true;
		}

		return strpos( $route, self::BATCH_ROUTE . '/' ) === 0;
	}
}
