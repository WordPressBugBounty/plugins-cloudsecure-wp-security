<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * TOTPアルゴリズムの2段階認証のためのクラス
 */
class CloudSecureWP_Time_Based_One_Time_Password {
	private static $digits      = 6;
	private static $discrepancy = 1;

	/**
	 * 指定されたシークレットと時点を使用してコードを計算
	 *
	 * @param string $secret
	 * @param int    $time_slice
	 *
	 * @return string
	 */
	public static function get_code( string $secret, int $time_slice ): string {
		// 16進数をバイナリデータに変換
		$secret_key = hex2bin( $secret );

		// 時間をバイナリ文字列にパック
		$time = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . pack( 'N*', $time_slice );
		// ユーザーの秘密鍵でハッシュ
		$hm = hash_hmac( 'SHA1', $time, $secret_key, true );
		// 結果の最後のニップルをインデックス/オフセットとして使用
		$offset = ord( substr( $hm, - 1 ) ) & 0x0F;
		// 結果の4バイトを取得
		$hash_part = substr( $hm, $offset, 4 );

		// バイナリ値を切り出す
		$value = unpack( 'N', $hash_part );
		$value = $value[1];
		// 32ビットのみ
		$value = $value & 0x7FFFFFFF;

		$modulo = pow( 10, self::$digits );

		return str_pad( $value % $modulo, self::$digits, '0', STR_PAD_LEFT );
	}

	/**
	 * コードが正しいかどうかを検証
	 * 前後1つ分の時間スライスを許容
	 *
	 * @param string $secret
	 * @param string $code
	 * @param int    $time_step 時間間隔（秒）デフォルトは30秒
	 *
	 * @return bool
	 */
	public static function verify_code( string $secret, string $code, int $time_step ): bool {
		$current_time_slice = floor( time() / $time_step );

		if ( strlen( $code ) !== 6 ) {
			return false;
		}

		for ( $i = - self::$discrepancy; $i <= self::$discrepancy; ++$i ) {
			$calculated_code = self::get_code( $secret, $current_time_slice + $i );
			if ( self::timing_safe_equals( $calculated_code, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Base32をデコード
	 *
	 * @param string $secret
	 *
	 * @return bool|string
	 */
	public static function base32_decode( $secret ) {
		if ( empty( $secret ) ) {
			return '';
		}

		$base32_chars         = str_split( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' );
		$base32_chars_flipped = array_flip( $base32_chars );

		$padding_char_count = substr_count( $secret, $base32_chars[32] );
		$allowed_values     = array( 6, 4, 3, 1, 0 );
		if ( ! in_array( $padding_char_count, $allowed_values ) ) {
			return false;
		}
		for ( $i = 0; $i < 4; ++$i ) {
			if ( $padding_char_count === $allowed_values[ $i ] &&
				substr( $secret, - ( $allowed_values[ $i ] ) ) !== str_repeat( $base32_chars[32], $allowed_values[ $i ] ) ) {
				return false;
			}
		}
		$secret        = str_replace( '=', '', $secret );
		$secret        = str_split( $secret );
		$binary_string = '';
		for ( $i = 0; $i < count( $secret ); $i = $i + 8 ) {
			$x = '';
			if ( ! in_array( $secret[ $i ], $base32_chars ) ) {
				return false;
			}
			for ( $j = 0; $j < 8; ++$j ) {
				$x .= str_pad( base_convert( @$base32_chars_flipped[ @$secret[ $i + $j ] ], 10, 2 ), 5, '0', STR_PAD_LEFT );
			}
			$eight_bits = str_split( $x, 8 );
			for ( $z = 0; $z < count( $eight_bits ); ++$z ) {
				$binary_string .= ( ( $y = chr( base_convert( $eight_bits[ $z ], 2, 10 ) ) ) || ord( $y ) === 48 ) ? $y : '';
			}
		}

		return $binary_string;
	}

	/**
	 * タイミングセーフの等価比較
	 * http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
	 *
	 * @param string $safe_string チェックする安全な値
	 * @param string $user_string ユーザーが送信した値
	 *
	 * @return bool 2つの文字列が同一かどうか
	 */
	private static function timing_safe_equals( string $safe_string, string $user_string ): bool {
		if ( function_exists( 'hash_equals' ) ) {
			return hash_equals( $safe_string, $user_string );
		}
		$safe_len = strlen( $safe_string );
		$user_len = strlen( $user_string );

		if ( $user_len !== $safe_len ) {
			return false;
		}

		$result = 0;

		for ( $i = 0; $i < $user_len; ++$i ) {
			$result |= ( ord( $safe_string[ $i ] ) ^ ord( $user_string[ $i ] ) );
		}

		// $resultが0のとき、同一の文字列となります...
		return $result === 0;
	}

	/**
	 * メール認証用のコードを生成
	 *
	 * @param string $secret
	 * @param int    $time_step 時間間隔（秒）
	 *
	 * @return string
	 */
	public static function create_code_for_email( string $secret, int $time_step ): string {

		// 現在の時間スライスを計算
		$time_slice = floor( time() / $time_step );

		// コードを生成
		return self::get_code( $secret, $time_slice );
	}

	/**
	 * Base32エンコード
	 *
	 * @param string $binary バイナリデータ
	 *
	 * @return string
	 */
	public static function base32_encode( string $binary ): string {
		if ( '' === $binary ) {
			return '';
		}

		$base32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$v            = 0;
		$vbits        = 0;
		$ret          = '';

		// 1. 5ビットずつ切り出して変換
		for ( $i = 0, $j = strlen( $binary ); $i < $j; $i++ ) {
			$v    <<= 8;
			$v     += ord( $binary[ $i ] );
			$vbits += 8;

			while ( $vbits >= 5 ) {
				$vbits -= 5;
				$ret   .= $base32_chars[ ( $v >> $vbits ) & 31 ];
			}
		}

		// 2. 余ったビットの処理
		if ( $vbits > 0 ) {
			$v  <<= ( 5 - $vbits );
			$ret .= $base32_chars[ $v & 31 ];
		}

		// 3. RFC 4648 に基づくパディング処理（デコーダーのチェックをパスするために必須）
		// Base32は8文字（40ビット）単位でブロックを作る必要がある
		$padding = ( 8 - ( strlen( $ret ) % 8 ) ) % 8;
		$ret    .= str_repeat( '=', $padding );

		return $ret;
	}

	/**
	 * ランダムな秘密鍵を生成
	 *
	 * @return array ['hex' => 16進数文字列, 'base32' => Base32文字列]
	 */
	public static function generate_secret_key(): array {
		// ランダムなバイナリデータを生成
		$binary = random_bytes( 10 );

		// 16進数に変換
		$hex = bin2hex( $binary );

		// Base32エンコード
		$base32 = self::base32_encode( $binary );

		return array(
			'hex'    => $hex,
			'base32' => $base32,
		);
	}
}
