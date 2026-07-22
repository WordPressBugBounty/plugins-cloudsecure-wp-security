<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Waf_Engine extends CloudSecureWP_Common {
	protected const VARIABLE_ARGS_GET              = 'args_get';
	protected const VARIABLE_ARGS_GET_NAMES        = 'args_get_names';
	protected const VARIABLE_ARGS_POST             = 'args_post';
	protected const VARIABLE_ARGS_POST_NAMES       = 'args_post_names';
	protected const VARIABLE_REQUEST_COOKIES       = 'request_cookies';
	protected const VARIABLE_REQUEST_COOKIES_NAMES = 'request_cookies_names';
	protected const VARIABLE_REQUEST_HEADERS       = 'request_headers';
	protected const VARIABLE_REQUEST_FILENAME      = 'request_filename';
	protected const VARIABLE_XML                   = 'xml';
	private $parsed_xml;
	private $request_body            = null;
	private $excluded_user_by_cookie = null;



	function __construct( array $info ) {
		parent::__construct( $info );

	}


	/**
	 * リクエストボディ（php://input）を取得する
	 * 同一リクエスト内でボディは不変のため、初回読み込み時にキャッシュして再読み込みを防ぐ
	 *
	 * @return string
	 */
	private function get_request_body(): string {
		if ( null === $this->request_body ) {
			$this->request_body = (string) file_get_contents( 'php://input' );
		}

		return $this->request_body;
	}


	/**
	 * XML パース時のコールバック関数
	 *
	 * @return void
	 */
	public function char( $parser, $data ): void {
		$this->parsed_xml .= $data;
}


	/**
	 * XML パース
	 *
	 * @return string
	 */
	public function xml_parser(): string {
		$request_body     = $this->get_request_body();
		$this->parsed_xml = '';

		if ( ! empty( $request_body ) ) {
			$parser = xml_parser_create();

			xml_set_object( $parser, $this );
			xml_set_character_data_handler( $parser, 'char' );

			if ( ! xml_parse( $parser, $request_body ) ) {
				$this->parsed_xml .= 'xml_parse_failed';
			};

			xml_parser_free( $parser );
		}

		return $this->parsed_xml;
	}


	/**
	 * ARGS_GET、ARGS_GET_NAMES 用 GETデータ取得
	 *
	 * @return array
	 */
	public function get_request_args_get_data(): array {
		if ( ! empty( $_GET ) ) {
			return $_GET;
		}

		return array();
	}


	/**
	 * ARGS_POST、ARGS_POST_NAMES 用 POSTデータ取得
	 *
	 * @return array
	 */
	public function get_request_args_post_data(): array {
		if ( ! empty( $_POST ) ) {
			return $_POST;
		}

		$post_data = $this->get_request_body();

		if ( ! empty( $post_data ) ) {
			$json_decoded_post_data = json_decode( $post_data, true );

			// nullでなければjsonとなる
			if ( is_array( $json_decoded_post_data ) ) {
				return $json_decoded_post_data;
			}
		}

		return array();
	}


	/**
	 * Cookie情報取得
	 *
	 * @return array
	 */
	public function get_request_cookies(): array {
		if ( ! empty( $_COOKIE ) ) {
			return $_COOKIE;
		} else {
			return array();
		}
	}


	/**
	 * リクエスト情報取得
	 * 取得・パースできなかったものに関しては空白で返す
	 *
	 * @return array
	 */
	public function get_request_items(): array {
		$request_items = array(
			'access_at'                     => current_time( 'mysql' ),
			'ip'                            => $this->get_client_ip(),
			self::VARIABLE_XML              => $this->xml_parser(),
			self::VARIABLE_REQUEST_FILENAME => $this->get_request_uri(),
			self::VARIABLE_REQUEST_HEADERS  => $this->get_http_request_headers(),
			self::VARIABLE_ARGS_GET         => $this->get_request_args_get_data(),
			self::VARIABLE_ARGS_POST        => $this->get_request_args_post_data(),
			self::VARIABLE_REQUEST_COOKIES  => $this->get_request_cookies(),
		);

		return $request_items;
	}


	/**
	 * ルールの設定を参考に1つのリクエスト情報に対して複数の変換を行う処理
	 *
	 * @param array  $transformations
	 * @param string $request_item
	 * @return string
	 */
	public function transform( $transformations, $request_item ): string {
		$converted_request_item = $request_item;

		foreach ( $transformations as $transformation ) {
			switch ( $transformation ) {
				case 'htmlentitydecode':
					$converted_request_item = html_entity_decode( $converted_request_item, ENT_QUOTES, 'utf-8' );
					break;
				case 'lowercase':
					$converted_request_item = strtolower( $converted_request_item );
					break;
				case 'replacecomments':
					$converted_request_item = preg_replace( '/(\/\*.*?\*\/|\/\*.*(?!\*\/).*)/s', ' ', $converted_request_item );
					break;
				case 'compresswhitespace':
					$converted_request_item = preg_replace( '/(\s|\xa0)/s', ' ', $converted_request_item );
					$converted_request_item = preg_replace( '/\s{2,}/s', ' ', $converted_request_item );
					break;
				default:
					$converted_request_item = '変換に失敗しました';
					break 2;
			}
		}

		return $converted_request_item;
	}


	/**
	 * LocationMatch設定によるルールのスキップ用関数
	 *
	 * @param array  $locationmatch_rules
	 * @param string $request_uri
	 * @return array
	 */
	public function locationmatch_remove_rules( $locationmatch_rules, $request_uri ): array {
		$locationmatch_removed_rule_ids = array();

		foreach ( $locationmatch_rules as $locationmatch_rule ) {
			if ( preg_match( '/' . $locationmatch_rule['path'] . '/', $request_uri ) ) {
				$locationmatch_removed_rule_ids = array_merge( $locationmatch_removed_rule_ids, $locationmatch_rule['remove_rule_ids'] );
			}
		}

		$locationmatch_removed_rule_ids = array_unique( $locationmatch_removed_rule_ids );

		return $locationmatch_removed_rule_ids;
	}


	/**
	 * skip表記の存在確認
	 *
	 * @param int $skip
	 * @return int
	 */
	public function check_skip( $skip ): int {
		if ( $skip !== 0 ) {
			return $skip;
		} else {
			return 0;
		}
	}


	/**
	 * skipafter表記の存在確認
	 *
	 * @param string $skipafter
	 * @return string
	 */
	public function check_skipafter( $skipafter ): string {
		if ( ! empty( $skipafter ) ) {
			return $skipafter;
		} else {
			return '';
		}
	}


	/**
	 * skipが有効か判定
	 *
	 * @param int $skip
	 * @return bool
	 */
	public function is_skip_enabled( $skip ): bool {
		if ( 0 < $skip ) {
			return true;
		} else {
			return false;
		}
	}


	/**
	 * skipafterが有効か判定
	 *
	 * @param string $skipafter
	 * @return bool
	 */
	public function is_skipafter_enabled( $skipafter ): bool {
		if ( ! empty( $skipafter ) ) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * ルールが終了したか判定
	 *
	 * @param string $chain
	 * @param string $skip
	 * @param string $skipafter
	 * @return bool
	 */
	public function is_rule_finished( $chain, $skip, $skipafter ): bool {
		if ( ! empty( $chain ) || $this->is_skip_enabled( $skip ) || $this->is_skipafter_enabled( $skipafter ) ) {
			return false;
		} else {
			return true;
		}
	}


	/**
	 * ルール内に除外の表記があるか確認
	 *
	 * @param array  $remove_variables
	 * @param string $variable
	 * @param string $request_item
	 * @return bool
	 */
	public function is_remove_variables( $remove_variables, $variable, $request_item ): bool {
		if ( ! empty( $remove_variables ) ) {
			foreach ( $remove_variables as $remove_variable => $remove_values ) {
				if ( $remove_variable === $variable ) {
					foreach ( $remove_values as $remove_value ) {

						// REQUEST_HEADERSの場合は大文字小文字関係なく判定する
						if ( $variable === self::VARIABLE_REQUEST_HEADERS ) {
							if ( preg_match( '/' . $remove_value . '/i', $request_item ) ) {
								return true;
							}
						}

						if ( preg_match( '/^\/.+\/$/', $remove_value ) ) {
							// 除外の値が部分一致(/で囲まれているもの)の場合
							if ( preg_match( $remove_value . 's', $request_item ) ) {
								return true;
							}
						} else {
							// 除外の値が完全一致の場合
							if ( $remove_value === $request_item ) {
								return true;
							}
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * マッチした結果を配列に格納
	 *
	 * @param array  $rule
	 * @param array  $request_items
	 * @param string $variable
	 * @param string $match_string
	 * @return array
	 */
	public function get_match_results( $rule, $request_items, $variable, $match_string ): array {

		if ( isset( $_SERVER['HTTP_HOST'] ) && isset( $_SERVER['REQUEST_URI'] ) ) {
			$complete_url = ( empty( $_SERVER['HTTPS'] ) ? 'http://' : 'https://' )
				. sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) )
				. esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		} else {
			$complete_url = '';
		}

		$match_results = array(
			'id'        => $rule['id'],
			'attack'    => $rule['attack'],
			'variable'  => $variable,
			'matched'   => $match_string,
			'ip'        => $request_items['ip'],
			'access_at' => $request_items['access_at'],
			'url'       => $complete_url,
		);

		return $match_results;
	}


	/**
	 * chain_itemsの取得
	 *
	 * @param array $rule
	 * @return array
	 */
	public function get_chain_items( $rule ): array {
		$chain_items = array(
			'id'        => $rule['id'],
			'attack'    => $rule['attack'],
			'skip'      => $rule['skip'],
			'skipafter' => $rule['skipafter'],
		);

		return $chain_items;
	}


	/**
	 * マッチしたルールの設定、結果を取得
	 *
	 * @param array  $waf_rule
	 * @param array  $request_items
	 * @param string $variable
	 * @param array  $chain_items
	 * @param array  $match_string
	 * @return array
	 */
	public function get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, $match_string ): array {
		$results = array(
			'is_matched'    => true,
			'chain_items'   => array(),
			'skip'          => 0,
			'skipafter'     => '',
			'match_results' => array(),
		);

		// 前ルールからchainの設定を引き継いでいるか確認
		if ( ! empty( $chain_items ) ) {
			if ( $waf_rule['attack'] === '' && $this->is_rule_finished( $waf_rule['chain'], $waf_rule['skip'], $waf_rule['skipafter'] ) ) {
				// ルールの終了判定がtrueではあるが、攻撃種別が設定されていない場合はマッチ用のルールではないのでマッチしていないと判定
				$results['is_matched'] = false;

			} elseif ( $this->is_rule_finished( $waf_rule['chain'], $chain_items['skip'], $chain_items['skipafter'] ) ) {
				$results['match_results'] = $this->get_match_results( $chain_items, $request_items, $variable, $match_string );

			} elseif ( $waf_rule['chain'] ) {
				// 現在のルールにchainの設定がある場合
				$results['chain_items'] = $chain_items;

			} else {
				$results['skip']      = $this->check_skip( $chain_items['skip'] );
				$results['skipafter'] = $this->check_skipafter( $chain_items['skipafter'] );
			}
		} else {
			if ( $waf_rule['attack'] === '' && $this->is_rule_finished( $waf_rule['chain'], $waf_rule['skip'], $waf_rule['skipafter'] ) ) {
				// ルールの終了判定がtrueではあるが、攻撃種別が設定されていない場合はマッチ用のルールではないのでマッチしていないと判定
				$results['is_matched'] = false;

			} elseif ( $this->is_rule_finished( $waf_rule['chain'], $waf_rule['skip'], $waf_rule['skipafter'] ) ) {
				$results['match_results'] = $this->get_match_results( $waf_rule, $request_items, $variable, $match_string );

			} elseif ( $waf_rule['chain'] ) {
				// 現在のルールにchainの設定がある場合
				$results['chain_items'] = $this->get_chain_items( $waf_rule );

			} else {
				$results['skip']      = $this->check_skip( $waf_rule['skip'] );
				$results['skipafter'] = $this->check_skipafter( $waf_rule['skipafter'] );
			}
		}
		return $results;
	}

	/**
	 * ネストした配列をパース
	 *
	 * @param string $name
	 * @param array  $array
	 */
	public function parse_array( $name, $array ) {
		$parsed_array = array();

		foreach ( $array as $key => $val ) {
			if ( is_array( $val ) ) {
				$tmp_name         = $name . '[' . $key . ']';
				$tmp_parsed_array = $this->parse_array( $tmp_name, $val );
				$parsed_array     = array_merge( $parsed_array, $tmp_parsed_array );

			} else {
				$parsed_array_key                  = $name . '[' . $key . ']';
				$parsed_array[ $parsed_array_key ] = $val ?? '';
			}
		}
		return $parsed_array;
	}


	/**
	 * リクエスト情報配列を使用するルール判定
	 *
	 * @param array  $waf_rule
	 * @param array  $request_items
	 * @param string $variable
	 * @param array  $chain_items
	 * @return array
	 */
	public function check_request_item_array( $waf_rule, $request_items, $variable, $chain_items ) {
		$results = array(
			'is_matched'          => false,
			'chain_items'         => array(),
			'skip'                => 0,
			'skipafter'           => '',
			'match_results'       => array(),
			'has_backtrack_error' => false,
			'backtrack_key'       => '',
		);

		$get_request_item_variable = preg_replace( '/_names/', '', $variable );

		if ( ! isset( $get_request_item_variable ) ) {
			return $results;
		}

		foreach ( $request_items[ $get_request_item_variable ] as $key => $val ) {

			if ( ! isset( $val ) ) {
				$val = '';
			}

			switch ( $variable ) {
				case self::VARIABLE_ARGS_GET:
				case self::VARIABLE_ARGS_POST:
				case self::VARIABLE_REQUEST_COOKIES:
				case self::VARIABLE_REQUEST_HEADERS:
					if ( is_array( $val ) ) {
						$parsed_vals = $this->parse_array( $key, $val );

						foreach ( $parsed_vals as $key => $val ) {
							$checked_request_item = $this->check_request_item_value( $waf_rule, $key, $val, $variable );

							if ( $checked_request_item['has_backtrack_error'] ) {
								$results['has_backtrack_error'] = true;
								$results['backtrack_key']       = $checked_request_item['backtrack_key'] ?? '';
							}

							if ( $checked_request_item['is_matched'] ) {
								$has_bt  = $results['has_backtrack_error'];
								$has_btk = $results['backtrack_key'];
								$results = $this->get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, $checked_request_item['match_string'] );

								$results['has_backtrack_error'] = $has_bt;
								$results['backtrack_key']       = $has_btk;
								break;
							}
						}
					} else {
						$checked_request_item = $this->check_request_item_value( $waf_rule, $key, $val, $variable );
					}

					break;

				case self::VARIABLE_ARGS_GET_NAMES:
				case self::VARIABLE_ARGS_POST_NAMES:
				case self::VARIABLE_REQUEST_COOKIES_NAMES:
					$checked_request_item = $this->check_request_item_key( $waf_rule, $key, $variable );
					break;
			}

			if ( isset( $checked_request_item['has_backtrack_error'] ) && $checked_request_item['has_backtrack_error'] ) {
				$results['has_backtrack_error'] = true;
				$results['backtrack_key']       = $checked_request_item['backtrack_key'] ?? '';
			}

			if ( $checked_request_item['is_matched'] ) {
				$has_bt  = $results['has_backtrack_error'];
				$has_btk = $results['backtrack_key'];
				$results = $this->get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, $checked_request_item['match_string'] );

				$results['has_backtrack_error'] = $has_bt;
				$results['backtrack_key']       = $has_btk;

				break;
			}
		}
		return $results;
	}



	/**
	 * リクエスト情報配列のうちvalueの値を使用するルール判定
	 *
	 * @param array  $waf_rule
	 * @param string $request_items_key
	 * @param string $request_items_value
	 * @param string $variable
	 * @return array
	 */
	public function check_request_item_value( $waf_rule, $request_items_key, $request_items_value, $variable ): array {
		$results = array(
			'is_matched'          => false,
			'match_string'        => '',
			'has_backtrack_error' => false,
			'backtrack_key'       => '',
		);
		$matches = array();

		// リクエスト情報配列のkeyの変換
		$tmp_key = $this->transform( $waf_rule['transformations'], $request_items_key );

		// 除外対象のキーは検査自体を行わない
		// preg_matchを先に実行するとバックトラック超過時に正常な操作が誤って遮断されるため、除外判定を検査前に行う
		if ( true === $this->is_remove_variables( $waf_rule['remove_variables'], $variable, $tmp_key ) ) {
			return $results;
		}

		// リクエスト情報配列のvalueの変換
		$tmp_val = $this->transform( $waf_rule['transformations'], $request_items_value );

		$preg_result = preg_match( '/' . $waf_rule['regex_pattern'] . '/s', $tmp_val, $matches );

		if ( $preg_result === false ) {
			// preg_matchが完走しなかった場合（バックトラック/JITスタック/再帰上限/不正UTF-8等）は検査失敗として扱う
			$results['has_backtrack_error'] = true;
			$results['backtrack_key']       = $request_items_key;
		} elseif ( $preg_result === 1 ) {
			if ( ! empty( $matches ) ) {
				// 除外判定は検査前に実施済みのためマッチしたと判定
				$results['is_matched']   = true;
				$results['match_string'] = $matches[0];
			}
		}

		return $results;
	}


	/**
	 * リクエスト情報配列のうちkeyの値を使用するルール判定
	 *
	 * @param array  $waf_rule
	 * @param string $request_items_key
	 * @param string $variable
	 * @return array
	 */
	public function check_request_item_key( $waf_rule, $request_items_key, $variable ): array {
		$results = array(
			'is_matched'          => false,
			'match_string'        => '',
			'has_backtrack_error' => false,
			'backtrack_key'       => '',
		);
		$matches = array();

		// リクエスト情報配列のkeyの変換
		$tmp_key = $this->transform( $waf_rule['transformations'], $request_items_key );

		// 除外対象のキーは検査自体を行わない
		// preg_matchを先に実行するとバックトラック超過時に正常な操作が誤って遮断されるため、除外判定を検査前に行う
		if ( true === $this->is_remove_variables( $waf_rule['remove_variables'], $variable, $tmp_key ) ) {
			return $results;
		}

		$preg_result = preg_match( '/' . $waf_rule['regex_pattern'] . '/s', $tmp_key, $matches );

		if ( $preg_result === false ) {
			// preg_matchが完走しなかった場合（バックトラック/JITスタック/再帰上限/不正UTF-8等）は検査失敗として扱う
			$results['has_backtrack_error'] = true;
			$results['backtrack_key']       = $request_items_key;
		} elseif ( $preg_result === 1 ) {
			if ( ! empty( $matches ) ) {
				// 除外判定は検査前に実施済みのためマッチしたと判定
				$results['is_matched']   = true;
				$results['match_string'] = $matches[0];
			}
		}

		return $results;
	}


	/**
	 * リクエスト情報配列のうち文字列の値を使用するルール判定
	 *
	 * @param array  $waf_rule
	 * @param array  $request_items
	 * @param string $variable
	 * @param array  $chain_items
	 * @return array
	 */
	public function check_request_item_strings( $waf_rule, $request_items, $variable, $chain_items ): array {
		$results = array(
			'is_matched'          => false,
			'chain_items'         => array(),
			'skip'                => 0,
			'skipafter'           => '',
			'match_results'       => array(),
			'has_backtrack_error' => false,
		);

		if ( empty( $request_items[ $variable ] ) ) {
			return $results;
		}

		if ( $variable === self::VARIABLE_XML ) {
			if ( $request_items[ self::VARIABLE_XML ] === 'xml_parse_failed' ) {
				return $results;
			} else {
				$request_items[ self::VARIABLE_XML ] = str_replace( 'xml_parse_failed', '', $request_items[ self::VARIABLE_XML ] );
			}
		}

		// リクエスト情報の変換
		$tmp_string = $this->transform( $waf_rule['transformations'], $request_items[ $variable ] );

		// REQUEST_FILENAMEに関しては、urlデコード済の値も判定し、マッチしたら結果を出力
		if ( $variable === self::VARIABLE_REQUEST_FILENAME ) {
			// リクエスト情報のデコード&変換
			$request_items_urldecoded = urldecode( $request_items[ $variable ] );
			$tmp_urldecoded           = $this->transform( $waf_rule['transformations'], $request_items_urldecoded );

			$preg_result = preg_match( '/' . $waf_rule['regex_pattern'] . '/s', $tmp_urldecoded, $matches );

			if ( $preg_result === false ) {
				// preg_matchが完走しなかった場合（バックトラック/JITスタック/再帰上限/不正UTF-8等）は検査失敗として扱う
				$results['has_backtrack_error'] = true;
			} elseif ( $preg_result === 1 ) {
				if ( ! empty( $matches ) ) {
					$results = $this->get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, $matches[0] );
					return $results;
				}
			}
		}

		$preg_result = preg_match( '/' . $waf_rule['regex_pattern'] . '/s', $tmp_string, $matches );

		if ( $preg_result === false ) {
			// preg_matchが完走しなかった場合（バックトラック/JITスタック/再帰上限/不正UTF-8等）は検査失敗として扱う
			$results['has_backtrack_error'] = true;
			return $results;
		}

		if ( empty( $matches ) ) {
			// 正規表現パターンにマッチしなければ終了
			return $results;
		}

		$has_bt  = $results['has_backtrack_error'];
		$results = $this->get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, $matches[0] );

		$results['has_backtrack_error'] = $has_bt;

	return $results;
	}


	/**
	 * REST APIエンドポイントを取得（パーマリンク設定に依存しない）
	 *
	 * @param array $request_items
	 * @return string
	 */
	public function get_rest_endpoint( $request_items ): string {
		// パーマリンクが「基本」の場合はrest_routeパラメータにエンドポイントが含まれる
		// GETとPOSTの両方にrest_routeが含まれる場合は404エラーになる
		if ( isset( $request_items['args_get']['rest_route'] ) && is_string( $request_items['args_get']['rest_route'] ) ) {
			return $request_items['args_get']['rest_route'];
		}
		if ( isset( $request_items['args_post']['rest_route'] ) && is_string( $request_items['args_post']['rest_route'] ) ) {
			return $request_items['args_post']['rest_route'];
		}

		// その他のパーマリンク設定の場合はrequest_filenameを使用
		return $request_items['request_filename'];
	}


	/**
	 * AND判定の共通ロジック
	 *
	 * 存在するチャネル（args_get / args_post）の値がすべて $predicate を満たし、かつ最低1つのチャネルに存在する場合のみ true。
	 *
	 * @param array    $request_items
	 * @param string   $key
	 * @param callable $predicate function( mixed $value ): bool  1チャネルの値が条件を満たすか
	 * @return bool
	 */
	private function args_value_all_match( array $request_items, string $key, callable $predicate ): bool {
		$args_get  = $request_items['args_get'] ?? array();
		$args_post = $request_items['args_post'] ?? array();

		$in_args_get  = array_key_exists( $key, $args_get );
		$in_args_post = array_key_exists( $key, $args_post );

		if ( ! $in_args_get && ! $in_args_post ) {
			return false;
		}
		if ( $in_args_get && ! $predicate( $args_get[ $key ] ) ) {
			return false;
		}
		if ( $in_args_post && ! $predicate( $args_post[ $key ] ) ) {
			return false;
		}

		return true;
	}


	/**
	 * 判定対象キーに対する値の完全一致判定（AND判定）
	 * 許可する値が1つの場合
	 *
	 * 存在するチャネルの値がすべて $expected と厳密一致し、かつ最低1つのチャネルに存在する場合のみ true。
	 *
	 * @param array  $request_items
	 * @param string $key
	 * @param string $expected
	 * @return bool
	 */
	private function args_value_matches( array $request_items, string $key, string $expected ): bool {
		return $this->args_value_all_match(
			$request_items,
			$key,
			static function ( $value ) use ( $expected ) {
				return $value === $expected;
			}
		);
	}


	/**
	 * 判定対象キーに対する値の完全一致判定（AND判定）
	 * 許可する値が2つ以上の場合
	 *
	 * 存在するチャネルの値がすべて $allowed のいずれかと厳密一致し、かつ最低1つのチャネルに存在する場合のみ true。
	 *
	 * @param array    $request_items
	 * @param string   $key
	 * @param string[] $allowed
	 * @return bool
	 */
	private function args_value_matches_any( array $request_items, string $key, array $allowed ): bool {
		return $this->args_value_all_match(
			$request_items,
			$key,
			static function ( $value ) use ( $allowed ) {
				return in_array( $value, $allowed, true );
			}
		);
	}


	/**
	 * 判定対象キーに対する値の正規表現一致判定（AND判定）
	 *
	 * 存在するチャネルの値がすべて $pattern に一致し、かつ最低1つに存在する場合のみ true。
	 *
	 * @param array  $request_items
	 * @param string $key
	 * @param string $pattern
	 * @return bool
	 */
	private function args_value_matches_regex( array $request_items, string $key, string $pattern ): bool {
		return $this->args_value_all_match(
			$request_items,
			$key,
			static function ( $value ) use ( $pattern ) {
				return is_string( $value ) && 1 === preg_match( $pattern, $value );
			}
		);
	}


	/**
	 * 判定対象キーに対する値の部分一致判定（AND判定）
	 *
	 * 存在するチャネルの値がすべて $needle を含み、かつ最低1つに存在する場合のみ true。
	 *
	 * @param array  $request_items
	 * @param string $key
	 * @param string $needle
	 * @return bool
	 */
	private function args_value_matches_partial( array $request_items, string $key, string $needle ): bool {
		return $this->args_value_all_match(
			$request_items,
			$key,
			static function ( $value ) use ( $needle ) {
				return is_string( $value ) && false !== strpos( $value, $needle );
			}
		);
	}


	/**
	 * 判定対象キーの存在判定（OR判定）
	 *
	 * どちらかのチャネルに存在すれば true
	 *
	 * @param array  $request_items
	 * @param string $key
	 * @return bool
	 */
	private function args_key_exists( array $request_items, string $key ): bool {
		$args_get  = $request_items['args_get'] ?? array();
		$args_post = $request_items['args_post'] ?? array();

		return array_key_exists( $key, $args_get ) || array_key_exists( $key, $args_post );
	}


	/**
	 * WordPress管理画面での特定の処理に対し、特定のルールを除外する
	 *
	 * @param string $rule_id
	 * @param array  $request_items
	 * @param array  $remove_rules
	 * @return array
	 */
	public function is_remove_rule( $rule_id, $request_items, $remove_rules, $acf_post_types, $cptui_post_types ): array {
		$is_rule_removed         = false;
		$modify_remove_variables = array();
		$modify_variables        = array();

		if ( isset( $remove_rules['woocommerce'] ) ) {
			if ( in_array( $rule_id, $remove_rules['woocommerce'], true ) ) {
				$sbjs_cookie_keys = preg_grep( '/^sbjs_.+/', array_keys( $request_items['request_cookies'] ) );

				// sourcebusterの除外（woocommerce）
				if ( ! empty( $sbjs_cookie_keys ) ) {
					foreach ( $sbjs_cookie_keys as $key ) {
						if ( preg_match( '/(\;|\||\`)\W*?\b(?:(?:c(?:h(?:grp|mod|own|sh)|md|pp)|p(?:asswd|ython|erl|ing|s)|n(?:asm|map|c)|f(?:inger|tp)|(?:kil|mai)l|(?:xte)?rm|ls(?:of)?|telnet|uname|echo|id)\b|g(?:\+\+|cc\b))/i', $request_items['request_cookies'][ $key ] ) === 1 ) {
							$is_rule_removed = true;
							break;
						}
					}
				}
			}
		}

		if ( isset( $remove_rules['ajax_customize'] ) ) {
			if ( in_array( $rule_id, $remove_rules['ajax_customize'], true ) ) {
				// カスタマイズ操作、オートセーブ時の除外（issetで先に判定、最安価）
				if (
					$this->args_key_exists( $request_items, 'customize_changeset_uuid' ) &&
					( $this->args_value_matches( $request_items, 'customize_autosaved', 'on' ) || $this->args_value_matches( $request_items, 'wp_customize', 'on' ) )
				) {
					$action = $request_items['args_post']['action'] ?? '';
					if ( $action === 'update-widget' ) {
						// actionがupdate-widgetの場合はルール全体を除外（cocoon）
						$is_rule_removed = true;
					} else {
						// それ以外の場合はcustomized, customize_changeset_dataキーのみ除外
						$modify_remove_variables['args_post'] = array( 'customized', 'customize_changeset_data' );
					}
				// admin-ajax.phpへのリクエスト（ウィジェット保存・メニュー操作(WP5.3)をまとめて1回のpreg_matchで判定）
				} elseif ( preg_match( '/wp-admin\/admin-ajax\.php/', $request_items['request_filename'] ) === 1 ) {
					$action = $request_items['args_post']['action'] ?? '';
					// ウィジェット保存時（cocoonテーマ）の除外
					if ( $action === 'save-widget' && isset( $request_items['args_post']['widget-id'] ) ) {
						$is_rule_removed = true;
					// メニュー操作時（WordPress5.3）の除外
					} elseif ( $action === 'add-menu-item' ) {
						$is_rule_removed = true;
					}
				// メニュー操作時（cocoonテーマ）の除外
				} elseif ( preg_match( '/wp-admin\/nav-menus\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( $this->args_value_matches_any( $request_items, 'action', array( 'update', 'edit' ) ) ) {
						$is_rule_removed = true;
					}
				}
			}
		}

		if ( isset( $remove_rules['rest_api'] ) ) {
			$rest_endpoint = $this->get_rest_endpoint( $request_items );

			// 投稿・編集（templates, blocks, template-parts, navigation, pages, posts）の場合はcontentキーを除外
			if ( preg_match( '/templates|blocks|template-parts|navigation|pages|posts/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// global-styles の場合はstylesキーを除外
			} elseif ( preg_match( '/global-styles/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( '/^styles/' );
						$modify_remove_variables['args_post'] = array( '/^styles/' );
					}
				}

			// batch の場合はrequestsキーを除外
			} elseif ( preg_match( '/batch/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_post'] = array( '/^requests/' );
					}
				}

			// 投稿・編集の操作は特定のルールを除外する(post.php)
			} elseif ( preg_match( '/wp-admin\/post\.php/', $request_items['request_filename'] ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( $this->args_value_matches( $request_items, 'action', 'editpost' ) ) {
						$is_rule_removed = true;
					} elseif ( $this->args_value_matches( $request_items, 'action', 'post-quickdraft-save' ) ) {
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// カスタマイズ機能からの投稿作成時の除外
			} elseif (
				$this->args_key_exists( $request_items, 'customize_changeset_uuid' ) &&
				( $this->args_value_matches( $request_items, 'customize_autosaved', 'on' ) || $this->args_value_matches( $request_items, 'wp_customize', 'on' ) )
			) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( $this->args_value_matches( $request_items, 'action', 'customize-nav-menus-insert-auto-draft' ) ) {
						$modify_remove_variables['args_post'] = array( '/^params/' );
					}
				}

			// nishiki の場合はcontentキーを除外
			} elseif ( preg_match( '/wp\/v2\/nishiki_pro_(patterns|content)/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// xerite の場合はcontentキーを除外
			} elseif ( preg_match( '/wp\/v2\/xw_block_patterns/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// Lightning の場合はcontentキーを除外
			} elseif ( preg_match( '/wp\/v2\/(cta|vk-block-patterns)/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// SWELL の場合はcontentキーを除外
			} elseif ( preg_match( '/wp\/v2\/(lp|blog_parts)/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// Snow Monkey の場合はcontentキーを除外
			} elseif ( preg_match( '/wp\/v2\/snow-monkey-search/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// Advanced Custom Fields の場合はcontentキーを除外
			// カスタム投稿タイプキーは小文字、アンダースコア、ダッシュのみを許容するが、念のためarray_mapで正規表現用にエスケープする
			} elseif ( ! empty( $acf_post_types ) && preg_match( '/wp\/v2\/(' . implode( '|', array_map( 'preg_quote', $acf_post_types ) ) . ')/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}

			// Custom Post Type UI の場合はcontentキーを除外
			// カスタム投稿タイプキーは小文字、アンダースコア、ダッシュのみを許容するが、念のためarray_mapで正規表現用にエスケープする
			} elseif ( ! empty( $cptui_post_types ) && preg_match( '/wp\/v2\/(' . implode( '|', array_map( 'preg_quote', $cptui_post_types ) ) . ')/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						$modify_remove_variables['args_get']  = array( 'content' );
						$modify_remove_variables['args_post'] = array( 'content' );
					}
				}
			}
		}

		if ( isset( $remove_rules['rest_api_search'] ) ) {
			$rest_endpoint = $this->get_rest_endpoint( $request_items );

			// pages または posts エンドポイントで context=edit かつ search パラメータが存在する場合は search の値を除外
			if ( preg_match( '/wp\/v2\/(pages|posts)/', $rest_endpoint ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['rest_api_search'], true ) ) {
					if ( preg_match( '/_locale\=user/', $_SERVER['QUERY_STRING'] ?? '' ) === 1 ) {
						if ( ( $request_items['args_get']['context'] ?? '' ) === 'edit' && isset( $request_items['args_get']['search'] ) ) {
							$modify_remove_variables['args_get'] = array( 'search' );
						}
					}
				}
			}
		}

		// cocoonテーマでの除外処理（theme-func-text, theme-settings, theme-ranking, theme-affiliate-tag）
		if ( isset( $remove_rules['cocoon'] ) ) {
			$page = $request_items['args_get']['page'] ?? '';
			if ( preg_match( '/^theme-(func-text|settings|ranking|affiliate-tag)$/', $page ) === 1 ) {
				if ( preg_match( '/wp-admin\/admin\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( in_array( $rule_id, $remove_rules['cocoon'], true ) ) {
						if ( $this->args_value_matches_any( $request_items, 'action', array( 'new', 'edit' ) ) ) {
							$is_rule_removed = true;
						}

						if ( isset( $request_items['args_post']['comment_information_message'] ) ) {
							$is_rule_removed = true;
						}
					}
				}
			}
		}

		if ( isset( $remove_rules['emanon'] ) ) {
			// emanonルール除外
			if ( ( $request_items['args_get']['page'] ?? '' ) === 'emanon_setting_page' ) {
				if ( preg_match( '/wp-admin\/admin\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( in_array( $rule_id, $remove_rules['emanon'], true ) ) {
						if ( $this->args_value_matches( $request_items, 'action', 'delete_transients_emanon_setting' ) ) {
							$is_rule_removed = true;
						}
					}
				}
			}
		}

		if ( isset( $remove_rules['vkexunit'] ) ) {
			// vkExUnitルール除外（メイン設定）
			if ( ( $request_items['args_get']['page'] ?? '' ) === 'vkExUnit_main_setting' ) {
				if ( preg_match( '/wp-admin\/admin\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( isset( $request_items['args_post']['_nonce_vkExUnit'] ) ) {
						if ( in_array( $rule_id, $remove_rules['vkexunit'], true ) ) {
							$is_rule_removed = true;
						}
					}
				}
			}

			// vkExUnitルール除外（cssカスタマイズ）
			if ( preg_match( '/wp-admin\/admin.php\?page\=vkExUnit_css_customize/', $_SERVER['REQUEST_URI'] ?? '' ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['vkexunit'], true ) ) {
					if ( $this->args_value_matches_partial( $request_items, '_wp_http_referer', '/wp-admin/admin.php?page=vkExUnit_css_customize' ) ) {
						$is_rule_removed = true;
					}
				}
			}
		}

		if ( isset( $remove_rules['nishiki'] ) ) {
			// nishikiルール除外
			if ( $this->args_value_matches_regex( $request_items, 'option_page', '/^nishiki_pro_general/' ) ) {
				if ( preg_match( '/wp-admin\/options\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( in_array( $rule_id, $remove_rules['nishiki'], true ) ) {
						if ( $this->args_value_matches( $request_items, 'action', 'update' ) ) {
							$is_rule_removed = true;
						}
					}
				}
			}
		}

		if ( isset( $remove_rules['swell'] ) ) {
			// swellルール除外
			if ( $this->args_value_matches_regex( $request_items, 'option_page', '/^swell_setting_group_editor/' ) ) {
				if ( preg_match( '/wp-admin\/options\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( in_array( $rule_id, $remove_rules['swell'], true ) ) {
						if ( $this->args_value_matches( $request_items, 'action', 'update' ) ) {
							$is_rule_removed = true;
						}
					}
				}
			}
		}

		if ( isset( $remove_rules['comment'] ) ) {
			// コメント編集時の除外
			if ( preg_match( '/wp-admin\/comment\.php/', $request_items['request_filename'] ?? '' ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['comment'], true ) ) {
					if ( $this->args_value_matches( $request_items, 'action', 'editedcomment' ) ) {
						$is_rule_removed = true;
					}
				}
			}
		}

		if ( isset( $remove_rules['ajax_editor'] ) ) {
			// テーマ・プラグインエディターの操作時の除外
			if ( preg_match( '/wp-admin\/admin-ajax\.php/', $request_items['request_filename'] ) === 1 ) {
				if ( in_array( $rule_id, $remove_rules['ajax_editor'], true ) ) {
					if ( $this->args_value_matches_regex( $request_items, '_wp_http_referer', '/theme-editor(\.php)?|plugin-editor(\.php)?/' ) ) {
						$is_rule_removed = true;
					}

					// オートセーブ時
					$screen_id = $request_items['args_post']['screen_id'] ?? '';
					if ( preg_match( '/theme-editor(\.php)?|plugin-editor(\.php)?/', $screen_id ) === 1 ) {
						$is_rule_removed = true;
					}
				}
			}
		}

		if ( isset( $remove_rules['rename_login_page'] ) ) {
			$login_page_name = $remove_rules['rename_login_page']['login_page_name'];
			$is_target_rule  = in_array( $rule_id, $remove_rules['rename_login_page']['rule_ids'], true );

			if ( $is_target_rule ) {
				// ログインURL変更設定保存時：rename_login_page_nameキーの値のみ除外
				if ( preg_match( '/wp-admin\/admin\.php/', $request_items['request_filename'] ) === 1 ) {
					if ( ( $request_items['args_get']['page'] ?? '' ) === 'cloudsecurewp_rename_login_page' ) {
						$modify_remove_variables['args_post'] = array( 'rename_login_page_name' );
					}
				}

				// 変更後ログインURLへのアクセス時、またはリファラーが変更後ログインURLである時の対応
				if ( ! empty( $login_page_name ) ) {
					$login_page_pattern    = '/\/' . preg_quote( $login_page_name, '/' ) . '(?:[\/\?#]|$)/';
					$is_login_page_access  = preg_match( $login_page_pattern, $request_items['request_filename'] ) === 1;
					$is_login_page_referer = preg_match( $login_page_pattern, $_SERVER['HTTP_REFERER'] ?? '' ) === 1;

					if ( $is_login_page_access ) {
						// 1. URI自体に誤検知ワードが含まれるため、request_filenameを除外
						$modify_variables[] = self::VARIABLE_REQUEST_FILENAME;

						// 2. args の特定キー（リダイレクト系など）を除外
						if ( ! isset( $modify_remove_variables['args_get'] ) ) {
							$modify_remove_variables['args_get'] = array();
						}
						$modify_remove_variables['args_get'] = array_merge( $modify_remove_variables['args_get'], array( 'redirect_to', '_wp_http_referer' ) );

						if ( ! isset( $modify_remove_variables['args_post'] ) ) {
							$modify_remove_variables['args_post'] = array();
						}
						$modify_remove_variables['args_post'] = array_merge( $modify_remove_variables['args_post'], array( 'redirect_to', '_wp_http_referer' ) );
					}

					if ( $is_login_page_access || $is_login_page_referer ) {
						// 3. リファラーヘッダーを除外
						if ( ! isset( $modify_remove_variables['request_headers'] ) ) {
							$modify_remove_variables['request_headers'] = array();
						}
						$modify_remove_variables['request_headers'][] = 'Referer';
					}
				}
			}
		}

		return array(
			'is_removed'              => $is_rule_removed,
			'modify_remove_variables' => $modify_remove_variables,
			'modify_variables'        => $modify_variables,
		);
	}

	/**
	 * Advanced Custom Fieldsプラグイン除外対応
	 * 有効なカスタム投稿タイプキーを取得する
	 *
	 * @return array
	 */
	public function get_acf_post_types(): array {
		global $wpdb;
		$active_plugins = get_option( 'active_plugins' );
		$acf_post_types = array();

		if ( is_array( $active_plugins ) && preg_match( '/advanced-custom-fields/', implode( ',', $active_plugins ) ) ) {
			$results = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT post_content
					FROM {$wpdb->posts}
					WHERE post_type = %s
					AND post_status = %s",
					'acf-post-type',
					'publish'
				)
			);

			if ( ! empty( $results ) ) {
				foreach ( $results as $result ) {
					$post_content = unserialize( $result->post_content, [ 'allowed_classes' => false ] );

					if ( is_array( $post_content ) && isset( $post_content['post_type'] ) ) {
						$acf_post_types[] = $post_content['post_type'];
					}
				}
			}
		}

		return $acf_post_types;
	}


	/**
	 * Custom Post Type UIプラグイン除外対応
	 * 有効なカスタム投稿タイプキーを取得する
	 *
	 * @return array
	 */
	public function get_cptui_post_types(): array {
		$active_plugins   = get_option( 'active_plugins' );
		$cptui_post_types = array();

		if ( is_array( $active_plugins ) && preg_match( '/custom-post-type-ui/', implode( ',', $active_plugins ) ) ) {
			$cptui_data = get_option( 'cptui_post_types' );

			if ( is_string( $cptui_data ) ) {
				$cptui_data = unserialize( $cptui_data, [ 'allowed_classes' => false ] );
			}

			if ( is_array( $cptui_data ) ) {
				foreach ( $cptui_data as $post_type ) {
					if ( is_array( $post_type ) && isset( $post_type['name'] ) ) {
						$cptui_post_types[] = $post_type['name'];
					}
				}
			}
		}

		return $cptui_post_types;
	}


	/**
	 * バックトラック超過が発生したパラメータの表示用文字列を生成
	 *
	 * @param string $variable WAF 変数種別
	 * @param string $key      パラメータ名
	 * @return string
	 */
	private function format_backtrack_key( string $variable, string $key ): string {
		switch ( $variable ) {
			// REQUEST_FILENAME / XML は単一文字列を検査するためパラメータ名（キー）を持たず、固定ラベルを返す
			case self::VARIABLE_REQUEST_FILENAME:
				return 'URL';

			case self::VARIABLE_XML:
				return 'XML';

			case self::VARIABLE_ARGS_GET:
			case self::VARIABLE_ARGS_GET_NAMES:
				$label = 'GET';
				break;

			case self::VARIABLE_ARGS_POST:
			case self::VARIABLE_ARGS_POST_NAMES:
				$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) : '';
				$label        = ( false !== strpos( $content_type, 'application/json' ) ) ? 'JSON' : 'POST';
				break;

			case self::VARIABLE_REQUEST_COOKIES:
			case self::VARIABLE_REQUEST_COOKIES_NAMES:
				$label = 'COOKIE';
				break;

			case self::VARIABLE_REQUEST_HEADERS:
				$label = 'HEADER';
				break;

			// 到達しない想定
			default:
				return '';
		}

		// パラメータ名が取得できない場合（JSONの空文字キー等）はカテゴリ名のみを返し、
		// ログの検知データ欄が空文字にならないようにする
		if ( '' === $key ) {
			return $label;
		}

		return $label . ': ' . $key;
	}


	/**
	 * 除外対象ユーザーの判定（Cookie認証 + 編集権限）
	 *
	 * シンプルWAFは plugins_loaded（優先度10）段階で実行されるが、この段階でも
	 * wp_validate_auth_cookie() / user_can() は使用できる。Cookie認証以外
	 * （Application Password、JWT、OAuth、Basic認証等）はこの判定では未ログイン扱いとなる。
	 *
	 * 除外条件は REST API無効化機能（disable-restapi.php）と揃え、
	 * edit_pages または edit_posts を持つユーザー（＝寄稿者以上）のみを対象とする。
	 *
	 * @return bool true: 除外対象（編集権限を持つログインユーザー） / false: それ以外
	 */
	private function is_excluded_user_by_cookie(): bool {
		if ( null === $this->excluded_user_by_cookie ) {
			$this->excluded_user_by_cookie = false;

			if ( function_exists( 'wp_validate_auth_cookie' ) && function_exists( 'user_can' ) ) {
				$user_id = wp_validate_auth_cookie( '', 'logged_in' );
				if ( $user_id ) {
					$this->excluded_user_by_cookie =
						user_can( $user_id, 'edit_pages' ) || user_can( $user_id, 'edit_posts' );
				}
			}
		}

		return $this->excluded_user_by_cookie;
	}


	/**
	 * バックトラック超過エラーの結果配列を生成
	 *
	 * @param array  $request_items
	 * @param string $variable WAF 変数種別
	 * @param string $key      パラメータ名
	 * @return array
	 */
	private function get_backtrack_error_results( array $request_items, string $variable, string $key ): array {
		$matched = $this->format_backtrack_key( $variable, $key );

		// バックトラックエラー記録用のURL生成
		if ( isset( $_SERVER['HTTP_HOST'] ) && isset( $_SERVER['REQUEST_URI'] ) ) {
			$backtrack_url = ( empty( $_SERVER['HTTPS'] ) ? 'http://' : 'https://' )
				. sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) )
				. esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		} else {
			$backtrack_url = '';
		}

		return array(
			'matched'            => $matched,
			'ip'                 => $request_items['ip'],
			'access_at'          => $request_items['access_at'],
			'url'                => $backtrack_url,
			'is_backtrack_error' => true,
		);
	}


	/**
	 * waf_engine
	 *
	 * @param array $waf_rules
	 * @param array $locationmatch_rules
	 * @param int   $available_rules
	 * @param array $remove_rules
	 * @return array
	 */
	public function waf_engine( $waf_rules, $locationmatch_rules, $available_rules, $remove_rules, $deny_on_backtrack_error = '1' ): array {
		$request_items = $this->get_request_items();

		$locationmatch_removed_rule_ids = $this->locationmatch_remove_rules( $locationmatch_rules, $_SERVER['REQUEST_URI'] ?? '' );
		$skip                           = 0;
		$skipafter                      = '';
		$chain_items                    = array();
		$tmp_match_results              = array();

		// Advanced Custom Fieldsプラグイン除外対応で追加
		$acf_post_types = $this->get_acf_post_types();
		// Custom Post Type UIプラグイン除外対応で追加
		$cptui_post_types = $this->get_cptui_post_types();

		foreach ( $waf_rules as $waf_rule ) {
			// 前回マッチしたルールからskipの設定を引き継いでいる場合はスキップ
			if ( $this->is_skip_enabled( $skip ) ) {
				$skip--;
				continue;
			}

			// 前回マッチしたルールからskipafterの設定を引き継いでいる場合は現在のルールIDと比較し、一致するまでスキップ
			// ルールIDの比較結果が同じの場合は、$skipafterを初期化して次のルールから判定を行う
			if ( $this->is_skipafter_enabled( $skipafter ) ) {
				if ( $skipafter !== $waf_rule['id'] ) {
					continue;
				} else {
					$skipafter = '';
					continue;
				}
			}

			// LocationMatchによるルールの除外があるか確認。ある場合は現在のルールIDと比較し、一致する場合はスキップ
			if ( ! empty( $locationmatch_removed_rule_ids ) ) {
				if ( in_array( $waf_rule['id'], $locationmatch_removed_rule_ids, true ) ) {
					continue;
				}
			}

			// ルールにvariables設定がない場合、skip,akipafterの設定を確認して次のルール判定へ
			if ( empty( $waf_rule['variables'] ) ) {
				$skip      = $this->check_skip( $waf_rule['skip'] );
				$skipafter = $this->check_skipafter( $waf_rule['skipafter'] );
				continue;
			}

			// 特定の操作の場合、特定のルールを除外する
			$remove_rule_result = $this->is_remove_rule( $waf_rule['id'], $request_items, $remove_rules, $acf_post_types, $cptui_post_types );

			if ( $remove_rule_result['is_removed'] ) {
				continue;
			}

			// ルールのremove_variablesを動的に変更
			if ( ! empty( $remove_rule_result['modify_remove_variables'] ) ) {
				$waf_rule['remove_variables'] = array_merge_recursive(
					$waf_rule['remove_variables'],
					$remove_rule_result['modify_remove_variables']
				);
			}

			// ルールのvariablesを動的に変更
			if ( ! empty( $remove_rule_result['modify_variables'] ) ) {
				$waf_rule['variables'] = array_diff(
					$waf_rule['variables'],
					$remove_rule_result['modify_variables']
				);
			}

			foreach ( $waf_rule['variables'] as $variable ) {
				switch ( $variable ) {
					case self::VARIABLE_ARGS_GET:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_ARGS_GET, $chain_items );
						break;

					case self::VARIABLE_ARGS_GET_NAMES:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_ARGS_GET_NAMES, $chain_items );
						break;

					case self::VARIABLE_ARGS_POST:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_ARGS_POST, $chain_items );
						break;

					case self::VARIABLE_ARGS_POST_NAMES:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_ARGS_POST_NAMES, $chain_items );
						break;

					case self::VARIABLE_REQUEST_COOKIES:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_REQUEST_COOKIES, $chain_items );
						break;

					case self::VARIABLE_REQUEST_COOKIES_NAMES:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_REQUEST_COOKIES_NAMES, $chain_items );
						break;

					case self::VARIABLE_REQUEST_HEADERS:
						$results = $this->check_request_item_array( $waf_rule, $request_items, self::VARIABLE_REQUEST_HEADERS, $chain_items );
						break;

					case self::VARIABLE_REQUEST_FILENAME:
						$results = $this->check_request_item_strings( $waf_rule, $request_items, self::VARIABLE_REQUEST_FILENAME, $chain_items );
						break;

					case self::VARIABLE_XML:
						$results = $this->check_request_item_strings( $waf_rule, $request_items, self::VARIABLE_XML, $chain_items );
						break;
				}

				// プリフィルタ（attack='')でバックトラック超過エラーが発生した場合は一致側に倒し、
				// 除外対象に関わらず、後続の精密ルールに進んで判定する
				if ( ! empty( $results['has_backtrack_error'] ) && '' === $waf_rule['attack'] ) {
					$results = $this->get_rule_settings_and_results( $waf_rule, $request_items, $variable, $chain_items, '' );
				}

				// バックトラック超過エラーの処理
				// 編集権限を持つログインユーザー（Cookie認証）は遮断・ログ記録の対象外とし、
				// それ以外（未ログイン・権限なしユーザー）の場合のみ以降の判定を行う
				if ( ! empty( $results['has_backtrack_error'] ) && ! $this->is_excluded_user_by_cookie() ) {
					$backtrack_error_result = $this->get_backtrack_error_results( $request_items, $variable, $results['backtrack_key'] ?? '' );

					// 有効な攻撃種別かつ即遮断設定（'1'）の場合のみ遮断する。
					if ( ( $waf_rule['attack'] & $available_rules ) !== 0 && $deny_on_backtrack_error === '1' ) {
						// バックトラック超過発生時点で即遮断
						$backtrack_error_result['is_deny']      = true;
						$backtrack_error_result['is_write_log'] = true;

						return $backtrack_error_result;
					}
					// 遮断しない場合（無効化された攻撃種別、または '0'：ログのみ設定）は
					// バックトラックエラーをログ候補として保持し、次のルールへ続行
					$tmp_match_results = $backtrack_error_result;
				}

				$is_matched = $results['is_matched'];

				if ( $is_matched ) {
					$skip          = $results['skip'];
					$skipafter     = $results['skipafter'];
					$chain_items   = $results['chain_items'];
					$match_results = $results['match_results'];

					// マッチしたが、chain,skip,skipafterの設定がある場合は次のルール判定へ
					if ( ! empty( $chain_items ) || 0 < $skip || ! empty( $skipafter ) ) {
						break;
					}

					// マッチしたが、除外設定されているルールの場合は値を保持して次のルール判定へ
					if ( ( $waf_rule['attack'] & $available_rules ) === 0 ) {
						$tmp_match_results = $match_results;
						break;
					}

					// マッチした結果がある場合は終了処理へ（ログ記述、通知、画面表示）
					if ( ! empty( $match_results ) ) {
						$match_results['is_deny']            = true;
						$match_results['is_write_log']       = true;
						$match_results['is_backtrack_error'] = false;

						return $match_results;
					}
				}

				$chain_items = array();
			}
		}

		if ( ! empty( $tmp_match_results ) ) {
			$match_results                       = $tmp_match_results;
			$match_results['is_deny']            = false;
			$match_results['is_write_log']       = true;
			$match_results['is_backtrack_error'] = ! empty( $match_results['is_backtrack_error'] );

		} else {
			$match_results['is_deny']            = false;
			$match_results['is_write_log']       = false;
			$match_results['is_backtrack_error'] = false;
		}

		return $match_results;
	}
}
