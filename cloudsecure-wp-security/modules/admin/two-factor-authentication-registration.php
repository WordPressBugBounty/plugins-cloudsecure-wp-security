<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CloudSecureWP_Admin_Two_Factor_Authentication_Registration extends CloudSecureWP_Admin_Common {
	private $two_factor_authentication;
	/**
	 * 認証方法
	 *
	 * @var bool
	 */
	private $auth_method;
	/**
	 * リカバリーコードが登録済みかどうか
	 *
	 * @var bool
	 */
	private $is_registered_recovery;
	/**
	 * 使用可能なリカバリーコードの数
	 *
	 * @var bool
	 */
	private $recovery_cnt;
	/**
	 * ユーザのメールアドレス
	 *
	 * @var string
	 */
	private $mail_address;

	function __construct( array $info, CloudSecureWP_Two_Factor_Authentication $two_factor_authentication ) {
		parent::__construct( $info );
		$this->two_factor_authentication = $two_factor_authentication;
		$this->prepare_view_data();
		$this->render();
	}

	/**
	 * 画面表示用のデータを準備
	 */
	public function prepare_view_data(): void {
		$user_id   = get_current_user_id();
		$auth_info = $this->two_factor_authentication->get_2fa_auth_info( $user_id );

		$this->auth_method            = $this->two_factor_authentication::USER_AUTH_METHOD_NONE;
		$this->is_registered_recovery = false;
		$this->recovery_cnt           = 0;
		$this->mail_address           = $this->two_factor_authentication->mask_email( $user_id );

		if ( count( $auth_info ) === 0 ) {
			$auth_info = $this->two_factor_authentication->repair_migration_gaps( $user_id );
		}
		
		if ( count( $auth_info ) > 0 ) {
			$this->auth_method = intVal( $auth_info['method'] );

			if ( ! is_null( $auth_info['recovery'] ) ) {
				$this->is_registered_recovery = true;
				$this->recovery_cnt           = count( $auth_info['recovery'] );
			}
		}

		if ( isset( $_POST['message'] ) ) {
			$message = sanitize_text_field( $_POST['message'] ) ?? '';
			if ( ! empty( $message ) ) {
				$this->messages[] = $message;
			}
		}
		if ( isset( $_POST['error'] ) ) {
			$error = sanitize_text_field( $_POST['error'] ) ?? '';
			if ( ! empty( $error ) ) {
				$this->errors[] = $error;
			}
		}
	}

	/**
	 * ディスクリプション
	 */
	protected function admin_description(): void {
		?>
		<div class="title-block mb-12">
			<h1 class="title-block-title">2段階認証の設定</h1>
			<p class="title-block-small-text">この機能のマニュアルは<a class="title-block-link" target="_blank"
																href="https://wpplugin.cloudsecure.ne.jp/cloudsecure_wp_security/two_factor_authentication.php">こちら</a>
			</p>
		</div>
		<div class="title-bottom-text">
			2段階認証に使用する認証方法を設定します。<br />
			Google Authenticator またはメール認証のいずれかを使用できます。
		</div>
		<?php
	}

	/**
	 * ページコンテンツ
	 */
	protected function page(): void {
		?>
		<div id="two-fa-setting-area">
			<div class="box">
				<div class="box-bottom">
					<div class="box-row">
						<div class="box-row-title not-label">
							<label for="key">設定方法</label>
						</div>
						<div class="box-row-content">
							<div id="auth-method-status" class="status-area" data-auth-method="<?php echo esc_attr( $this->auth_method ); ?>">
								<?php if ( $this->auth_method === $this->two_factor_authentication::USER_AUTH_METHOD_APP ) : ?>
									<div class="status-area-text">										
										<p class="status-text">Authenticatorアプリ</p>
									</div>
								<?php elseif ( $this->auth_method === $this->two_factor_authentication::USER_AUTH_METHOD_EMAIL ) : ?>
									<div class="status-area-text">
										<p class="status-text">メール認証</p>
									</div>
								<?php else : ?>
									<div class="status-not-registered-back-none status-area-text">
										<span class="dashicons dashicons-warning"></span>
										<p class="status-text">未設定</p>
									</div>
								<?php endif; ?>
								<button id="register-method" type="button" class="status-area-btn button">
									<?php echo ( $this->auth_method === $this->two_factor_authentication::USER_AUTH_METHOD_NONE ? '設定' : '設定を変更' ); ?>
								</button>
							</div>
						</div>
					</div>
					<div class="box-row">
						<div class="box-row-title not-label">
							<label for="key">リカバリーコード</label>
							<div class="description-recovery-code">
								<p class="description-text">デバイス紛失時などの緊急時、<br class="pc-only">認証代わりに使用できるコードです。</p>
							</div>
						</div>
						<div class="box-row-content">
							<div id="recovery-code-status" class="status-area" data-is-registered-recovery="<?php echo esc_attr( $this->is_registered_recovery ? 1 : 0 ); ?>">
								<div class="status-area-text">
									<?php if ( $this->is_registered_recovery ) : ?>		
										<p class="status-text">生成済み（残り<?php echo esc_html( $this->recovery_cnt ); ?>個）</p>
									<?php else : ?>
										<div class="status-not-registered-back-none status-area-text">
											<span class="dashicons dashicons-warning"></span>
											<p class="status-text">未生成</p>
										</div>
										<?php if ( $this->auth_method === $this->two_factor_authentication::USER_AUTH_METHOD_NONE ) : ?>
											<p class="status-text description">※認証方法の設定完了後、生成可能になります。</p>
										<?php endif; ?>
									<?php endif; ?>
								</div>
								<button id="generate-recovery" type="button" class="status-area-btn button" <?php echo ( $this->auth_method === $this->two_factor_authentication::USER_AUTH_METHOD_NONE ? 'disabled' : '' ); ?>>
									<?php echo ( $this->is_registered_recovery ? '再生成' : '生成' ); ?>
								</button>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- 設定モーダル -->
			<div id="setting-modal" class="setting-modal" style="display: none;" data-setting-status="" data-regist-status="">
				<div class="setting-modal-content">
					<div class="setting-modal-header">
						<h2 id="setting-modal-title">
							<!-- タイトル -->
						</h2>
						<span class="dashicons dashicons-no-alt modal-close"></span>
					</div>
					<div id="setting-modal-body" class="setting-modal-body">
						<!-- テンプレート -->
					</div>
				</div>
			</div>

			<!-- 確認モーダル -->
			<div id="confirm-modal" class="confirm-modal" style="display: none;" data-confirm-status="">
				<div class="confirm-modal-content">
					<div class="confirm-modal-body">
						<div class="confirm-message-area">
							<h2 id="confirm-message-title">
								<!-- タイトル -->
							</h2>
							<div id="confirm-message-body" class="confirm-message-body">
								<!-- 本文 -->
							</div>
						</div>
						<div id="confirm-modal-btn" class="modal-btn-area-end">
							<button type="button" id="confirm-modal-cancel" class="button button-gray modal-close style-cancel">キャンセル</button>
							<button type="button" id="confirm-modal-ok" class="button button-blue modal-next style-next">OK</button>
						</div>
					</div>
				</div>
			</div>

			<?php $this->nonce_wp( $this->two_factor_authentication->get_feature_key() ); ?>
			<input type="hidden" id="ajax-url" value="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" />
		</div>

		<!-- 認証方法選択テンプレート -->
		<template id="select-method-modal">
			<p class="modal-text">認証方法を選択してください。</p>
			<div class="auth-method-options">
				<div class="auth-method-option">
					<input type="radio" class="circle-radio" id="auth_method_app" name="auth_method_select" value="app" checked>
					<label for="auth_method_app" class="auth-method-label">
						<img src="<?php echo esc_url( plugin_dir_url( dirname( __FILE__, 2 ) ) . 'assets/images/icon_mobile.svg?v=1' ); ?>" alt="スマホアイコン" class="auth-method-icon">
						<span class="auth-method-text">Google Authenticatorで認証する</span>
					</label>
				</div>
				<div class="auth-method-option">
					<input type="radio" class="circle-radio" id="auth_method_email" name="auth_method_select" value="email">
					<label for="auth_method_email" class="auth-method-label">
						<img src="<?php echo esc_url( plugin_dir_url( dirname( __FILE__, 2 ) ) . 'assets/images/icon_mail.svg?v=1' ); ?>" alt="メールアイコン" class="auth-method-icon">
						<span class="auth-method-text">メールアドレスで認証する</span>
					</label>
				</div>
			</div>
			<div class="modal-btn-area-end">
				<button type="button" id="setting-modal-cancel" class="button button-gray modal-close">キャンセル</button>
				<button type="button" id="setting-modal-next" class="button button-blue modal-next">次へ</button>
			</div>
		</template>

		<!-- Google Authenticator設定テンプレート -->
		<template id="app-auth-modal">
			<div id="message-area" class="info-box blue" style="display: none;"></div>
			<div id="error-area" class="error-box red" style="display: none;"></div>
			<p class="modal-text">
				<a class="title-block-link" href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank">Google Authenticator</a>　で以下のQRコードを読み込み、表示された認証コードを入力してください。QRコードを読み込めない場合は、セットアップキーを手動で入力してください。
			</p>
			<div class="qr-setup-container">
				<div id="qrcode_container" class="qr-code-section">
					<div id="qrcode">
						<!-- QRコード表示エリア -->
					</div>
				</div>
				<div class="setup-key-section">
					<div class="generate-key-section" style="text-align: left;">
						<p class="modal-text">セットアップキー：<span id="setup_key_display"></span></p>
						<p class="modal-text" style="color: #2271b1;"><span class="dashicons dashicons-update"></span><a href="#" id="regenerate-key">新しいキーを生成</a></p>
					</div>
					<div class="input-code-section">
						<label for="verification-code">認証コード（6桁）</label>
						<input type="text" id="verification-code" name="verification_code" class="verification-code-app" placeholder="例）123456" />
					</div>
				</div>
			</div>
			<div class="modal-btn-area-end">
				<input type="hidden" id="secret-key" value="" />
				<button type="button" id="setting-modal-cancel" class="button button-gray modal-close">キャンセル</button>
				<button type="button" id="setting-modal-next" class="button button-blue modal-next">設定を完了</button>
			</div>
		</template>

		<!-- メール認証設定テンプレート -->
		<template id="email-auth-modal">
			<div id="message-area" class="info-box blue" style="display: none;"></div>
			<div id="error-area" class="error-box red" style="display: none;"></div>
			<p class="modal-text">
				ログイン時に登録されているメールアドレスに認証コードを送信しました。<br />
				受信した認証コードを入力してください。<br />
				メールアドレス: <strong><?php echo esc_html( $this->mail_address ); ?></strong>
			</p>
			<div class="input-code-section">
				<label for="verification-code">認証コード（6桁）</label>
				<input type="text" id="verification-code" name="verification_code" class="verification-code-email" placeholder="例）123456" />
			</div>
			<p class="description">
				※メールが届かない場合は、迷惑メールフォルダをご確認ください。<br />
				　メールが見つからない場合は、<a href="#" id="resend-email-code" class="resend-email-code-inactive">認証コードを再送信</a> できます。<span class="countdown-message"></span>
			</p>
			<div class="modal-btn-area-end">
				<input type="hidden" id="secret-key" value="" />
				<button type="button" id="setting-modal-cancel" class="button button-gray modal-close">キャンセル</button>
				<button type="button" id="setting-modal-next" class="button button-blue modal-next">設定を完了</button>
			</div>
		</template>

		<!-- リカバリーコードの作成案内テンプレート -->
		<template id="suggest-recovery-modal">
			<div class="status-registered-back-none">
				<span class="dashicons dashicons-yes-alt"></span>
				<p class="h2-text"><strong>2段階認証が有効になりました。</strong></p>
			</div>
			<div class="recovery-text-area">
				<p class="modal-text">続けて、<strong>リカバリーコードを生成し、安全な場所に保管してください。</strong></p>
				<p class="modal-text">未生成の場合、デバイス紛失時などにログインできなくなる恐れがあります。</p>
			</div>
			<div class="modal-btn-area-end">
				<button type="button" id="setting-modal-cancel" class="button button-gray modal-close">あとで生成</button>
				<button type="button" id="setting-modal-next" class="button button-blue modal-next">リカバリーコードを生成</button>
			</div>
		</template>
		
		<!-- リカバリーコードテンプレート（成功） -->
		<template id="recovery-code-modal-success">
			<div class="recovery-modal-body-top">
				<div class="recovery-text-area">
					<p class="modal-text" style="margin-bottom: 4px;">リカバリーコードを生成しました。</p>
					<div class="recovery-text">
						<div class="black-circle"></div><p class="modal-text">この画面を閉じると<strong>コードは再表示できません</strong>。</p>
					</div>
					<div class="recovery-text">
						<div class="black-circle"></div><p class="modal-text">各コードは1回のみ使用できます。</p>
					</div>
					<div class="recovery-text">
						<div class="black-circle"></div><p class="modal-text">必ずコピーまたはダウンロードして安全な場所に保管してください。</p>
					</div>
				</div>
				<div id="recovery-codes-container" class="recovery-codes-grid">
					<!-- リカバリーコード表示エリア -->
				</div>
				<div class="modal-btn-area-center">
					<button type="button" id="recovery-code-copy" class="button button-blue">コピー</button>
					<button type="button" id="recovery-code-download" class="button button-blue">ダウンロード</button>
				</div>
			</div>
			<div class="recovery-modal-body-bottom">
				<div class="modal-btn-area-end">
					<button type="button" id="recovery-modal-close" class="button modal-close">閉じる</button>
				</div>
			</div>
		</template>

		<!-- リカバリーコードテンプレート（失敗） -->
		<template id="recovery-code-modal-failure">
			<div class="recovery-modal-body-top">
				<p class="modal-text">エラーが発生しました。しばらく待ってから再度お試しください。</p>
			</div>
			<div class="recovery-modal-body-bottom">
				<div class="modal-btn-area-end">
					<button type="button" id="recovery-modal-close" class="button modal-close">閉じる</button>
					<button type="button" id="recovery-modal-retry" class="button modal-next">再試行</button>
				</div>
			</div>
		</template>

		<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
				type="text/javascript"></script>
		<script type="text/javascript">
			const messageRegist           = '認証方法の設定が完了しました。'; 
			const messageUpdate           = '認証方法の変更が完了しました。';
			const messageError            = 'エラーが発生しました。しばらく待ってから再度お試しください。';
			const messageAppCodeEmpty     = '認証に失敗しました。<br />QRコードをGoogle Authenticator でスキャンし、認証コードを入力してください。';
			const messageAppCodeInvalid   = '認証に失敗しました。コードが正しいか確認し、もう一度お試しください。';
			const messageEmailCodeEmpty   = '認証に失敗しました。メールで送信された認証コードを入力してください';
			const messageEmailCodeInvalid = '認証に失敗しました。認証コードが間違っているか、有効期限が切れています。';
			const messageEmailSent        = '認証コードを再送信しました。メールをご確認ください。';
			const ajaxUrl                 = document.getElementById('ajax-url').value;

			let emailSentTime    = null;
			let countdownTimeout = null;
			let qrcodeInstance   = null;

			// モーダル内のすべてのボタンを非活性処理
			function disableModalButtons() {
				const settingModal = document.getElementById('setting-modal');
				const confirmModal = document.getElementById('confirm-modal');
				
				if (settingModal && settingModal.style.display === 'block') {
					const buttons = settingModal.querySelectorAll('button');
					buttons.forEach(btn => {
						btn.disabled = true;
					});
					// ×ボタンも非活性化
					const closeIcon = settingModal.querySelector('.dashicons.modal-close');
					if (closeIcon) {
						closeIcon.style.pointerEvents = 'none';
						closeIcon.style.opacity = '0.5';
					}
				}
				
				if (confirmModal && confirmModal.style.display === 'block') {
					const buttons = confirmModal.querySelectorAll('button');
					buttons.forEach(btn => {
						btn.disabled = true;
					});
					// ×ボタンも非活性化
					const closeIcon = confirmModal.querySelector('.dashicons.modal-close');
					if (closeIcon) {
						closeIcon.style.pointerEvents = 'none';
						closeIcon.style.opacity = '0.5';
					}
				}
			}
			// モーダル内のすべてのボタンを活性処理
			function enableModalButtons() {
				const settingModal = document.getElementById('setting-modal');
				const confirmModal = document.getElementById('confirm-modal');
				
				if (settingModal && settingModal.style.display === 'block') {
					const buttons = settingModal.querySelectorAll('button');
					buttons.forEach(btn => {
						btn.disabled = false;
					});
					// ×ボタンも活性化
					const closeIcon = settingModal.querySelector('.dashicons.modal-close');
					if (closeIcon) {
						closeIcon.style.pointerEvents = 'auto';
						closeIcon.style.opacity = '1';
					}
				}
				
				if (confirmModal && confirmModal.style.display === 'block') {
					const buttons = confirmModal.querySelectorAll('button');
					buttons.forEach(btn => {
						btn.disabled = false;
					});
					// ×ボタンも活性化
					const closeIcon = confirmModal.querySelector('.dashicons.modal-close');
					if (closeIcon) {
						closeIcon.style.pointerEvents = 'auto';
						closeIcon.style.opacity = '1';
					}
				}
			}
			// ページリロード処理
			function reloadPageWithMessage(message, error) {
				const form = document.createElement('form');
				form.method = 'POST';
				form.action = window.location.href;
				
				const inputMessage = document.createElement('input');
				inputMessage.type = 'hidden';
				inputMessage.name = 'message';
				inputMessage.value = message;

				const inputError = document.createElement('input');
				inputError.type = 'hidden';
				inputError.name = 'error';
				inputError.value = error;
				
				form.appendChild(inputMessage);
				form.appendChild(inputError);
				document.body.appendChild(form);
				form.submit();
			}
			// モーダル内にメッセージ表示処理
			function showModalMessage(message) {
				const modalBody   = document.getElementById('setting-modal-body');
				const messageArea = document.getElementById('message-area');
				const errorArea   = document.getElementById('error-area');
				if (errorArea) {
					errorArea.innerHTML = '';
					errorArea.style.display = 'none';
				}
				if (messageArea) {
					messageArea.innerHTML = message;
					messageArea.style.display = 'block';
				}
				setTimeout(() => {
					modalBody.scrollTop = 0;
				}, 0);
			}
			// モーダル内にエラー表示処理
			function showModalError(message) {
				const modalBody   = document.getElementById('setting-modal-body');
				const messageArea = document.getElementById('message-area');
				const errorArea   = document.getElementById('error-area');
				if (messageArea) {
					messageArea.innerHTML = '';
					messageArea.style.display = 'none';
				}
				if (errorArea) {
					errorArea.innerHTML = message;
					errorArea.style.display = 'block';
				}
				setTimeout(() => {
					modalBody.scrollTop = 0;
				}, 0);
			}
			// 再送信リンクの有効/無効の制御処理
			function updateResendLinkState() {
				const resendLink = document.getElementById('resend-email-code');
				const countdownSpan = document.querySelector('.countdown-message');
				
				if (!resendLink || !emailSentTime || !countdownSpan) {
					return;
				}

				// 現在時刻と送信可能時刻を比較して残り秒数を計算
				const now = Date.now();
				const remaining = Math.ceil((emailSentTime - now) / 1000);

				if (remaining > 0) {
					// リンクを非活性化してカウントダウン表示
					resendLink.className = 'resend-email-code-inactive';
					countdownSpan.textContent = ` (${remaining}秒後)`;
					
					// 1秒後に再度更新
					countdownTimeout = setTimeout(updateResendLinkState, 1000);
				} else {
					// リンクを有効化してカウントダウン非表示
					resendLink.className = 'resend-email-code-active';
					countdownSpan.textContent = '';

					// タイマーを停止（これ以上更新不要）
					countdownTimeout = null;
				}
			}
			// カウントダウンタイマーを開始処理
			function startCountdown() {
				// 既存のタイマーがあればクリア
				if (countdownTimeout) {
					clearTimeout(countdownTimeout);
					countdownTimeout = null;
				}
				
				// 即座に状態を更新
				updateResendLinkState();
			}
			// QRコードを生成・表示処理
			function displayQRCode(key) {
				const qrcodeElement = document.getElementById('qrcode');
				const setupKeyDisplay = document.getElementById('setup_key_display');
				
				if (!qrcodeElement) {
					console.error('QRコード要素が見つかりません');
					return
				}

				// 既存のQRコードを完全にクリア
				qrcodeElement.innerHTML = '';
				qrcodeInstance = null;

				// 新しいQRCodeインスタンスを作成
				qrcodeInstance = new QRCode(qrcodeElement, {
					correctLevel: QRCode.CorrectLevel.M,
					width: 200,
					height: 200
				});

				// ユーザー名を取得
				const nameElement = document.querySelector('.display-name');
				const name = nameElement ? nameElement.textContent : 'User';

				// QRコードを生成
				const otpauthUrl = `otpauth://totp/${encodeURIComponent(name)}?secret=${key}&issuer=${location.hostname}`;
				qrcodeInstance.makeCode(otpauthUrl);

				// セットアップキーを表示
				if (setupKeyDisplay) {
					setupKeyDisplay.textContent = key;
				}

				// 認証コード入力欄をクリア&フォーカス
				setTimeout(function() {
					const codeInput = document.getElementById('verification-code');
					if (codeInput) {
						codeInput.value = '';
						codeInput.focus();
					}
				}, 100);
			}
			// メール認証コードを送信処理
			function generateSecretKeyAndsendEmail(resendFlg) {
				const nonce = document.getElementById('_wpnonce').value;
				
				if (!resendFlg) {
					disableModalButtons();
				}
				
				// AJAXでサーバーに送信
				jQuery.ajax({
					url: ajaxUrl,
					type: 'POST',
					data: {
						action: 'cloudsecurewp_generate_key_and_send_email',
						nonce: nonce,
					}
				})
				.done(function(response) {
					if (response.success) {
						if (resendFlg === false) {
							openAuthModal('email');
						}
						if (resendFlg && response.data.is_send_email) {
							showModalMessage(messageEmailSent);
						}
						// APIから受け取った残り秒数を使って送信可能時刻を計算
						const remainingSeconds = parseInt(response.data.remaining_seconds, 10);
						emailSentTime = Date.now() + (remainingSeconds * 1000);
						setTimeout(function() {
							startCountdown();
							const codeInput = document.getElementById('verification-code');
							if (codeInput) {
								codeInput.value = '';
								codeInput.focus();
							}
							if (!resendFlg) {
								enableModalButtons();
							}
						}, 100);
					} else {
						reloadPageWithMessage('', messageError);												
					}
					return;
				})
				.fail(function(xhr) {
					reloadPageWithMessage('', messageError);
					return;
				});
			}
			// 秘密鍵生成処理(サーバー側から取得)
			function generateSecretKey(reGenerateFlg) {
				const nonce = document.getElementById('_wpnonce').value;

				disableModalButtons();

				// AJAXでサーバーから秘密鍵を取得
				jQuery.ajax({
					url: ajaxUrl,
					type: 'POST',
					data: {
						action: 'cloudsecurewp_generate_key',
						nonce: nonce
					}
				})
				.done(function(response) {
					if (response.success) {
						const hexKey    = response.data.hex;
						const base32Key = response.data.base32;

						// モーダルを表示
						if (reGenerateFlg === false) {
							openAuthModal('app');
						}
						
						// DOMが構築されるのを待ってから処理を実行
						setTimeout(function() {
							const secretKeyEle = document.getElementById('secret-key');
							if (secretKeyEle) {
								secretKeyEle.value = hexKey;
							}
							displayQRCode(base32Key);
							enableModalButtons();
						}, 100);
					} else {
						reloadPageWithMessage('', messageError);
					}
					return;
				})
				.fail(function(xhr) {
					reloadPageWithMessage('', messageError);
					return;
				});
			}
			// 認証コード検証処理
			function verifyCode(method) {
				const secretKey        = document.getElementById('secret-key').value;
				const codeInput        = document.getElementById('verification-code');
				const code             = codeInput.value.trim();
				const nextBtn          = document.getElementById('setting-modal-next');
				const authMethodStatus = document.getElementById('auth-method-status').dataset.authMethod;
				const isRegistered     = (authMethodStatus !== '0') ? true : false;
				const nonce            = document.getElementById('_wpnonce').value;

				disableModalButtons();

				if (!code) {
					if (method === 'app') {
						showModalError(messageAppCodeEmpty);
					} else {
						showModalError(messageEmailCodeEmpty);
					}
					enableModalButtons();
					codeInput.value = '';
					codeInput.focus();
				} else {
					// AJAXでサーバーに送信
					jQuery.ajax({
						url: ajaxUrl,
						type: 'POST',
						data: {
							action: 'cloudsecurewp_verify_auth_code',
							nonce: nonce,
							secret_key: secretKey,
							code: code,
							method: method
						}
					})
					.done(function(response) {
						if (response.success) {
							if (response.data.has_recovery) {
								closeSettingModal();
								if (isRegistered) {
									reloadPageWithMessage(messageUpdate, '');
								} else {
									reloadPageWithMessage(messageRegist, '');
								}
							} else {
								document.getElementById('setting-modal').dataset.registStatus = isRegistered ? 'update' : 'regist';
								openSuggestRecoveryModal();
								enableModalButtons();
							}
							return;						
						} else {
							if (method === 'app') {
								showModalError(messageAppCodeInvalid);
							} else {
								showModalError(messageEmailCodeInvalid);
							}
							enableModalButtons();
							codeInput.value = '';
							codeInput.focus();
							return;
						}						
					})
					.fail(function(xhr) {
						reloadPageWithMessage('', messageError);
						return;
					})
				}
			}
			// リカバリーコード生成処理
			function generateRecoveryCode(openModalFlg) {
				const nonce      = document.getElementById('_wpnonce').value;

				if (openModalFlg) {
					disableModalButtons();
				}

				// AJAXでサーバーに送信
				jQuery.ajax({
					url: ajaxUrl,
					type: 'POST',
					data: {
						action: 'cloudsecurewp_generate_recovery_codes',
						nonce: nonce
					}
				})
				.done(function(response) {
					if (response.success && Array.isArray(response.data.codes) && response.data.codes.length > 0) {
						// 成功時のリカバリーコードモーダルを表示
						closeConfirmModal();
						openRecoveryCodesSuccessModal(response.data.codes)
						enableModalButtons();
						return;
					} else {
						// 失敗時のリカバリーコードモーダルを表示
						closeConfirmModal();
						openRecoveryCodesFailureModal()
						enableModalButtons();
						return;
					}
				})
				.fail(function(xhr) {
					// 失敗時のリカバリーコードモーダルを表示
					closeConfirmModal();
					openRecoveryCodesFailureModal()
					enableModalButtons();
					return;
				})
			}
			// リカバリーコードのコピー処理
			function codeCopy() {
				const codeItems = document.querySelectorAll('.recovery-code-item');
				const codes = Array.from(codeItems).map(item => item.textContent);
				const codesText = codes.join('\n');
				
				// HTTPS環境またはlocalhost: Clipboard APIを使用
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(codesText).then(function() {
						alert('クリップボードにコピーしました。');
					}).catch(function() {
						fallbackCopy(codesText);
					});
				} else {
					// HTTP環境: フォールバック処理
					fallbackCopy(codesText);
				}
			}			
			// HTTP環境用のフォールバックコピー処理
			function fallbackCopy(text) {
				const textarea = document.createElement('textarea');
				textarea.value = text;
				textarea.style.position = 'fixed';
				textarea.style.top = '0';
				textarea.style.left = '0';
				textarea.style.opacity = '0';
				document.body.appendChild(textarea);
				textarea.focus();
				textarea.select();
				
				try {
					const successful = document.execCommand('copy');
					if (successful) {
						alert('クリップボードにコピーしました。');
					} else {
						alert('コピーに失敗しました。手動でコードをコピーしてください。');
					}
				} catch (err) {
					alert('コピーに失敗しました。手動でコードをコピーしてください。');
				} finally {
					document.body.removeChild(textarea);
				}
			}
			// リカバリーコードのダウンロード処理
			function codeDownload() {
				const codeItems = document.querySelectorAll('.recovery-code-item');
				const codes = Array.from(codeItems).map(item => item.textContent);
				const codesText = codes.join('\n');
				const blob = new Blob([codesText], { type: 'text/plain' });
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.href = url;
				a.download = 'recovery-codes.txt';
				a.style.display = 'none';
				document.body.appendChild(a);
				a.click();
				
				setTimeout(function() {
					document.body.removeChild(a);
					URL.revokeObjectURL(url);
				}, 100);
			}
			// 選択モーダル表示処理
			function openSelectModal() {
				const settingModal = document.getElementById('setting-modal');
				const targetTitle  = document.getElementById('setting-modal-title');
				const targetBody   = document.getElementById('setting-modal-body');
				const template     = document.getElementById('select-method-modal');

				if (template) {
					settingModal.dataset.settingStatus = 'select_method';

					targetTitle.textContent = '認証方法の設定';
					targetBody.innerHTML    = '';

					const clone = document.importNode(template.content, true);
					targetBody.appendChild(clone);

					settingModal.style.display = 'block';
					document.body.style.overflowY = 'hidden';
				}
			}
			// 認証モーダル表示処理
			function openAuthModal(method) {
				const settingModal = document.getElementById('setting-modal');
				const settingTitle = document.getElementById('setting-modal-title');
				const settingBody  = document.getElementById('setting-modal-body');
				let template       = null;

				settingModal.dataset.settingStatus = method;

				if (method === 'app') {
					template = document.getElementById('app-auth-modal');
				} else if (method === 'email') {
					template = document.getElementById('email-auth-modal');
				}

				settingBody.innerHTML = '';
				
				const clone = document.importNode(template.content, true);
				settingBody.appendChild(clone);
			}
			// リカバリーコード生成提案モーダル表示処理
			function openSuggestRecoveryModal() {
				const settingModal = document.getElementById('setting-modal');
				const targetTitle  = document.getElementById('setting-modal-title');
				const targetBody   = document.getElementById('setting-modal-body');
				const template     = document.getElementById('suggest-recovery-modal');
				const clone        = document.importNode(template.content, true);
				settingModal.dataset.settingStatus = 'suggest_recovery';
				targetBody.innerHTML = '';
				targetBody.appendChild(clone);
			}
			// 成功時リカバリーコードモーダル表示処理
			function openRecoveryCodesSuccessModal(codes) {
				const settingModal = document.getElementById('setting-modal');
				const settingTitle = document.getElementById('setting-modal-title');
				const settingBody  = document.getElementById('setting-modal-body');

				settingModal.dataset.settingStatus = 'recovery_codes';
				settingTitle.textContent           = 'リカバリーコード';
				settingBody.innerHTML              = '';

				const template = document.getElementById('recovery-code-modal-success');
				const clone    = document.importNode(template.content, true);
				settingBody.appendChild(clone);

				// リカバリーコードを表示
				const container = document.getElementById('recovery-codes-container');		
				codes.forEach(function(code) {
					const codeItem = document.createElement('div');
					codeItem.className = 'recovery-code-item';
					codeItem.textContent = code;
					container.appendChild(codeItem);
				})

				settingBody.className = 'recovery-modal-body';
				settingModal.style.display = 'block';
			}
			// 失敗時リカバリーコードモーダル表示処理
			function openRecoveryCodesFailureModal() {
				const settingModal = document.getElementById('setting-modal');
				const settingTitle = document.getElementById('setting-modal-title');
				const settingBody  = document.getElementById('setting-modal-body');

				settingModal.dataset.settingStatus = 'recovery_codes';
				settingTitle.textContent           = 'リカバリーコードの生成に失敗しました';
				settingBody.innerHTML              = '';

				const template = document.getElementById('recovery-code-modal-failure');
				const clone    = document.importNode(template.content, true);
				settingBody.appendChild(clone);

				settingBody.className = 'recovery-modal-body';
				settingModal.style.display = 'block';
			}
			// 確認モーダル表示処理
			function openConfirmModal(status) {
				const contentBody  = document.getElementById('content-body');
				const modal        = document.getElementById('confirm-modal');
				const title        = document.getElementById('confirm-message-title');
				const modalBody    = document.getElementById('confirm-message-body');

				if (status === 'recovery') {
					title.textContent = 'リカバリーコードを再生成しますか？';
					modalBody.innerHTML    = `
						<div class="recovery-text">
							<div class="black-circle"></div><p class="modal-text">誰にも見られていない安全な環境で実行してください。</p>
						</div>
						<div class="recovery-text">
							<div class="black-circle"></div><p class="modal-text">再生成を行うと既存のリカバリーコードはすべて使用できなくなります。</p>
						</div>
					`;
					document.body.style.overflowY = 'hidden';
				} else {
					title.textContent = '処理を中断しますか？';
					modalBody.innerHTML    = '<p class="modal-text">保存していない変更は失われます。</p>';
				}

				modal.dataset.confirmStatus = status;
				modal.style.display = 'block';
			}
			// 設定モーダル非表示処理
			function closeSettingModal() {
				const settingModal = document.getElementById('setting-modal');
				const settingTitle  = document.getElementById('setting-modal-title');
				const settingBody   = document.getElementById('setting-modal-body');

				settingTitle.innerHTML = '';
				settingBody.innerHTML  = '';
				settingBody.className = 'setting-modal-body';
				settingModal.style.display = 'none';
			}
			// 確認モーダル非表示処理
			function closeConfirmModal() {
				const confirmModal = document.getElementById('confirm-modal');
				const confirmTitle  = document.getElementById('confirm-message-title');
				const confirmBody   = document.getElementById('confirm-message-body');

				confirmTitle.innerHTML = '';
				confirmBody.innerHTML  = '';
				confirmModal.style.display = 'none';
			}
			// 設定モーダルの次へボタン押下時のアクション
			function handleSettingNext(status) {
				if (status === 'select_method') {
					// 次へボタン押下時の処理
					const selectedMethod = document.querySelector('input[name="auth_method_select"]:checked').value;
					if (selectedMethod === 'app') {
						// アプリ認証の場合はQRコード生成処理を実行
						generateSecretKey(false);
					} else {
						generateSecretKeyAndsendEmail(false);
					}
				} else if (status === 'app' || status === 'email') {
					// 設定を完了ボタン押下時の処理
					verifyCode(status);
				} else if (status === 'suggest_recovery' || status === 'recovery_codes') {
					// リカバリーコードを生成ボタン押下時の処理
					generateRecoveryCode(true);
				}
			}
			// 確認モーダルの次へボタン押下時のアクション
			function handleConfirmNext(status) {
				if (status === 'recovery') {
					generateRecoveryCode(true);
				} else {
					if (countdownTimeout) {
						clearTimeout(countdownTimeout);
						countdownTimeout = null;
					}
					closeConfirmModal();
					closeSettingModal();
					document.body.style.overflowY = 'auto';
				}
			}
			// 設定モーダルの閉じるボタン押下時のアクション
			function handleSettingClose(status) {
				if (status === 'select_method') {
					closeSettingModal();
					document.body.style.overflowY = 'auto';
				} else if (status === 'suggest_recovery' || status === 'recovery_codes') {
					const registStatus = document.getElementById('setting-modal').dataset.registStatus;
					if (registStatus === 'regist') {
						reloadPageWithMessage(messageRegist, '');
					} else if (registStatus === 'update') {
						reloadPageWithMessage(messageUpdate, '');
					} else {
						reloadPageWithMessage('', '');
					}
				} else {
					openConfirmModal(status);
				}
			}
			// リカバリーコード生成ボタン押下時のアクション
			function handleCreateRecovery() {
				// リカバリーコードの生成状態を確認
				const registerMethodBtn    = document.getElementById('register-method');
				const generateRecoveryBtn  = document.getElementById('generate-recovery');
				const isRegisteredRecovery = document.getElementById('recovery-code-status').dataset.isRegisteredRecovery;
				if (isRegisteredRecovery === '1') {
					// 既にリカバリーコードが登録されている場合は確認モーダルを表示
					openConfirmModal('recovery');
				} else {
					// リカバリーコードが未登録の場合は直接生成処理を実行
					registerMethodBtn.disabled   = true;
					generateRecoveryBtn.disabled = true;
					generateRecoveryCode(false);
				}
			}

			// 画面読み込み時の処理
			document.addEventListener('DOMContentLoaded', function() {
				const registerMethodBtn       = document.getElementById('register-method');
				const generateRecoveryBtn     = document.getElementById('generate-recovery');
				const settingModal            = document.getElementById('setting-modal');
				const confirmModal            = document.getElementById('confirm-modal');

				// 認証方法「設定」ボタンのイベント付与
				if (registerMethodBtn) {
					registerMethodBtn.addEventListener('click', function() {
						openSelectModal();
					})
				}
				// リカバリーコード「生成」ボタンのイベント付与
				if (generateRecoveryBtn) {
					generateRecoveryBtn.addEventListener('click', function() {
						handleCreateRecovery();
					})
				}
				// 設定モーダル内のボタンイベント付与
				if (settingModal) {
					settingModal.addEventListener('click', (e) => {
						const nextSettingBtn   = e.target.closest('.modal-next');
						const closeSettingBtn  = e.target.closest('.modal-close');
						const regenerateKeyBtn = e.target.closest('#regenerate-key');
						const resendEmailBtn   = e.target.closest('#resend-email-code');
						const codeCopyBtn      = e.target.closest('#recovery-code-copy');
						const codeDownloadBtn  = e.target.closest('#recovery-code-download');
						// 共通「次へ」ボタンイベント付与
						if (nextSettingBtn) {
							const settingStatus = settingModal.dataset.settingStatus;
							handleSettingNext(settingStatus);
						}
						// 共通「キャンセル」ボタン「×」ボタンイベント付与
						if (closeSettingBtn) {
							const settingStatus = settingModal.dataset.settingStatus;
							handleSettingClose(settingStatus);
						}
						// シークレットキー再生成リンクイベント付与
						if (regenerateKeyBtn) {
							generateSecretKey(true);
						}
						// メール認証コード再送信リンクイベント付与
						if (resendEmailBtn) {
							generateSecretKeyAndsendEmail(true);
						}
						// リカバリーコードコピーイベント付与
						if (codeCopyBtn) {
							codeCopy();
						}
						// リカバリーコードダウンロードイベント付与
						if (codeDownloadBtn) {
							codeDownload();
						}
					});
				}
				// 確認モーダル内のボタンイベント付与
				if (confirmModal) {
					confirmModal.addEventListener('click', (e) => {
						const nextConfirmBtn  = e.target.closest('.modal-next');
						const closeConfirmBtn = e.target.closest('.modal-close');

						// 共通「次へ」ボタンイベント付与
						if (nextConfirmBtn) {
							const confirmStatus = confirmModal.dataset.confirmStatus;
							handleConfirmNext(confirmStatus);
						}
						// 共通「キャンセル」ボタン「×」ボタンイベント付与
						if (closeConfirmBtn) {
							closeConfirmModal();
						}
					})
				}
			})
		</script>

		<?php
	}
}
