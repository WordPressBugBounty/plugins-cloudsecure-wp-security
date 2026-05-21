<?php

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit();
}

/**
 * プラグインuninstall時の処理
 */
function cloudsecurewp_uninstall() {
	global $wpdb;

	// cloudsecurewp_で始まるオプションを削除.
	$options = $wpdb->get_results( $wpdb->prepare( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE %s", $wpdb->esc_like( 'cloudsecurewp_' ) . '%' ) );
	foreach ( $options as $option ) {
		delete_option( $option->option_name );
	}

	// cloudsecurewp_で始まるトランジェントを削除.
	$transients = $wpdb->get_results( $wpdb->prepare( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_cloudsecurewp_' ) . '%' ) );
	foreach ( $transients as $transient ) {
		$key = substr( $transient->option_name, strlen( '_transient_' ) );
		delete_transient( $key );
	}

	// wp_cloudsecurewp_で始まるユーザーメタを削除.
	delete_metadata( 'user', 0, 'wp_cloudsecurewp_two_factor_authentication_email_send', '', true );
	delete_metadata( 'user', 0, 'wp_cloudsecurewp_two_factor_authentication_last_success', '', true );

	// 独自prefix + cloudsecurewp_で始まるユーザーオプションを削除.（削除漏れ対策のために残す）
	$user_options = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_key FROM $wpdb->usermeta WHERE meta_key LIKE %s", $wpdb->esc_like( $wpdb->get_blog_prefix() . 'cloudsecurewp_' ) . '%' ) );
	foreach ( $user_options as $user_option ) {
		delete_user_option( (int) $user_option->user_id, $user_option->meta_key, true );
	}

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_login" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_login_log" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_server_error" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_waf_log" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_2fa_auth" );
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}cloudsecurewp_2fa_login" );
}

cloudsecurewp_uninstall();
