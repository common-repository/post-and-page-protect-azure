<?php
/**
 * Plugin Name: Post and Page Protect with Azure AD
 * Description: Add protection to individual posts and pages using Azure Active Directory OAuth 2.0
 * Version: 1.2.0
 * Author: Dash10 Digital
 * Author URI: https://dash10.digital
 */

/**
 * Register meta box(es) for both posts and pages
 *
 */
add_action( 'add_meta_boxes', 'azure_ad_protect_register_meta_box' );
function azure_ad_protect_register_meta_box() {
	add_meta_box( 'azure_ad_protection', __( 'Azure AD Protect Information' ), 'azure_ad_protect_metabox_callback',
		array(
			'page',
			'post'
		) );
}

/**
 * Meta box display callback.
 *
 * @param WP_Post $post Current post object.
 */
function azure_ad_protect_metabox_callback( $post ) {
	wp_nonce_field( 'update_azure_data', '_azure_nonce' );
	?>
    <p>
        When creating the Azure application use the following information:<br/><br/>
        <strong>Reply URL</strong>: <?php echo get_permalink( $post->ID ); ?>
    </p>
    <hr/>
    <table class="form-table">
        <tr>
            <th scope="row">Enable Azure AD protection for this post/page</th>
            <td>
                <input type="checkbox" name="azure_ad_protect_enabled" value="1"
					<?php if ( get_post_meta( $post->ID, '_azure_ad_protect_enabled', true ) == 'yes' ) {
						echo 'checked';
					}; ?>/>
            </td>
        </tr>
        <tr>
            <th scope="row">Directory (tenant) ID</th>
            <td>
                <input style="width: 100%;" type="text" name="azure_ad_protect_directory_id"
                       value="<?php echo get_post_meta( $post->ID, '_azure_ad_protect_directory_id', true ); ?>"
                       placeholder=""/>
            </td>
        </tr>
        <tr>
            <th scope="row">Application ID</th>
            <td>
                <input style="width: 100%;" type="text" name="azure_ad_protect_application_id"
                       value="<?php echo get_post_meta( $post->ID, '_azure_ad_protect_application_id', true ); ?>"
                       placeholder=""/>
            </td>
        </tr>
        <tr>
            <th scope="row">Application Secret</th>
            <td>
                <input style="width: 100%;" type="text" name="azure_ad_protect_application_secret"
                       value="<?php echo get_post_meta( $post->ID, '_azure_ad_protect_application_secret', true ); ?>"
                       placeholder=""/>
            </td>
        </tr>
    </table>
	<?php
}

/**
 * Save meta box content.
 *
 * @param int $post_id Post ID
 */
add_action( 'save_post', 'azure_ad_protect_save_post_meta_update' );
function azure_ad_protect_save_post_meta_update( $post_id ) {
	if ( isset( $_POST['azure_ad_protect_application_id'] ) ) {
		$enabled            = isset( $_POST['azure_ad_protect_enabled'] ) ? 'yes' : 'no';
		$app_id             = sanitize_text_field( $_POST['azure_ad_protect_application_id'] );
		$application_secret = sanitize_text_field( $_POST['azure_ad_protect_application_secret'] );
		$directory_id       = sanitize_text_field( $_POST['azure_ad_protect_directory_id'] );

		update_post_meta( $post_id, '_azure_ad_protect_enabled', $enabled );
		update_post_meta( $post_id, '_azure_ad_protect_application_id', $app_id );
		update_post_meta( $post_id, '_azure_ad_protect_directory_id', $directory_id );
		update_post_meta( $post_id, '_azure_ad_protect_application_secret', $application_secret );
	}
}

/**
 * Preform checks before page and post template redirect
 *
 */
add_action( 'wp', 'azure_protect_wp_hook', 9999 );
function azure_protect_wp_hook() {

	$post_id                  = get_queried_object_id();
	$azure_directory_id       = get_post_meta( $post_id, '_azure_ad_protect_directory_id', true );
	$azure_application_id     = get_post_meta( $post_id, '_azure_ad_protect_application_id', true );
	$azure_application_secret = get_post_meta( $post_id, '_azure_ad_protect_application_secret', true );

	if ( get_post_meta( $post_id, '_azure_ad_protect_enabled', true ) == 'yes' ) {

		if ( function_exists( 'mk_purge_cache_actions' ) ) {
			mk_purge_cache_actions();
		}
		header( "Cache-Control: no-store, no-cache, must-revalidate" ); // HTTP/1.1
		header( "Cache-Control: post-check=0, pre-check=0", false );
		header( "Expires: Sat, 26 Jul 1997 05:00:00 GMT" ); // Date in the past
		header( "Pragma: no-cache" ); // HTTP/1.0
		header( "Last-Modified: " . gmdate( "D, d M Y H:i:s" ) . " GMT" );

		if ( isset( $_REQUEST['code'] ) ) {
			$post_data = array(
				'grant_type'    => 'authorization_code',
				'code'          => sanitize_text_field( $_REQUEST['code'] ),
				'redirect_uri'  => get_permalink( $post_id ),
				'client_id'     => $azure_application_id,
				'client_secret' => $azure_application_secret,
				'resource'      => $azure_application_id // <---- WHY? A MS THING I GUESS
			);

			$response = wp_remote_post( 'https://login.microsoftonline.com/' . $azure_directory_id . '/oauth2/token/', array(
					'method'      => 'POST',
					'timeout'     => 45,
					'redirection' => 5,
					'httpversion' => '1.0',
					'blocking'    => true,
					'headers'     => array(),
					'body'        => $post_data,
					'cookies'     => array()
				)
			);

			$response = wp_remote_retrieve_body( $response );
			$response = json_decode( $response );

			if ( isset( $response->access_token ) ) {
				if ( false == get_option( '_ad_protect_' . sha1( sanitize_text_field( $_REQUEST['code'] ) ), false ) ) {
					update_option( '_ad_protect_' . sha1( sanitize_text_field( $_REQUEST['code'] ) ), '1' );
				} else {
					wp_redirect( 'https://login.microsoftonline.com/' . $azure_directory_id . '/oauth2/authorize/' . '?client_id=' . $azure_application_id . '&response_type=code&response_mode=query&redirect_uri=' . get_permalink( $post_id ) . '&prompt=consent' );
				}
			} else {
				wp_die( 'Access Denied: ' . $response->error_description );
				exit;
			}
		} else {
			wp_redirect( 'https://login.microsoftonline.com/' . $azure_directory_id . '/oauth2/authorize/' . '?client_id=' . $azure_application_id . '&response_type=code&response_mode=query&redirect_uri=' . get_permalink( $post_id ) . '&prompt=consent' );
		}
	}
}