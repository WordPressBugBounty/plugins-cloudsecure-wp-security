<?php
/*
  Class names are changed to avoid duplication.
  The class name has been changed from ReallySimpleCaptcha to CloudSecureWP_ReallySimpleCaptcha.
*/

/*
 * Plugin Name: Really Simple CAPTCHA
 * Plugin URI: https://contactform7.com/captcha/
 * Description: Really Simple CAPTCHA is a CAPTCHA module intended to be called from other plugins. It is originally created for my Contact Form 7 plugin.
 * Author: Takayuki Miyoshi
 * Author URI: https://ideasilo.wordpress.com/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Version: 2.2
 * Requires at least: 6.1
 * Requires PHP: 7.4
 */


if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'CLOUDSECUREWP_REALLYSIMPLECAPTCHA_VERSION', '2.2' );

class CloudSecureWP_ReallySimpleCaptcha {

	public $chars;
	public $char_length;
	public $fonts;
	public $tmp_dir;
	public $img_size;
	public $bg;
	public $fg;
	public $base;
	public $font_size;
	public $font_char_width;
	public $img_type;
	public $file_mode;
	public $answer_file_mode;

	public function __construct() {
		/* Characters available in images */
		$this->chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

		/* Length of a word in an image */
		$this->char_length = 4;

		/* Array of fonts. Randomly picked up per character */
		$this->fonts = array(
			path_join( __DIR__, 'gentium/GenBkBasR.ttf' ),
			path_join( __DIR__, 'gentium/GenBkBasI.ttf' ),
			path_join( __DIR__, 'gentium/GenBkBasBI.ttf' ),
			path_join( __DIR__, 'gentium/GenBkBasB.ttf' ),
		);

		/* Directory temporary keeping CAPTCHA images and corresponding text files */
		$this->tmp_dir = path_join( __DIR__, 'tmp' );

		/* Array of CAPTCHA image size. Width and height */
		$this->img_size = array( 72, 24 );

		/* Background color of CAPTCHA image. RGB color 0-255 */
		$this->bg = array( 255, 255, 255 );

		/* Foreground (character) color of CAPTCHA image. RGB color 0-255 */
		$this->fg = array( 0, 0, 0 );

		/* Coordinates for a text in an image. I don't know the meaning. Just adjust. */
		$this->base = array( 6, 18 );

		/* Font size */
		$this->font_size = 14;

		/* Width of a character */
		$this->font_char_width = 15;

		/* Image type. 'png', 'gif' or 'jpeg' */
		$this->img_type = 'png';

		/* Mode of temporary image files */
		$this->file_mode = 0644;

		/* Mode of temporary answer text files */
		$this->answer_file_mode = 0640;
	}

	/**
	 * Generate and return a random word.
	 *
	 * @return string Random word with $chars characters x $char_length length
	 */
	public function generate_random_word() {
		$word = '';

		for ( $i = 0; $i < $this->char_length; $i++ ) {
			$pos   = mt_rand( 0, strlen( $this->chars ) - 1 );
			$char  = $this->chars[ $pos ];
			$word .= $char;
		}

		return $word;
	}

	/**
	 * Generate CAPTCHA image and corresponding answer file.
	 *
	 * @param string $prefix File prefix used for both files
	 * @param string $word Random word generated by generate_random_word()
	 * @return string|bool The file name of the CAPTCHA image. Return false if temp directory is not available.
	 */
	public function generate_image( $prefix, $word ) {
		if ( ! $this->make_tmp_dir() ) {
			return false;
		}

		$this->cleanup();

		$dir      = trailingslashit( $this->tmp_dir );
		$filename = null;

		$im = imagecreatetruecolor(
			$this->img_size[0],
			$this->img_size[1]
		);

		if ( $im ) {
			$bg = imagecolorallocate( $im, $this->bg[0], $this->bg[1], $this->bg[2] );
			$fg = imagecolorallocate( $im, $this->fg[0], $this->fg[1], $this->fg[2] );

			imagefill( $im, 0, 0, $bg );

			$x = $this->base[0] + mt_rand( -2, 2 );

			for ( $i = 0; $i < strlen( $word ); $i++ ) {
				$font = $this->fonts[ array_rand( $this->fonts ) ];
				$font = wp_normalize_path( $font );

				imagettftext(
					$im,
					$this->font_size,
					mt_rand( -12, 12 ),
					$x,
					$this->base[1] + mt_rand( -2, 2 ),
					$fg,
					$font,
					$word[ $i ]
				);

				$x += $this->font_char_width;
			}

			switch ( $this->img_type ) {
				case 'jpeg':
					$filename = sanitize_file_name( $prefix . '.jpeg' );
					$file     = wp_normalize_path( path_join( $dir, $filename ) );
					imagejpeg( $im, $file );
					break;
				case 'gif':
					$filename = sanitize_file_name( $prefix . '.gif' );
					$file     = wp_normalize_path( path_join( $dir, $filename ) );
					imagegif( $im, $file );
					break;
				case 'png':
				default:
					$filename = sanitize_file_name( $prefix . '.png' );
					$file     = wp_normalize_path( path_join( $dir, $filename ) );
					imagepng( $im, $file );
			}

			imagedestroy( $im );
			@chmod( $file, $this->file_mode );
		}

		$this->generate_answer_file( $prefix, $word );

		return $filename;
	}

	/**
	 * Generate answer file corresponding to CAPTCHA image.
	 *
	 * @param string $prefix File prefix used for answer file
	 * @param string $word Random word generated by generate_random_word()
	 */
	public function generate_answer_file( $prefix, $word ) {
		$dir         = trailingslashit( $this->tmp_dir );
		$answer_file = path_join( $dir, sanitize_file_name( $prefix . '.txt' ) );
		$answer_file = wp_normalize_path( $answer_file );

		if ( $fh = @fopen( $answer_file, 'w' ) ) {
			$word = strtoupper( $word );
			$salt = wp_generate_password( 64 );
			$hash = hash_hmac( 'md5', $word, $salt );
			$code = $salt . '|' . $hash;
			fwrite( $fh, $code );
			fclose( $fh );
		}

		@chmod( $answer_file, $this->answer_file_mode );
	}

	/**
	 * Check a response against the code kept in the temporary file.
	 *
	 * @param string $prefix File prefix used for both files
	 * @param string $response CAPTCHA response
	 *
	 * @return bool Return true if the two match, otherwise return false.
	 */
	public function check( string $prefix, string $response ): bool {
		if ( 0 === strlen( $prefix ) ) {
			return false;
		}

		$response = str_replace( array( " ", "\t" ), '', $response );
		$response = strtoupper( $response );

		$dir      = trailingslashit( $this->tmp_dir );
		$filename = sanitize_file_name( $prefix . '.txt' );
		$file     = wp_normalize_path( path_join( $dir, $filename ) );

		if ( is_readable( $file )
		and $code = file_get_contents( $file ) ) {
			$code = explode( '|', $code, 2 );
			$salt = $code[0];
			$hash = $code[1];

			if ( hash_equals( $hash, hash_hmac( 'md5', $response, $salt ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Remove temporary files with given prefix.
	 *
	 * @param string $prefix File prefix
	 */
	public function remove( $prefix ) {
		$dir      = trailingslashit( $this->tmp_dir );
		$suffixes = array( '.jpeg', '.gif', '.png', '.php', '.txt' );

		foreach ( $suffixes as $suffix ) {
			$filename = sanitize_file_name( $prefix . $suffix );
			$file     = wp_normalize_path( path_join( $dir, $filename ) );

			if ( is_file( $file ) ) {
				@unlink( $file );
			}
		}
	}

	/**
	 * Clean up dead files older than given length of time.
	 *
	 * @param int $minutes Consider older files than this time as dead files
	 * @return int|bool The number of removed files. Return false if error occurred.
	 */
	public function cleanup( $minutes = 60, $max = 100 ) {
		$dir = trailingslashit( $this->tmp_dir );
		$dir = wp_normalize_path( $dir );

		if ( ! is_dir( $dir )
		or ! is_readable( $dir ) ) {
			return false;
		}

		$is_win = ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) );

		if ( ! ( $is_win ? win_is_writable( $dir ) : is_writable( $dir ) ) ) {
			return false;
		}

		$count = 0;

		if ( $handle = opendir( $dir ) ) {
			while ( false !== ( $filename = readdir( $handle ) ) ) {
				if ( ! preg_match( '/^[0-9]+\.(php|txt|png|gif|jpeg)$/', $filename ) ) {
					continue;
				}

				$file = wp_normalize_path( path_join( $dir, $filename ) );

				if ( ! file_exists( $file )
				or ! $stat = stat( $file ) ) {
					continue;
				}

				if ( ( $stat['mtime'] + $minutes * MINUTE_IN_SECONDS ) < time() ) {
					if ( ! @unlink( $file ) ) {
						@chmod( $file, 0644 );
						@unlink( $file );
					}

					$count += 1;
				}

				if ( $max <= $count ) {
					break;
				}
			}

			closedir( $handle );
		}

		return $count;
	}

	/**
	 * Make a temporary directory and generate .htaccess file in it.
	 *
	 * @return bool True on successful create, false on failure.
	 */
	public function make_tmp_dir() {
		$dir = trailingslashit( $this->tmp_dir );
		$dir = wp_normalize_path( $dir );

		if ( ! wp_mkdir_p( $dir ) ) {
			return false;
		}

		$htaccess_file = wp_normalize_path( path_join( $dir, '.htaccess' ) );

		if ( file_exists( $htaccess_file ) ) {
			list( $first_line_comment ) = (array) file(
				$htaccess_file,
				FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
			);

			if ( '# Apache 2.4+' === $first_line_comment ) {
				return true;
			}
		}

		if ( $handle = @fopen( $htaccess_file, 'w' ) ) {
			fwrite( $handle, "# Apache 2.4+\n" );
			fwrite( $handle, "<IfModule authz_core_module>\n" );
			fwrite( $handle, "    Require all denied\n" );
			fwrite( $handle, '    <FilesMatch "^\w+\.(jpe?g|gif|png)$">' . "\n" );
			fwrite( $handle, "        Require all granted\n" );
			fwrite( $handle, "    </FilesMatch>\n" );
			fwrite( $handle, "</IfModule>\n" );
			fwrite( $handle, "\n" );
			fwrite( $handle, "# Apache 2.2\n" );
			fwrite( $handle, "<IfModule !authz_core_module>\n" );
			fwrite( $handle, "    Order deny,allow\n" );
			fwrite( $handle, "    Deny from all\n" );
			fwrite( $handle, '    <FilesMatch "^\w+\.(jpe?g|gif|png)$">' . "\n" );
			fwrite( $handle, "        Allow from all\n" );
			fwrite( $handle, "    </FilesMatch>\n" );
			fwrite( $handle, "</IfModule>\n" );

			fclose( $handle );
		}

		return true;
	}

}
