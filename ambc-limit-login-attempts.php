<?php
/**
 * Plugin Name: AMBC Limit Login Attempts
 * Plugin URI: https://www.appsmadebycats.com/ambc_limit_login_plugin
 * Description: A very lightweight plugin that limits login attempts to prevent brute force attacks
 * Version: 1.0.0
 * Requires at least: 5.8
 * Tested up to: 6.0
 * Author: eduardjacobs
 * Author URI: https://www.appsmadebycats.com/authors/eduardjacobs
 * License: GPLv2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ambc-limit-login-attempts
 * Domain Path: languages
 *
 *
 */

if ( !defined( 'ABSPATH' ) ) {
  die( '-1' );
}

if ( !class_exists( 'AMBCLimitLoginAttempts' ) ) {
  class AMBCLimitLoginAttempts {
    private $allowed_attempts = 3;
    private $option_name = 'ambc_blocked_ips';
    private $lock_duration = 1200;
    private $error_message = '';

    public function __construct() {
      add_filter('authenticate', array( $this, 'ambc853_check_attempted_login' ) , 30, 3);
    }

    /**
     * Lock login attempts of failed login limit is reached
     */
    public function ambc853_check_attempted_login( $user, $username, $password ) {

      $user_ip = $this->get_the_user_ip();

      /*
       * Check if $user object is a WP_Eror object i.e. if authentication failed
      */
      if ( is_wp_error( $user ) ) {

        //delete_option( $this->option_name );
        //return $user;
        //exit;
        $ambc_blocked_ips = get_option( $this->option_name );

        // Delete the option if one day passed since last anyone logging in
        // so not to litter the db
        if ( $ambc_blocked_ips ) {
          if ( time() >= ( $ambc_blocked_ips['today_time'] + 86400 ) ) {
            delete_option( $this->option_name );
            $ambc_blocked_ips = false;
            echo ' || one day passed so option was deleted  || ';
          }
        }

        if ( $ambc_blocked_ips ) {
          if ( array_key_exists( $user_ip, $ambc_blocked_ips ) ) {

            // We're incrementing [ $user_ip ][ 'attempts_made' ] by 1 because first time it was set to 1
            // when setting the option and now it is coming back second time so we set it to 2
            $attempts_left = $this->allowed_attempts - ( $ambc_blocked_ips[$user_ip]['attempts_made'] + 1 );

            if ( $attempts_left > 0 ) {
              $ambc_blocked_ips[$user_ip]['attempts_made'] = $ambc_blocked_ips[$user_ip]['attempts_made'] + 1;

              // Update the option with new attempts_made value
              $user = $this->ambc_update_option( $user, $ambc_blocked_ips );

              // Add AMBC error message to the E=$user object
              $user = $this->add_error_attempts_left( $user, $attempts_left );
              return $user;
              exit;
            } else {

              // If no attempts left check if this user is getting blocked first time
              // so we can set the initial time against which lock duration is calculated
              if ( $ambc_blocked_ips[$user_ip]['is_first_run'] ) {
                $ambc_blocked_ips[$user_ip]['is_first_run'] = false;
                $ambc_blocked_ips[$user_ip]['lock_start_time'] = time();

                if ( update_option( $this->option_name, $ambc_blocked_ips ) ) {
                  $this->disable_login_page( $this->lock_duration );
                } else {
                  $user->errors['ambc_limit_login_error'] = ['<strong>Error:</strong> Unexpected AMBC Limit Login error'];
                  return $user;
                }
              } else {
                $time_left = ( $ambc_blocked_ips[$user_ip]['lock_start_time'] + $this->lock_duration ) - time();

                // If lock duration time expired we remove the user from the option table
                // basically resetting the user
                if ( $time_left <= 0 ) {
                  unset( $ambc_blocked_ips[$user_ip] );

                  $user = $this->ambc_update_option( $user, $ambc_blocked_ips );
                  return $user;
                  exit;
                } else {
                  $this->disable_login_page( $time_left );
                }
              }
            }
          } else {

            // If username and password empty just return $user
            if ( $username === '' && $password === '' ) {
              return $user;
              exit;
            }

            /* 
             * If for some reason the option exists but no user entry then update with new time
             * and create an entry for user and update the option
             */
            $ambc_blocked_ips = $this->create_array_for_option( $user_ip );
            $user = $this->ambc_update_option( $user, $ambc_blocked_ips );
            $user = $this->add_error_attempts_left( $user, ( $this->allowed_attempts - 1 ) );
            return $user;
          }

        } else {

          /* 
           * If the option doesnt exist because the plugin is kicking in the first time
           * create an option in the db with user ip and other data
           */

          // If username and password empty just return $user
          if ( $username === '' && $password === '' ) {
            return $user;
            exit;
          }

          // Otherwise create an array to be stored in the option
          $ambc_blocked_ips = $this->create_array_for_option( $user_ip );
          $user = $this->ambc_update_option( $user, $ambc_blocked_ips );
          $user = $this->add_error_attempts_left( $user, ( $this->allowed_attempts - 1 ) );
          return $user;
          exit;
        }
      }
      return $user;
    }

    /**
     * Return a pre-populated array to be stored in the options
     *
     * @param string $user_ip User's IP address
     * 
     * @return array Return array
     */
    private function create_array_for_option( $user_ip ){
      return ['today_time' => time() , $user_ip => ['attempts_made' => 1, 'lock_start_time' => 0, 'is_first_run' => true]];
    }

    /**
     * Add AMBC error to the $user object
     *
     * @param object  $user User object which is WP_Error object in this case
     * @param int     $attempts_made How many login attempts made   
     * 
     * @return object Return modified $user object
     */
    private function add_error_attempts_left( $user, $attempts_left ){
      $user->errors['ambc_limit_login_error'] = ['<strong>Notice:</strong> You have ' . $attempts_left . ' attempts left'];
      return $user;
    }

    /**
     * Update the option in the database
     *
     * @param object  $user User object which is WP_Error object in this case
     * @param array   $ambc_blocked_ips An array with info such as user ip, attempts made, what time lock started
     * 
     * @return object Return $user if update was success else return it with an added error message
     */    
    private function ambc_update_option( $user, $ambc_blocked_ips ){
      if ( update_option( $this->option_name, $ambc_blocked_ips ) ){
        return $user;
      }
      else {
        $user->errors['ambc_limit_login_error'] = ['<strong>Error:</strong> AMBC Limit Login Unexpected Error'];
        return $user;
      }
    }

    /**
     * Retrieve user's IP address
     * 
     * @return string Return user's IP address
     */        
    private function get_the_user_ip(){
      if ( !empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
        $user_ip = $_SERVER['HTTP_CLIENT_IP'];
      } elseif ( !empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        $user_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
      } else {
        $user_ip = $_SERVER['REMOTE_ADDR'];
      }
      if ( filter_var( $user_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
        return $user_ip;
      } else {
        return 'no_ip';
      }
    }

    /**
     * Disables the login page
     * 
     * @param int $time_to_unblock How much time left until user unblocked
     */          
    private function disable_login_page( $time_until_unblock ) {
      $message = '';

      if ( $time_until_unblock <= 60 ) {
        $message = '<div style="text-align:center;">You have no attempts left. 
        Try again in ' . $time_until_unblock . ' seconds</div>';
      } else {
        $message = '<div style="text-align:center;">You have no attempts left. 
        Try again in ' . round($time_until_unblock / 60) . ' minutes</div>';
      }

      login_header( 'Log In' );
      echo $message;
      do_action( 'login_footer' );
      echo "</body></html>";
      exit;
    }
  }
}
// Enable the plugin
new AMBCLimitLoginAttempts();