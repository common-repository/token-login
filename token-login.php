<?php
/*
Plugin Name: Token Login
Plugin URI:  https://developer.wordpress.org/plugins/token-login/
Description: Auto login via a secure tokenized URL. Role wise restriction.
Version:     1.0.3
Author:      Priyabrata Sarkar
Author URI:  http://yespbs.com/
License:     GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: tl
Domain Path: /languages
Keywords: auto login, secure login, token url, role login, ip lockout
*/

if( ! class_exists('TokenLogin') )
{
	/**
	 * Base Class
	 */ 
	class TokenLogin
	{

		/**
		 * @todo
		 */ 
		public static function __callStatic($name, $arguments){
			// set
			$class = new TokenLogin();
			
			// execute
			return call_user_func_array( [$class, $name], $arguments );
		}

		/**
		 * @todo
		 */ 
		public function __call($name, $arguments)
	    {
	        // execute
			return call_user_func_array( [$class, $name], $arguments );
	    }

		/**
		 * @todo
		 */ 
		public static function init(){
			// load text domain
			self::load_plugin_textdomain();

			// plugin	
	  		$plugin_name = trailingslashit(str_replace('\\', '/', __FILE__));// token-login/token-login.php/
			
			// register activate
			register_activation_hook($plugin_name, array('TokenLogin', 'activate'));
			
			// register deactivate
			register_deactivation_hook($plugin_name, array('TokenLogin', 'deactivate'));
			
			// activate
			self::activate();
		}

		/**
		 * @todo
		 */ 
		public static function activate(){
			// version
			if( ! defined('TL_VERSION') ){
				define('TL_VERSION', '1.0.2');
			}

			add_action( 'show_user_profile'  , array('TokenLogin', 'showEditUserProfile'), 10, 1 );
			add_action( 'edit_user_profile'  , array('TokenLogin', 'showEditUserProfile'), 10, 1 );
			add_action( 'send_headers'       , array('TokenLogin', 'sendHeaders'), 10, 1 );
			add_action( 'admin_menu'         , array('TokenLogin', 'adminMenu'), 10, 1);
			add_filter( 'wp_mail'            , array('TokenLogin', 'addTokenUrlNewUserCreate'), 10, 1 );
			add_action( 'init'               , array('TokenLogin', 'addAssets'), 10, 1 );
			add_action( 'wp_login'           , array('TokenLogin', 'addLoginStamp'), 10, 2 );
			add_action( 'wp_logout'          , array('TokenLogin', 'addLogoutStamp'), 10, 1 ); 
			add_filter( 'wp_login_errors'    , array('TokenLogin', 'addLoginMessages'), 10, 2 );
			add_action( 'wp_ajax_tl_admin_ajax_action', array('TokenLogin', 'processAjax'), 10, 1 );
			add_filter( 'login_redirect'     , array('TokenLogin', 'loginRedirect'), 10, 3 );

			$tl_version = get_option('tl_version');
			if( ! $tl_version || version_compare($tl_version, TL_VERSION, '<') ){
			// upate	
				update_option('tl_version', TL_VERSION, true);

				// rename tokens for <1.0.0
				if( version_compare(TL_VERSION, '1.0.0', '<') ){
					self::renameUserToken();
				}
			}
		}

		/**
		 * @todo
		 */
		public static function addLoginMessages($errors, $redirect_to){
			// tokenreset
			if( isset($_GET['tokenreset']) && true == $_GET['tokenreset'] ){
				$errors->add('tokenreset', __('Your Token has been updated for new IP. Please re-authenticate 
					using new secure url sent to your registered E-mail', 'tl'), 'message');
			}

			// tokeninvalid
			if( isset($_GET['tokeninvalid']) && true == $_GET['tokeninvalid'] ){
				$errors->add('tokeninvalid', __('Your Token could not be authenticated.', 'tl'), 'message');
			}

			return $errors;
		}

		/**
		 * @todo
		 */ 
		public static function renameUserToken(){
			global $wpdb;

			$wpdb->update($wpdb->usermeta, array('meta_key'=>'tl_login_token'), array('meta_key'=>'login_token'));
		}

		/**
		 * @todo
		 */ 
		public static function addLoginStamp($user_login, $user){
			
			$now = current_time('mysql');
			$ip  = self::getIpAddress();

			update_user_option($user->ID, 'tl_last_login_at', $now, true);
			update_user_option($user->ID, 'tl_last_login_ip', $ip, true);
		}

		/**
		 * @todo
		 */ 
		public static function addLogoutStamp(){
			$user_id = get_current_user_id();

			$now = current_time('mysql');

			update_user_option($user_id, 'tl_last_logout_at', $now, true);
		}

		/**
		 * @todo
		 */ 
		public static function load_plugin_textdomain($domain = 'tl'){
			
			if( ! load_plugin_textdomain( $domain ) ){
				
				return load_plugin_textdomain( $domain, false, basename( dirname( __FILE__ ) ) . '/languages' ); 
			}		
		}	

		/**
		 * @todo
		 */ 
		public static function deactivate(){

		}

		/**
		 * @todo
		 */ 
		public static function addAssets(){
			add_action('admin_enqueue_scripts' , array('TokenLogin', 'adminEnqueueScripts'), 10, 1); 
		}

		/**
		 * @todo
		 */ 
		public static function adminEnqueueScripts(){
			// screen
			$screen_id = get_current_screen()->id;	

			switch ($screen_id) {
				case 'users':// list
				// case 'user':// add
				case 'user-edit':// edit
				case 'user-edit-network':// network edit	
				case 'settings_page_tl-settings':// settings	
					wp_enqueue_style('tl-toastr-css', 'https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.css');
					wp_enqueue_script('tl-toastr-js', 'https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.js');
				break;	
			}
		}
			
		/**
		 * @todo
		 */ 
		public static function adminMenu(){
			add_options_page( __('Token Login Settings','tl'), __('Token Login','tl'), 'administrator', 'tl-settings', array('TokenLogin', 'manageSettings') );
		}

		/**
		 * @todo
		 */ 
		public static function getIncludeRoles(){

			$include_roles = get_option('tl_include_roles');

			if( ! $include_roles ){
				$include_roles = 'editor,author,contributor,subscriber';
			}

			return explode(',', $include_roles);
		}

		/**
		 * @todo
		 */ 
		public static function manageSettings(){
			$include_roles = self::getIncludeRoles();

			$roles = wp_roles()->role_names;?>
			<div class="wrap">
				<h1><?php _e('Token Login Settings', 'tl');?></h1>
				<div>
					<form name="frmtlset" id="frmtlset" method="post" action="">
						<h4><?php _e('Select Roles to create and allow Token Login', 'tl')?></h4>
						<ul>
						<?php foreach( $roles as $role_key => $role_name ):?>
							<?php $role_checked = in_array($role_key, $include_roles) ? 'checked' : '';?>
							<li>
								<input type="checkbox" name="include_roles[]" 
								value="<?php echo $role_key?>" <?php echo $role_checked?>>
								<?php echo $role_name?>
							</li>
						<?php endforeach;?>	
						</ul>

						<h4><?php _e('E-mail Templates', 'tl')?></h4>
						<p>
							<?php $template = self::getEmailTemplate('new_token_email_template');?>
							<label><?php _e('New Token E-mail', 'tl')?></label><br><br>
							<?php _e('Subject', 'tl')?><br>
							<input type="text" name="new_token_email_template[subject]" size="50" 
							value="<?php echo $template['subject']?>"><br>
							<?php _e('Body', 'tl')?><br>
							<textarea name="new_token_email_template[body]" cols="50" rows="5"><?php echo $template['body']?></textarea>
						</p>
						<p>
							<?php $template = self::getEmailTemplate('reset_token_email_template');?>
							<label><?php _e('Reset Token E-mail', 'tl')?></label><br><br>
							<?php _e('Subject', 'tl')?><br>
							<input type="text" name="reset_token_email_template[subject]" size="50" 
							value="<?php echo $template['subject']?>"><br>
							<?php _e('Body', 'tl')?><br>
							<textarea name="reset_token_email_template[body]" cols="50" rows="5"><?php echo $template['body']?></textarea>
						</p>
						<p>
							<?php $template = self::getEmailTemplate('register_new_token_email_template');?>
							<label><?php _e('New Token E-mail (Register)', 'tl')?></label><br><br>
							<?php _e('Body', 'tl')?><br>
							<textarea name="register_new_token_email_template[body]" cols="50" rows="5"><?php echo $template['body']?></textarea>
						</p>

						<h4><?php _e('Login Redirect', 'tl')?></h4>
						<p>
							<label><?php _e('Redirect Url', 'tl')?></label><br><br>
							<input type="text" name="login_redirect_url" size="50" 
							value="<?php echo get_option('tl_login_redirect_url')?>" 
							placeholder="<?php _e('Default to profile if empty', 'tl')?>">
						</p>

						<h4><?php _e('Additional Options', 'tl')?></h4>
						<ul>
							<?php $add_checked = ('Y' == get_option('tl_add_to_new_email')) ? 'checked' : '';?>
							<li>
								<input type="checkbox" name="add_to_new_email" value="Y" <?php echo $add_checked?>>
								<?php _e('Add Token Login Url to New User E-mail', 'tl')?>
							</li>
						</ul>

						<input type="button" class="button button-primary" name="btnSubmit" onclick="tl_save_settings()" 
						value="Update">
						<input type="hidden" name="action" value="tl_admin_ajax_action">
						<input type="hidden" name="method" value="save_settings">
					</form>
				</div>
			</div>	
			<script type="text/javascript">
				tl_save_settings=function(user_id){
					var data = jQuery("#frmtlset").serialize();

					jQuery.post(ajaxurl, data, function(response) {
						
						if( response.status == 'success'){
							toastr.success(response.message, 'Update Settings', {timeOut: 2000});
						}else{
							toastr.error(response.message, 'Update Settings', {timeOut: 2000});
						}

					}, 'json');
				}
			</script>	
			<?php
		}

		/**
		 * @todo
		 */ 
		public static function userIncluded( $user ){
			$include_roles = self::getIncludeRoles();

			$included = false;
			foreach( $user->roles as $role ){
				if( in_array( $role, $include_roles ) ){
					$included = true; break;
				}
			}

			return $included;
		}

		/**
		 * @todo
		 */
		public static function showEditUserProfile($user){
			// check included
			if( ! self::userIncluded($user) ){
				return ;
			}

			// get token
			$login_token = self::getToken($user->ID);
			
			// get token url
			$token_url = self::getTokenUrl($user->ID, $login_token);
			?>
			<table class="form-table">
				<tr>
					<th>
						<label for="token_url"><?php _e('Token URL', 'tl'); ?></label>
					</th>
					<td>
						<div id="token_url_display"><?php echo $token_url?></div><br>

						<a href="javascript:tl_regenerate_token('<?php echo $user->ID?>')"><?php _e('Re-Generate', 'tl'); ?></a> | 
						<a href="javascript:tl_email_token('<?php echo $user->ID?>')"><?php _e('E-mail', 'tl'); ?></a>

					</td>
				</tr>

			</table>
			<script type="text/javascript">
				tl_regenerate_token=function(user_id){
					var data = {
						'action': 'tl_admin_ajax_action',
						'method': 'regenerate_token',
						'user_id': user_id
					};

					jQuery.post(ajaxurl, data, function(response) {
						
						if( response.status == 'success' ){
							jQuery('#token_url_display').html(response.token_url);

							toastr.success(response.message, 'Re-Generate Token', {timeOut: 2000});
						}else{
							toastr.error(response.message, 'Re-Generate Token', {timeOut: 2000});
						}
						
					}, 'json');
				}

				tl_email_token=function(user_id){
					var data = {
						'action': 'tl_admin_ajax_action',
						'method': 'email_token',
						'user_id': user_id
					};

					jQuery.post(ajaxurl, data, function(response) {
						
						if( response.status == 'success'){
							toastr.success(response.message, 'E-mail Token Link', {timeOut: 2000});
						}else{
							toastr.error(response.message, 'E-mail Token Link', {timeOut: 2000});
						}

					}, 'json');
				}
			</script>
			<?php
		}  

		/**
		 * @todo
		 */ 
		public static function addTokenUrlNewUserCreate($mail){

			if ( ! isset( $mail['message'] ) ) {
				return $mail;
			}

			// if set
			if('Y' == get_option('tl_add_to_new_email')){

				// if not admin
				if( $mail['to'] != get_option( 'admin_email' ) ){
					$email = $mail['to'];
					if ( preg_match( '/(.*)<(.+)>/', $email, $matches ) ) {
						if ( count( $matches ) == 3 ) {
							$recipient_name = $matches[1];
							$email = $matches[2];
						}
					}

					// get user by email
					$user = get_user_by('email', $email);

					if( self::userIncluded($user) ){
						
						if( $login_token = self::getToken($user->ID) ){

							// url
							$token_url = self::getTokenUrl($user->ID, $login_token);

							// Set Content-Type if we don't have a content-type from the input headers.
							if ( ! isset( $content_type ) ) {
								$content_type = 'text/plain';
							}

							/** This filter is documented in wp-includes/pluggable.php */
							$content_type = apply_filters( 'wp_mail_content_type', $content_type );

							$template = self::getEmailTemplate('register_new_token_email_template', $content_type);

							/*$message = __('To login without password, visit the following address:') . "\r\n\r\n";

							if ( 'text/html' === $content_type ) {
								$message .= '<p><a href="'.$token_url.'">secure login</a></p>';
							}else{
								$message .= "\r\n\r\n";
								$message .= '<'.$token_url.'>'. "\r\n\r\n";
							}*/

							$mail['message'] .= self::parseTml($template['body'], array('token_url'=>$token_url));
						}
					}	
				}
			}	

			return $mail;
		}

		/**
		 * @todo
		 */ 
		public static function sendMail($email, $subject, $body, $headers=''){

			add_filter('wp_mail_content_type', array('TokenLogin', 'mailContentType'), 10);	

			$r = wp_mail($email, $subject, $body, $headers);

			remove_filter('wp_mail_content_type', array('TokenLogin', 'mailContentType'));

			// log
			/*if( ! $r ){
				self::Debug($subject . "\n\r" . $body, __FUNCTION__, true);
			}*/

			return $r;	
		}

		/**
		 * @todo
		 */ 
		public static function mailContentType(){
			return 'text/html';
		}

		/**
		 * @todo
		 */ 
		public static function parseTml($tml, $data){
			foreach($data as $key => $val){
				$tml = str_replace('['.$key.']', $val, $tml);
			}

			return $tml;
		}

		/**
		 * @todo
		 */ 
		public static function getToken($user_id, $regenerate=false){
			// regenerate
			if( $regenerate ){
				// generate
				$login_token = self::generateToken();

				// update
				$result = update_user_option($user_id, 'tl_login_token', $login_token, true);
				
			}else{
				// new
				if( ! $login_token = get_user_option('tl_login_token', $user_id) ){
					// old
					if( ! $login_token = get_user_option('login_token', $user_id) ){
						// generate
						$login_token = self::generateToken();

						// update
						update_user_option($user_id, 'tl_login_token', $login_token, true);
					}	
				}
			}	

			return $login_token;
		}

		/**
		 * @todo
		 */ 
		public static function getTokenUrl($user_id, $login_token=null){

			if( ! $login_token ){
				$login_token = self::getToken($user_id);
			}
			
			return add_query_arg(array('__token__' => $login_token), site_url());	
		}

		/**
		 * @todo
		 */ 
		public static function generateToken(){
			return md5(uniqid(mt_rand()));
		}

		/**
		 * @todo
		 */ 
		public static function userIpKnown($user){

			$last_login_ip = get_user_option('tl_last_login_ip', $user->ID);

			if( $last_login_ip ){

				$ip = self::getIpAddress();

				// self::Debug($last_login_ip.' <==> '.$ip, __FUNCTION__, true);

				if( $ip !== $last_login_ip ){

					return false;
				}
			}

			return true;
		}

		/**
		 * @todo
		 */ 
		public static function sendTokenResetMail($user){

			$ip = self::getIpAddress();

			$login_token = self::getToken($user->ID, true);

			$token_url = add_query_arg(array('__ip__'=>md5($ip)), self::getTokenUrl($user->ID, $login_token));

			$tml_data = array('sitename'=>get_bloginfo('sitename'), 'token_url'=>$token_url);

			$template = self::getEmailTemplate('reset_token_email_template');

			$subject = self::parseTml($template['subject'], $tml_data);

			$body = self::parseTml($template['body'], $tml_data);

			return $sent = self::sendMail($user->user_email, $subject, $body);
		}

		/**
		 * @todo
		 */ 
		public static function verifyUserIp($user){
			// ip in request
			if( isset($_GET['__ip__']) && ! empty($_GET['__ip__']) ){
				// get 
				$ip_hash = $_GET['__ip__'];

				$ip = self::getIpAddress();

				if( $ip_hash == md5($ip) ){

					update_user_option($user->ID, 'tl_last_login_ip', $ip, true);

					// send reset mail
					self::sendTokenMail($user);

					return true;
				}
			}
			
			return false;
		}

		/**
		 * @todo
		 */ 
		public static function sendHeaders(){
			
			// token
			if( isset($_GET['__token__']) && ! empty($_GET['__token__']) ){
				
				// get 
				$token = $_GET['__token__'];

				// not alredy logged in
				if( ! is_user_logged_in() ){
					
					// sanitize
					$token_sanitized = sanitize_meta( 'tl_login_token', $token, 'user' );// safe?

					// find args
					$args = array('meta_key'=>'tl_login_token','meta_value'=>$token_sanitized,'meta_compare'=>'=');

					// find
					$users = get_users( $args );        

					// find userid
					if( count($users) == 1 ){
						// user
						$user = array_shift($users);

						// role included
						if( self::userIncluded($user) ){
							// check ip known
							if( ! self::userIpKnown($user) ){
								// if not know, check ip submitted for authenticate
								if( ! self::verifyUserIp($user) ){
									// send reset mail
									self::sendTokenResetMail($user);

									// redirect with error
									$redirect_to = 'wp-login.php?tokenreset=true';
									wp_safe_redirect( $redirect_to ); exit();
								}	
							}

							// set auth cookie
							wp_set_auth_cookie($user->ID, true);

							// run default action
							do_action( 'wp_login', $user->user_login, $user );

							// run token login action
							do_action( 'wp_token_login', $user );

							// default 
							$redirect_to = admin_url();

							// apply default filter
							$redirect_to = apply_filters( 'login_redirect', $redirect_to, '', $user );

							// copied from wp-login.php
							if ( ( empty( $redirect_to ) || $redirect_to == 'wp-admin/' || $redirect_to == admin_url() ) ) {
								// If the user doesn't belong to a blog, send them to user admin. If the user can't edit posts, send them to their profile.
								if ( is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin( $user->ID ) )
									$redirect_to = user_admin_url();
								elseif ( is_multisite() && !$user->has_cap('read') )
									$redirect_to = get_dashboard_url( $user->ID );
								elseif ( !$user->has_cap('edit_posts') )
									$redirect_to = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();

								wp_redirect( $redirect_to );
								exit();
							}
							wp_safe_redirect( $redirect_to ); exit();
						}
					}	
				}

				// default
				//$redirect_to = home_url();
				$redirect_to = 'wp-login.php?tokeninvalid=true';
				wp_safe_redirect( $redirect_to ); exit();
			}
		}

		/**
		 * @todo
		 */ 
		public static function sendTokenMail($user){

			$tml_data = array('sitename'=>get_bloginfo('sitename'), 'token_url'=>self::getTokenUrl($user->ID));

			$template = self::getEmailTemplate('new_token_email_template');

			$subject = self::parseTml($template['subject'], $tml_data);

			$body = self::parseTml($template['body'], $tml_data);

			return self::sendMail($user->user_email, $subject, $body);
		}

		/**
		 * @todo
		 */ 
		public static function processAjax(){

			switch ($_POST['method']) {
				case 'regenerate_token':
					
					$user_id = $_POST['user_id'];
					
					/*$login_token = self::generateToken();

					update_user_option($user_id, 'login_token', $login_token, true);*/

					$login_token = self::getToken($user_id, true);
					
					$response = array(
						'status'=>'success', 'message'=>__('Successfully regenerated token!', 'tl'), 
						'token_url'=>self::getTokenUrl($user_id, $login_token)
					);

					echo json_encode($response);

					break;
				case 'email_token':
					
					$user_id = $_POST['user_id'];

					$user = get_userdata($user_id);

					$sent = self::sendTokenMail($user);

					$response = array(
						'status'=>'success', 'message'=>__('Successfully emailed token!', 'tl'), 'sent'=>$sent
					);

					echo json_encode($response);
					break;

				case 'save_settings':

					$include_roles = $_POST['include_roles'];
					$add_to_new_email = isset($_POST['add_to_new_email']) ? 'Y' : 'N';

					$new_token_email_template = $_POST['new_token_email_template'];
					$reset_token_email_template = $_POST['reset_token_email_template'];
					$register_new_token_email_template = $_POST['register_new_token_email_template'];
					$login_redirect_url = isset($_POST['login_redirect_url']) ? $_POST['login_redirect_url'] : '';

					update_option( 'tl_include_roles', implode(',', $include_roles), true);
					update_option( 'tl_add_to_new_email', $add_to_new_email, true);

					update_option( 'tl_new_token_email_template', $new_token_email_template, true);
					update_option( 'tl_reset_token_email_template', $reset_token_email_template, true);
					update_option( 'tl_register_new_token_email_template', $register_new_token_email_template, true);
					
					if( ! empty($login_redirect_url) ){
						update_option( 'tl_login_redirect_url', $login_redirect_url, true);
					}else{
						delete_option( 'tl_login_redirect_url' );
					}	

					$response = array(
						'status'=>'success', 'message'=>__('Successfully updated settings!', 'tl')
					);

					echo json_encode($response);
				break;	
				default:
					$response = array(
						'status'=>'error', 'message'=>__('No such method!', 'tl')
					);
					echo json_encode($response);
					break;
			}

			wp_die(); // this is required to terminate immediately and return a proper response
		}

		/**
		 * Debug
		 */
		public static function Debug($data, $context, $file=true){
			if( is_array($data) || is_object($data) ){
				$data = sprintf('<pre>%s</pre>', print_r($data, true));
			}

			if( $file ){

				if( ! defined('TL_LOG_DIR') ){
					define('TL_LOG_DIR', __DIR__.'/logs/');
				}	

				if( ! is_dir(TL_LOG_DIR) ){
					wp_mkdir_p(TL_LOG_DIR);
				}

				return file_put_contents(TL_LOG_DIR . $context. '-' .time().'.txt', $data . "\n\n", FILE_APPEND);
			}

			return $data;
		}  

		/**
		 * @todo
		 */ 
		public static function getIpAddress(){
			// possible
			$possible = array('HTTP_CLIENT_IP','HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR');
			
			// loop
			foreach($possible as $name){
				// check
				if (isset($_SERVER[$name]) && !empty($_SERVER[$name])) {
					$ip_address = $_SERVER[$name]; break;
				}
			}

			// return
			return $ip_address;
		}

		/**
		 * @todo
		 */ 
		public static function getEmailTemplate($name, $content_type='text/html'){
			// saved
			if( ! $template = get_option('tl_'.$name) ){
				
				// default
				switch( $name ){
					case 'new_token_email_template':
						$template['subject'] = 'Your Secure Login Link for [sitename]';
						$template['body'] = '<p>You can now quickly access your account at [sitename] '.
				                            'with this <a href="[token_url]">secure link.</a></p>';
					break;
					case 'reset_token_email_template':
						$template['subject'] = 'Your Secure Login Link for [sitename]';
						$template['body'] = '<p>Your secure login link at [sitename] '.
				                            'has been updated for new IP address, please verify '.
				                            '<a href="[token_url]">your login IP.</a></p>';
					break;
					case 'register_new_token_email_template':
						if( 'text/html' == $content_type ){
							$template['body'] = 'To login without password, visit the following address:'.
						                        '<p><a href="[token_url]">secure login</a></p>';
						}else{             
						    $template['body'] = '<[token_url]>';
						}		

					break;
				}
			}	

			return stripslashes_deep($template);
		}

		/**
		 * @todo
		 */ 
		public static function loginRedirect($redirect_to, $what='', $user){

			if( $login_redirect_url = get_option('tl_login_redirect_url') ){
				return $login_redirect_url;
			}

			return $redirect_to;
		}
		
	}
}

/**
 * Create
 */ 
add_action('plugins_loaded',  array('TokenLogin', 'init'));