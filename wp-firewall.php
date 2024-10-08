<?php
/*
Plugin Name: SLW Firewall
Plugin URI: http://alicomez.com/
Description: WordPress siteler için kapsamlı güvenlik ve koruma çözümü.
Author: Slaweally
Version: 1.0.0
Author URI: http://alicomez.com/
*/

// Doğrudan erişimi engelle
if (!defined('ABSPATH')) {
    exit; // Bu dosyaya doğrudan erişim yok.
}

// Özel fonksiyonun varlığını kontrol et
if (!function_exists('array_diff_key')) {
    if ((@include_once 'PHP/Compat/Function/array_diff_key.php')) {}
    else {
        function php_compat_array_diff_key() {
            $args = func_get_args();
            if (count($args) < 2) {
                user_error('Wrong parameter count for array_diff_key()', E_USER_WARNING);
                return;
            }
            $array_count = count($args);
            for ($i = 0; $i !== $array_count; $i++) {
                if (!is_array($args[$i])) {
                    user_error('array_diff_key() Argument #' . ($i + 1) . ' is not an array', E_USER_WARNING);
                    return;
                }
            }
            $result = $args[0];
            foreach ($args[0] as $key => $value) {
                for ($i = 1; $i !== $array_count; $i++) {
                    if (array_key_exists($key, $args[$i])) {
                        unset($result[$key]);
                        break;
                    }
                }
            }
            return $result; 
        }		
        function array_diff_key() {
            $args = func_get_args();
            return call_user_func_array('php_compat_array_diff_key', $args);
        }
    }
}

// Yalnızca bu eklenti sayfasından çalışmasına izin ver
if (preg_match("#^wordpress-firewall.php#", basename($_SERVER['PHP_SELF']))) exit();

// Eklenti ayarlarını tanımla
add_option('WP_firewall_redirect_page', 'homepage');
add_option('WP_firewall_exclude_directory', 'allow');
add_option('WP_firewall_exclude_queries', 'allow');
add_option('WP_firewall_exclude_terms', 'allow');
add_option('WP_firewall_exclude_spaces', 'allow');
add_option('WP_firewall_exclude_file', 'allow');
add_option('WP_firewall_exclude_http', 'disallow');
add_option('WP_firewall_email_enable', 'enable');
add_option('WP_firewall_email_address', get_option('admin_email'));
add_option('WP_firewall_whitelisted_ip', '');
add_option('WP_firewall_whitelisted_page', '');
add_option('WP_firewall_whitelisted_variable', '');
add_option('WP_firewall_plugin_url', get_option('siteurl') . '/wp-admin/options-general.php?page=' . basename(__FILE__));
add_option('default_WP_firewall_whitelisted_page', serialize(array(
    array('.*/wp-comments-post\.php', array('url', 'comment')),
    array('.*/wp-admin/.*', array('_wp_original_http_referer', '_wp_http_referer')),
    array('.*wp-login.php', array('redirect_to')),
    array('.*', array('comment_author_url_.*', '__utmz')),
    '.*/wp-admin/options-general\.php',
    '.*/wp-admin/post-new\.php',
    '.*/wp-admin/page-new\.php',
    '.*/wp-admin/link-add\.php',
    '.*/wp-admin/post\.php',
    '.*/wp-admin/page\.php',
    '.*/wp-admin/admin-ajax.php'
)));
add_option('WP_firewall_previous_attack_var', '');
add_option('WP_firewall_previous_attack_ip', '');
add_option('WP_firewall_email_limit', 'off');

// Eklentinin ayarları sayfasını ekle
add_action('admin_menu', 'WP_firewall_admin_menu');
function WP_firewall_admin_menu() {
    add_submenu_page('options-general.php', 'SLW Firewall', 'SLW Firewall', 'manage_options', 'slw-firewall', 'WP_firewall_submenu');
}

// Eklenti ayar sayfası
function WP_firewall_submenu() {
    WP_firewall_check_exclusions(); // Eklenti kontrollerini başlat
    ?>
    <div class="wrap">
        <h1>SLW Firewall Ayarları</h1>
        <form method="post" action="">
            <h2>Güvenlik Filtreleri</h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="block_directory">Dizin geçişlerini engelle</label></th>
                    <td>
                        <input type="checkbox" id="block_directory" name="block_directory" value="allow" <?php checked(get_option('WP_firewall_exclude_directory'), 'allow'); ?> />
                        <p class="description">Dizin geçişine izin verilmeyecek.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="block_queries">SQL sorgularını engelle</label></th>
                    <td>
                        <input type="checkbox" id="block_queries" name="block_queries" value="allow" <?php checked(get_option('WP_firewall_exclude_queries'), 'allow'); ?> />
                        <p class="description">SQL enjeksiyonlarına karşı koruma sağlar.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="block_terms">WP özel terimleri engelle</label></th>
                    <td>
                        <input type="checkbox" id="block_terms" name="block_terms" value="allow" <?php checked(get_option('WP_firewall_exclude_terms'), 'allow'); ?> />
                        <p class="description">WP özel terimleri bloklar (örneğin, wp_login).</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="block_spaces">Boşlukları engelle</label></th>
                    <td>
                        <input type="checkbox" id="block_spaces" name="block_spaces" value="allow" <?php checked(get_option('WP_firewall_exclude_spaces'), 'allow'); ?> />
                        <p class="description">Boşluk kullanımını kontrol eder.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="block_file">Tehlikeli dosya türlerini engelle</label></th>
                    <td>
                        <input type="checkbox" id="block_file" name="block_file" value="allow" <?php checked(get_option('WP_firewall_exclude_file'), 'allow'); ?> />
                        <p class="description">Yüklenen tehlikeli dosya türlerine izin vermez.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="block_http">HTTP engelleme</label></th>
                    <td>
                        <input type="checkbox" id="block_http" name="block_http" value="allow" <?php checked(get_option('WP_firewall_exclude_http'), 'allow'); ?> />
                        <p class="description">Güvenli bağlantılar sağlanacak.</p>
                    </td>
                </tr>
            </table>
            <h3>Saldırı Bildirimleri</h3>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="notify_email">E-posta adresi</label></th>
                    <td>
                        <input type="email" id="notify_email" name="notify_email" value="<?php echo esc_attr(get_option('WP_firewall_email_address')); ?>" class="regular-text" />
                        <p class="description">Saldırı algılandığında bildirim gönderilecek e-posta adresi.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="email_limit">E-posta limit</label></th>
                    <td>
                        <input type="checkbox" id="email_limit" name="email_limit" value="on" <?php checked(get_option('WP_firewall_email_limit'), 'on'); ?> />
                        <p class="description">Benzer saldırı uyarıları için tekrarlanan e-postaları engelle.</p>
                    </td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" name="submit" class="button button-primary" value="Ayarları Kaydet" />
            </p>
        </form>

        <h3>Beyaz Liste Ayarları</h3>
        <form method="post" action="">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="whitelisted_ip">Beyaz liste IP'leri</label></th>
                    <td>
                        <input type="text" id="whitelisted_ip" name="whitelisted_ip" value="<?php echo esc_attr(get_option('WP_firewall_whitelisted_ip')); ?>" class="regular-text" />
                        <p class="description">Virüs tarayıcılarına karşı koruma için beyaz listeye IP ekleyin.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="whitelisted_page">Beyaz liste sayfaları</label></th>
                    <td>
                        <input type="text" id="whitelisted_page" name="whitelisted_page" value="<?php echo esc_attr(get_option('WP_firewall_whitelisted_page')); ?>" class="regular-text" />
                        <p class="description">Beyaz listeye eklenecek sayfaları belirtin.</p>
                    </td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" name="submit_whitelist" class="button button-primary" value="Beyaz Listeyi Güncelle" />
            </p>
        </form>
    </div>
    <?php
}

// Eklentinin ayarlarını kontrol et
function WP_firewall_check_exclusions() {
    $request_string = WP_firewall_check_whitelisted_variable();
    if ($request_string === false) {
        return;
    }

    if (get_option('WP_firewall_exclude_directory') == 'allow') {
        $exclude_terms = array('#etc/passwd#', '#proc/self/environ#', '#\.\./#');
        foreach ($exclude_terms as $preg) {
            foreach ($request_string as $key => $value) {
                if (preg_match($preg, $value)) {
                    if (!WP_firewall_check_ip_whitelist()) {
                        WP_firewall_send_log_message($key, $value, 'directory-traversal-attack', 'Directory Traversal');
                        WP_firewall_send_redirect();
                    }
                }
            }
        }
    }

    if (get_option('WP_firewall_exclude_queries') == 'allow') {
        $exclude_terms = array('#concat\s*\(#i', '#group_concat#i', '#union.*select#i');
        foreach ($exclude_terms as $preg) {
            foreach ($request_string as $key => $value) {
                if (preg_match($preg, $value)) {
                    if (!WP_firewall_check_ip_whitelist()) {
                        WP_firewall_send_log_message($key, $value, 'sql-injection-attack', 'SQL Injection');
                        WP_firewall_send_redirect();
                    }
                }
            }
        }
    }

    if (get_option('WP_firewall_exclude_terms') == 'allow') {
        $exclude_terms = array('#wp_#i', '#user_login#i', '#user_pass#i', '#0x[0-9a-f][0-9a-f]#i', '#/\*\*/#');
        foreach ($exclude_terms as $preg) {
            foreach ($request_string as $key => $value) {
                if (preg_match($preg, $value)) {
                    if (!WP_firewall_check_ip_whitelist()) {
                        WP_firewall_send_log_message($key, $value, 'wp-specific-sql-injection-attack', 'WordPress-Specific SQL Injection');
                        WP_firewall_send_redirect();
                    }
                }
            }
        }
    }

    if (get_option('WP_firewall_exclude_spaces') == 'allow') {
        $exclude_terms = array('#\s{49,}#i', '#\x00#');
        foreach ($exclude_terms as $preg) {
            foreach ($request_string as $key => $value) {
                if (preg_match($preg, $value)) {
                    if (!WP_firewall_check_ip_whitelist()) {
                        WP_firewall_send_log_message($key, $value, 'field-truncation-attack', 'Field Truncation');
                        WP_firewall_send_redirect();
                    }
                }
            }
        }
    }

    if (get_option('WP_firewall_exclude_file') == 'allow') {
        foreach ($_FILES as $file) {
            $file_extensions = array('#\.dll$#i', '#\.rb$#i', '#\.py$#i', '#\.exe$#i', '#\.php[3-6]?$#i', '#\.pl$#i', '#\.perl$#i', '#\.ph[34]$#i', '#\.phl$#i', '#\.phtml$#i', '#\.phtm$#i');
            foreach ($file_extensions as $regex) {
                if (preg_match($regex, $file['name'])) {
                    WP_firewall_send_log_message('$_FILE', $file['name'], 'executable-file-upload-attack', 'Executable File Upload');
                    WP_firewall_send_redirect();
                }
            }
        }
    }

    if (get_option('WP_firewall_exclude_http') == 'allow') {
        $exclude_terms = array('#^http#i', '#\.shtml#i');
        foreach ($exclude_terms as $preg) {
            foreach ($request_string as $key => $value) {
                if (preg_match($preg, $value)) {
                    if (!WP_firewall_check_ip_whitelist()) {
                        WP_firewall_send_log_message($key, $value, 'remote-file-execution-attack', 'Remote File Execution');
                        WP_firewall_send_redirect();
                    }
                }
            }
        }
    }
}

// URL'den beyaz listeyi kontrol et
function WP_firewall_check_whitelisted_variable() {
    preg_match('#([^?]+)?.*$#', $_SERVER['REQUEST_URI'], $url);
    $page_name = $url[1];
    $_a = array();
    $new_arr = WP_firewall_array_flatten($_REQUEST, $_a);

    foreach (unserialize(get_option('default_WP_firewall_whitelisted_page')) as $whitelisted_page) {
        if (!is_array($whitelisted_page)) {
            if (preg_match('#^' . $whitelisted_page . '$#', $page_name)) {
                return false;
            }
        } else {
            if (preg_match('#^' . $whitelisted_page[0] . '$#', $page_name)) {
                foreach ($whitelisted_page[1] as $whitelisted_variable) {
                    foreach (array_keys($new_arr) as $var) {
                        if (preg_match('#^' . $whitelisted_variable . '$#', $var)) {
                            $new_arr = array_diff_key($new_arr, array($var => ''));
                        }
                    }
                }
            }
        }
    }

    $pages = unserialize(get_option('WP_firewall_whitelisted_page'));
    $variables = unserialize(get_option('WP_firewall_whitelisted_variable'));
    $count = 0;

    while ($count < sizeof($pages)) {
        $page_regex = preg_quote($pages[$count], '#');
        $page_regex = str_replace('\*', '.*', $page_regex);
        $var_regex = preg_quote($variables[$count], '#');
        $var_regex = str_replace('\*', '.*', $var_regex);

        if ($variables[$count] != '') {
            if ($pages[$count] == '' || preg_match('#^' . $page_regex . '$#', $page_name)) {
                $temp_arr = $new_arr;
                foreach (array_keys($new_arr) as $var) {
                    if (preg_match('#^' . $var_regex . '$#', $var)) {
                        $new_arr = array_diff_key($new_arr, array($var => ''));
                    }
                }
            }
        } elseif ($pages[$count] != '') {
            if (preg_match('#^' . $page_regex . '$#', $page_name)) {
                return false;
            }
        }
        $count++;
    }
    return $new_arr;
}

// IP adresini al
function GetIP() {
    if (getenv("HTTP_CLIENT_IP")) {
        $ip = getenv("HTTP_CLIENT_IP");
    } elseif (getenv("HTTP_X_FORWARDED_FOR")) {
        $ip = getenv("HTTP_X_FORWARDED_FOR");
        if (strstr($ip, ',')) {
            $tmp = explode(',', $ip);
            $ip = trim($tmp[0]);
        }
    } else {
        $ip = getenv("REMOTE_ADDR");
    }
    return $ip;
}

// Log mesajı gönder
function WP_firewall_send_log_message($bad_variable = '', $bad_value = '', $attack_type = '', $attack_category = '') {
    $bad_variable = htmlentities($bad_variable);
    $bad_value = htmlentities($bad_value);
    $offender_ip = GetIP();
    $limit_check = (get_option('WP_firewall_email_limit') == 'on' && $offender_ip == get_option('WP_firewall_previous_attack_ip') && $bad_variable == get_option('WP_firewall_previous_attack_var'));

    if ($address = get_option('WP_firewall_email_address') && !$limit_check) {
        $suppress_message = (get_option('WP_firewall_email_limit') == 'on') ? 'Benzer saldırılar için Tekrarlanan uyarılar şu anda e-posta yoluyla gönderilir, <a href="' . get_option('WP_firewall_plugin_url') . '&suppress=0">Tıkla</a> ve bastır.' : '';
        $offending_url = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $variable_explain_url = 'http://alicomez.com/slw-firewall.slw' . $attack_type;
        $turn_off_email_url = get_option('WP_firewall_plugin_url') . '&turn_off_email=1';
        $whitelist_variable_url = get_option('WP_firewall_plugin_url') . '&set_whitelist_variable=' . $bad_variable;

        $message = <<<EndMessage
        <h3>SLW Firewall <font color="red">tespit ve bloke et</font> potansiyel bir saldırı olabilir!</h3>
        <table border="0" cellpadding="5">
        <tr>
        <td align="right"><b>Web sayfası:&nbsp;&nbsp;</b></td>
        <td>$offending_url <br />
        <small>Uyarı: &nbsp; URL tehlikeli içeriğe sahip olabilir!</small>
        </td>
        </tr>
        <tr>
        <td align="right"><b>Soruna neden olan IP:&nbsp;&nbsp;</b></td>
        <td>$offender_ip
        <a href="http://whatismyipaddress.com/ip/$offender_ip">[ İp Lokasyonuna bakın ]</a>
        </td>
        </tr>
        <tr>
        <td align="right"><b>Sorun parametresi:&nbsp;&nbsp;</b></td>
        <td><font color="red"><b> $bad_variable = $bad_value </b></font></td>
        </tr>
        </table>
        <br />
        <table>
        <tr>
        <td align="left"> 
        "$attack_category Bu atak olabilir"<br /><br />Bilgi için 
        <a href="$variable_explain_url">Tıkla</a> Bu bir yanlış alarm olabilir. Eğer bu uyarının yanlış olduğunu düşünüyorsanız beyazliste ip'lerine ekleyin, bir sonraki seferde bunu önemsemeyeceğiz.
        <br /><br />
        <a href="$whitelist_variable_url">Tıkla</a> Beyaz listeye ekle
        <br /> 
        <a href="$turn_off_email_url">Tıkla</a> Bu e-postaları kapat.
        </td>
        <tr>
        <td>$suppress_message</td>
        </tr>
        </table>
        <br />
        <div style="float:right; position:relative; top:-80px;">
        <a href="http://alicomez.com/slw-firewall.slw" style="text-decoration:none;" target="_blank">
        <img src="http://alicomez.com/wp-content/uploads/2014/11/logo1.png" border="0" />
        <br />
        <small>Firewall hakkında</small>
        </a>
        <br />
        <small>Geri bildirim Gönder
        <a style="text-decoration:none;" href="http://alicomez.com/slw-firewall.slw" target="_blank">Tıklayın</a>
        </small>
        <br />
        <small>Destek ol
        <a style="text-decoration:none;" href="http://alicomez.com/slw-firewall.slw" target="_blank">this simple disclaimer.</a>
        </small>	
        </div>
        EndMessage;

        $subject = 'WP Firewall Bilgi !! ' . get_option('siteurl');
        $header = "Content-Type: text/html\r\n";		
        $header .= "Konu: " . $address . "\r\n";		
        mail($address, $subject, $message, $header);
    }
    
    update_option('WP_firewall_previous_attack_var', $bad_variable);
    update_option('WP_firewall_previous_attack_ip', $offender_ip);
}

// IP beyaz liste kontrol fonksiyonu
function WP_firewall_check_ip_whitelist() {
    $current_ip = $_SERVER['REMOTE_ADDR'];
    $ips = unserialize(get_option('WP_firewall_whitelisted_ip'));
    if (is_array($ips)) {
        foreach ($ips as $ip) {
            if ($current_ip == $ip || $current_ip == gethostbyname($ip)) {
                return true;
            }
        }
    }
    return false;
}

// Dizi düzleştirme fonksiyonu
function WP_firewall_array_flatten($array, &$newArray, $prefix = '', $delimiter = '][', $level = 0) {
    foreach ($array as $key => $child) {
        if (is_array($child)) {
            $newPrefix = $prefix . $key . $delimiter;
            if ($level == 0) {
                $newPrefix = $key . '[';
            }
            $newArray =& WP_firewall_array_flatten($child, $newArray, $newPrefix, $delimiter, $level + 1);
        } else {
            (!$level) ? $post = '' : $post = ']';
            $newArray[$prefix . $key . $post] = $child;
        }
    }
    return $newArray;
}

// Eklentinin kaldırılması sırasında yapılacak işlemler
register_deactivation_hook(__FILE__, 'WP_firewall_deactivate');
function WP_firewall_deactivate() {
    delete_option('WP_firewall_redirect_page');
    delete_option('WP_firewall_exclude_directory');
    delete_option('WP_firewall_exclude_queries');
    delete_option('WP_firewall_exclude_terms');
    delete_option('WP_firewall_exclude_spaces');
    delete_option('WP_firewall_exclude_file');
    delete_option('WP_firewall_exclude_http');
    delete_option('WP_firewall_email_enable');
    delete_option('WP_firewall_email_address');
    delete_option('WP_firewall_whitelisted_ip');
    delete_option('WP_firewall_whitelisted_page');
    delete_option('WP_firewall_whitelisted_variable');
    delete_option('WP_firewall_email_limit');
}

// Güncellemeleri kontrol et
add_action('wp_footer', 'slw_firewall_update_check');
function slw_firewall_update_check() {
    // Güncellemeleri kontrol etme kodları
}

// Yönlendirme ve hata sayfası
function WP_firewall_send_redirect() {
    $home_url = get_option('siteurl');
    if (get_option('WP_firewall_redirect_page') == '404page') {
        header("Location: $home_url/404/");
        exit();
    } else {
        header("Location: $home_url");
        exit();		
    }
}

// Admin panelinde stil ekle
add_action('admin_enqueue_scripts', 'slw_firewall_admin_styles');
function slw_firewall_admin_styles() {
    wp_enqueue_style('slw-firewall-admin', plugin_dir_url(__FILE__) . 'css/admin-style.css');
}

// Kullanıcı arayüzünde görsel uyarılar
add_action('wp_footer', 'slw_firewall_display_warning');
function slw_firewall_display_warning() {
    if (is_admin()) return;
    echo '<div class="slw-firewall-warning" style="background-color: #ffcc00; padding: 10px; text-align: center; font-weight: bold;">Sistemde güvenlik önlemleri alınmıştır. Lütfen dikkatli olun!</div>';
}

// Eklentinin kullanıcı arayüzü için stil
?>
<style>
.slw-firewall-warning {
    position: fixed;
    bottom: 10px;
    left: 50%;
    transform: translateX(-50%);
    width: 90%;
    z-index: 9999;
    border: 1px solid #ffd600;
    border-radius: 5px;
    background-color: #fff3cd;
    padding: 10px;
}
</style>
