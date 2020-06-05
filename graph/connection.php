<?php
error_reporting(E_ERROR | E_PARSE);
$con = mysqli_init();
if (!$con) {
    die('mysqli_init failed');
}
#mysqli_options ($con, MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);
#$con->ssl_set('/etc/mysql/ssl/client-key.pem', '/etc/mysql/ssl/client-cert.pem', '/etc/mysql/ssl/ca-cert.pem', NULL, NULL);
if (!mysqli_real_connect ($con, '127.0.0.1', 'test', 'test', 'cache_db', 3306, NULL, MYSQLI_CLIENT_SSL)) {
    die('Connect Error (' . mysqli_connect_errno() . ') '. mysqli_connect_error());
}
?>
