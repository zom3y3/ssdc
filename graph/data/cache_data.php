<?php
require '../connection.php';
require '../function.php';

$streamData = file_get_contents('php://input');
$session=json_decode($streamData)->{'session'};
$type=json_decode($streamData)->{'type'};
$base64_data=json_decode($streamData)->{'base64_data'};

$session=remove_xss(inject_check(addslashes($session)));
$type=remove_xss(inject_check(addslashes($type)));
$base64_data=inject_check(addslashes($base64_data));

if ($type == "query") {
    $cache_sql = "select `base64_data` from cache_base64data where session = '{$session}'";
    $cache_result = mysqli_query($con, $cache_sql) or die(mysqli_error($con));
    while ($r = mysqli_fetch_array($cache_result)) {
        $cache_data = $r['base64_data'];
    }
    if(strlen($cache_data) > 0)  {
        print base64_decode($cache_data);
      }
    mysqli_close($con);
}elseif ($type == "set") {
    $cache_sql = "insert into cache_base64data (`timestamp`, session, base64_data) VALUES (NOW()"
    .",'".$session
    ."','".$base64_data
    ."')";
    $rs = mysqli_query($con, $cache_sql);
    if (!$rs) {
        die("Valid result!" . mysqli_error($con));
    }
    echo json_encode(array('state'=>'success'));
    mysqli_close($con);
}

?>
