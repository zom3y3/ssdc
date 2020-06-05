<?php
require 'function.php';
?>
<!DOCTYPE HTML>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Cluster analysis</title>
    <style>
      #loading,
      #canvas {
        position: absolute;
        margin: 0;
        width: 100%;
        height: 100%;
      }
      .links line {
        stroke: #999;
        stroke-opacity: 0.6;
        user-select: none;
        pointer-events: none;
      }
      .nodes circle {
        stroke: #fff;
        stroke-width: 1.5px;
      }
      .label text {
        text-anchor: middle;
        font-size: 12px;
        fill: black;
        user-select: none;
        pointer-events: none;
      }
      .label2 text {
        text-anchor: middle;
        font-size: 9px;
        fill: black;
        user-select: none;
        pointer-events: none;
      }
      div.tooltip {
        position: absolute;
        text-align: left;
        padding: 2px;
        font: 12px sans-serif;
        background: lightsteelblue;
        border: 0px;
        border-radius: 8px;
        user-select: none;
        pointer-events: none;
      }
    </style>
<script type="text/javascript" src="js/jquery/1.7.1/jquery.min.js"></script>
<script type="text/javascript" src="js/d3.v4.min.js"></script>
<script>
var session_str='';
</script>
<script src="js/graph.js"></script>
</head>
<body>
<div id="loading"></div>
<svg id="canvas"></svg>
<?php
if ($_GET) {
    $session = $_GET['session'];
    echo "<script>session_str = ('$session');</script>";
}
?>
</body>
</html>
