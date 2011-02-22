<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="generator" content=
"HTML Tidy for Mac OS X (vers 31 October 2006 - Apple Inc. build 15.3.6), see www.w3.org" />
<title></title>
</head>
<body>
<?php
ini_set("session.cookie_httponly", 1);
include_once("../lib/GoogleAuthenticator.php");
include_once("Users.php");

$debug = true;

$users = new Users();
if ($username = $users->hasSession()) {
    $user = $users->loadUser($username);
    if (isset($_GET['logout'])) {
        session_destroy();
        header("Location: ./");
    }
    if ($user->isLoggedIn()) {
        include("../tmpl/loggedin.php");
        if (isset($_GET['showqr'])) {
            $secret = $user->getSecret();
            include("../tmpl/show-qr.php");
        }
    } else if ($user->isOTP() && isset($_POST['otp'])) {
        $g = new GoogleAuthenticator();
        if ($g->checkCode($user->getSecret(),$_POST['otp'])) {
             $user->doLogin();
             if (isset($_POST['remember']) && $_POST['remember']) {
                 $user->setOTPCookie();
             }
             include("../tmpl/loggedin.php");   
        } else {
            session_destroy();
            include("../tmpl/login-error.php");
        }
        
    } else {
        session_destroy();
    }
    
    
                
   die();
} else if (isset($_POST['username'])) { 
    $user = $users->loadUser($_POST['username']);
    
    if ($user) {
        if ($user->auth($_POST['password'])) {
            $user->startSession();
            if ($user->hasValidOTPCookie()) {
                include("../tmpl/loggedin.php");
                $user->doLogin();
                
            } else if (!$user->getSecret()) {
                include("../tmpl/loggedin.php");
            
                $secret = $user->generateSecret();
                $users->storeData($user);
                $user->doLogin();
                include("../tmpl/show-qr.php");
               
            } else {
                $user->doOTP();
                include("../tmpl/ask-for-otp.php");
            }
            
            
            die();
        } 
    }
            session_destroy();
        
    include("../tmpl/login-error.php");
    die();
} 

include("../tmpl/login.php");


?>
</body>
</html>