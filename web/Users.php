<?php

class Users {
    
    
    function __construct($file = "../users.dat") {
        $this->userFile = $file;
        
        $this->users = json_decode(file_get_contents($file),true);   
    }
    function hasSession() {
        session_start();
        if (isset($_SESSION['username'])) {
            return $_SESSION['username'];
        }
        return false;
    }
    
    
    function storeData(User $user) {
        $this->users[$user->getUsername()] = $user->getData();
        file_put_contents($this->userFile,json_encode($this->users));
    }
    
    function loadUser($name) {
        if (isset($this->users[$name])) {
            
            return new User($name,$this->users[$name]);
        } else {
            return false;
        }
    }
    
    
    
}

class User {
    
    function __construct($user,$data) {
        $this->data = $data;
        $this->user = $user;
    }
    
    function auth($pass) {
        if ($this->data['password'] === $pass) {
            return true;
        }
        
        return false;
        
    }
    
    function startSession() {
        
        $_SESSION['username'] = $this->user;
    }
    
    function doLogin() {
        session_regenerate_id();
        $_SESSION['loggedin'] = true;
        $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'];
    }
    
    function doOTP() {
        $_SESSION['OTP'] = true;
    }
    
    function isOTP() {
        if (isset($_SESSION['OTP']) && $_SESSION['OTP'] == true) {
            
            return true;
        }
        return false;
        
    }
    function isLoggedIn() {
        if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] == true &&
            isset($_SESSION['ua']) && $_SESSION['ua'] == $_SERVER['HTTP_USER_AGENT']
        ) {
            
            return $_SESSION['username'];
        }
        return false;
        
    }
    
    
    function getUsername() {
        return $this->user;   
    }
    
    function getSecret() {
        if (isset($this->data['secret'])) {
            return $this->data['secret'];
        }
        return false;
    }
    
    function generateSecret() {
        $g = new GoogleAuthenticator();
        $secret = $g->generateSecret();
        $this->data['secret'] = $secret;
        return $secret;
        
    }
    
    function getData() {
        return $this->data;
    }
    
    function setOTPCookie() {
        $time = floor(time() / (3600 * 24) ); // get day number
        //about using the user agent: It's easy to fake it, but it increases the barrier for stealing and reusing cookies nevertheless
        // and it doesn't do any harm (except that it's invalid after a browser upgrade, but that may be even intented)
        $cookie =  $time.":".hash_hmac("sha1",$this->getUsername().":".$time.":". $_SERVER['HTTP_USER_AGENT'],$this->getSecret());
        setcookie ( "otp", $cookie, time() + (30 * 24 * 3600), null,null,null,true );
    }
    
    function hasValidOTPCookie() {
        // 0 = tomorrow it is invalid
        $daysUntilInvalid = 0;
        $time = (string) floor((time() / (3600 * 24))) ; // get day number
        if (isset($_COOKIE['otp'])) {
            list( $otpday,$hash) = explode(":",$_COOKIE['otp']);
               
            if ( $otpday >= $time - $daysUntilInvalid && $hash == hash_hmac('sha1',$this->getUsername().":".$otpday .":". $_SERVER['HTTP_USER_AGENT'] , $this->getSecret())
                ) {
                  return true;
            }
                
             
        }
        return false;
    
    }
    
}
?>
