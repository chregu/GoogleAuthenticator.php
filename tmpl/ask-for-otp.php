
<h1>please otp</h1>
<p>
<form method="post" action="./">
otp: <input name="otp"
value="<?php 
$g = new GoogleAuthenticator();
        
echo $g->getCode($user->getSecret());?>"/><br/>
<input type="submit"/>
</form>