
<h1>please otp</h1>
<p>
<form method="post" action="./">
otp: <input name="otp"
value="<?php 
if ($debug) {
$g = new GoogleAuthenticator();
echo $g->getCode($user->getSecret());
}
?>"/><br/>
<input type="checkbox" name="remember" id="remember" /><label for="remember"> Remember verification for this computer for 1 day.</label> <br/>
<input type="submit"/>
</form>