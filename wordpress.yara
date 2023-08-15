rule wordpress
{
    meta:
        description = "Detect Wordpress Malware"
        threat_level = 3
        in_the_wild = true
    strings:
        $global0 = "$GLOBALS['cwd']"
        $global1 = "$GLOBALS['pass']"
        $include0 = "@include \"\\0"
        $ico0 = "basename/*"
		$ico1 = "rawurldecode/*"
        $eval0 = "eval/*"
		$eval1 = "'] == 'eval')"
        $cookie0 = "@$_COOKIE[substr("
		$cookie1 = "array_merge($_COOKIE, $_POST)"
        $cookie2 = "[8]($_COOKIE, $_POST)"
        $anonymousFoxCronJobs = "wget -q -O xxxd http://"
		$chr0 = ".chr(111)"
    condition:
        ($global0 or $global1 or $include0 or $ico0 or $ico1 or $eval0 or $eval1 or $cookie0 or $cookie1 or $cookie2 or $anonymousFoxCronJobs or $chr0)
}
