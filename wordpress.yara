rule wordpress_malware_webshell
{
    meta:
        description = "Detect WordPress malware and webshells"
        author = "Security Team"
        date = "2026-01-21"
        version = "2.0"
        threat_level = 3
        severity = "high"
        category = "webshell"
        reference = "https://github.com/your-repo/yara-rules"
        in_the_wild = true
        
    strings:
        // Suspicious global variable usage
        $global0 = "$GLOBALS['cwd']" ascii
        $global1 = "$GLOBALS['pass']" ascii
        $global2 = "$GLOBALS['auth']" ascii
        $global3 = "$GLOBALS['login']" ascii
        
        // Obfuscated includes
        $include0 = "@include \"\\0" ascii
        $include1 = "include($_" ascii
        $include2 = "require($_" ascii
        
        // ICO/favicon disguised malware
        $ico0 = "basename/*" ascii
        $ico1 = "rawurldecode/*" ascii
        $ico2 = "GIF89a" ascii // fake image header
        
        // Eval patterns (high risk)
        $eval0 = "eval/*" ascii
        $eval1 = "'] == 'eval')" ascii
        $eval2 = "eval(base64_decode(" ascii nocase
        $eval3 = "eval(gzinflate(" ascii nocase
        $eval4 = "eval(str_rot13(" ascii nocase
        $eval5 = "assert($_" ascii
        
        // Cookie-based backdoors
        $cookie0 = "@$_COOKIE[substr(" ascii
        $cookie1 = "array_merge($_COOKIE, $_POST)" ascii
        $cookie2 = "[8]($_COOKIE, $_POST)" ascii
        $cookie3 = "extract($_COOKIE)" ascii
        
        // Command execution patterns
        $exec0 = "system($_" ascii
        $exec1 = "exec($_" ascii
        $exec2 = "shell_exec($_" ascii
        $exec3 = "passthru($_" ascii
        $exec4 = "popen($_" ascii
        $exec5 = "proc_open($_" ascii
        
        // Remote file inclusion / download
        $rfi0 = "wget -q -O xxxd http://" ascii
        $rfi1 = "file_get_contents('http" ascii
        $rfi2 = "curl_exec($" ascii
        
        // Obfuscation techniques
        $obf0 = ".chr(111)" ascii
        $obf1 = "str_replace(" ascii
        $obf2 = /chr\(\d{2,3}\)\.chr\(\d{2,3}\)/ ascii
        $obf3 = "base64_decode(" ascii
        $obf4 = "gzinflate(" ascii
        $obf5 = "gzuncompress(" ascii
        $obf6 = "str_rot13(" ascii
        
        // Variable function calls (highly suspicious)
        $varfunc0 = /\$[a-zA-Z_]+\s*=\s*['"]assert['"]/ ascii
        $varfunc1 = /\$[a-zA-Z_]+\s*=\s*['"]system['"]/ ascii
        $varfunc2 = /\$[a-zA-Z_]+\(\$_(GET|POST|COOKIE|REQUEST)\[/ ascii
        
        // Preg_replace /e modifier (deprecated but dangerous)
        $preg0 = "preg_replace(.*\/e" ascii nocase
        
        // Create_function backdoors
        $create0 = "create_function" ascii
        
        // File operations on suspicious paths
        $file0 = "fwrite($" ascii
        $file1 = "file_put_contents($_" ascii
        
        // PHP input stream (often used in webshells)
        $input0 = "php://input" ascii
        $input1 = "php://filter" ascii
        
    condition:
        // High confidence indicators
        (
            any of ($eval*) or
            any of ($cookie*) or
            $rfi0 or
            any of ($varfunc*) or
            $preg0
        )
        or
        // Medium confidence: multiple suspicious patterns
        (
            (any of ($global*) and (any of ($exec*) or any of ($obf*))) or
            (any of ($include*) and any of ($obf*)) or
            (2 of ($exec*)) or
            (3 of ($obf*)) or
            (any of ($ico*) and any of ($obf*))
        )
}

rule wordpress_malware_c99_shell
{
    meta:
        description = "Detect C99 shell variants in WordPress"
        author = "Security Team"
        date = "2026-01-21"
        threat_level = 5
        severity = "critical"
        category = "webshell"
        
    strings:
        $c99_0 = "c99shell" ascii nocase
        $c99_1 = "safe_mode" ascii
        $c99_2 = "disable_functions" ascii
        $c99_3 = "phpinfo()" ascii
        $c99_4 = "getmyuid()" ascii
        $c99_5 = "getcwd()" ascii
        
    condition:
        3 of them
}

rule wordpress_malware_uploader
{
    meta:
        description = "Detect file upload backdoors"
        author = "Security Team"
        date = "2026-01-21"
        threat_level = 4
        severity = "high"
        category = "uploader"
        
    strings:
        $upload0 = "move_uploaded_file($_FILES" ascii
        $upload1 = "copy($_FILES" ascii
        $upload2 = "$_FILES[" ascii
        $upload3 = "file_put_contents(" ascii
        
        $dest0 = /\$_(GET|POST|COOKIE|REQUEST)\['[^']{1,20}'\]/ ascii
        
    condition:
        any of ($upload*) and $dest0
}
