rule wordpress_malware_webshell {
    meta:
        description = "Detect WordPress malware, generic webshells, WSO, and Marvins variants"
        author = "Jake Pucan"
        date = "2026-10-01"
        version = "3.0"
        threat_level = 3
        severity = "high"
        category = "webshell"
        reference = "https://github.com/ljfreelancer88/gofence"
        in_the_wild = true

    strings:
        // Generic Suspicious Global Variables
        $global0 = "$GLOBALS['cwd']" ascii
        $global1 = "$GLOBALS['pass']" ascii
        $global2 = "$GLOBALS['auth']" ascii
        $global3 = "$GLOBALS['login']" ascii

        // Obfuscated Includes
        $include0 = "@include \"\\0" ascii
        $include1 = "include($_" ascii
        $include2 = "require($_" ascii

        // ICO/Favicon Disguised Malware
        $ico0 = "basename/*" ascii
        $ico1 = "rawurldecode/*" ascii
        $ico2 = "GIF89a" ascii // Fake image header

        // Eval Patterns (High Risk)
        $eval0 = "eval/*" ascii
        $eval1 = "'] == 'eval')" ascii
        $eval2 = "eval(base64_decode(" ascii nocase
        $eval3 = "eval(gzinflate(" ascii nocase
        $eval4 = "eval(str_rot13(" ascii nocase
        $eval5 = "assert($_" ascii
        $eval6 = "preg_replace" ascii nocase // Base for deprecated /e modifier

        // Cookie-Based Backdoors
        $cookie0 = "@$_COOKIE[substr(" ascii
        $cookie1 = "array_merge($_COOKIE, $_POST)" ascii
        $cookie2 = "($_COOKIE, $_POST)" ascii
        $cookie3 = "extract($_COOKIE)" ascii

        // Command Execution Patterns
        $exec0 = "system($_" ascii
        $exec1 = "exec($_" ascii
        $exec2 = "shell_exec($_" ascii
        $exec3 = "passthru($_" ascii
        $exec4 = "popen($_" ascii
        $exec5 = "proc_open($_" ascii

        // Remote File Inclusion / Download
        $rfi0 = "wget -q -O xxxd http://" ascii
        $rfi1 = "file_get_contents('http" ascii
        $rfi2 = "curl_exec($" ascii

        // Obfuscation Techniques
        $obf0 = ".chr(111)" ascii
        $obf1 = "str_replace(" ascii
        $obf2 = /chr\(\d{2,3}\)\.chr\(\d{2,3}\)/ ascii
        $obf3 = "base64_decode(" ascii
        $obf4 = "gzinflate(" ascii
        $obf5 = "gzuncompress(" ascii
        $obf6 = "str_rot13(" ascii
        $obf7 = "hex2bin" ascii nocase
        $obf8 = "pack(" ascii nocase

        // Variable Function Calls (Highly Suspicious)
        $varfunc0 = /\$[a-zA-Z_]+\s*=\s*['"]assert['"]/ ascii
        $varfunc1 = /\$[a-zA-Z_]+\s*=\s*['"]system['"]/ ascii
        $varfunc2 = /\$[a-zA-Z_]+\(\$_(GET|POST|COOKIE|REQUEST)\[/ ascii

        // WordPress Context Specifics
        $wp0 = "wp-config.php" ascii
        $wp1 = "wp_generate_password" ascii
        $wp2 = "add_action('wp_head'" ascii

        // WSO Specific Indicators
        $wso0 = "WSO_VERSION" ascii nocase
        $wso1 = "WSOsetcookie" ascii nocase
        $wso2 = "action=Network" ascii
        $wso3 = "default_action" ascii

        // Marvins/Marvin Webshell Specific Indicators
        $marv0 = "Marvins" ascii nocase
        $marv1 = "marvin" fullword ascii nocase
        $marv2 = "/* MARVIN */" ascii
        $marv3 = "Sec-Marvin" ascii nocase

    condition:
        // Ensure file size is within typical script ranges to prevent scanning massive DB backups
        filesize < 2MB and 
        
        // Target file headers: PHP tags or fake GIF header
        (uint16(0) == 0x3f3c or uint32(0) == 0x4649473c) and 
        
        (
            // Immediate match for known specialized webshell footprints
            any of ($wso*) or 
            2 of ($marv*) or

            // High confidence standalone malicious indicators
            any of ($global*) or
            any of ($varfunc*) or
            
            // Highly suspicious combinations (requires multi-indicator intersection to reduce false positives)
            (any of ($eval*) and any of ($obf*)) or
            (any of ($cookie*) and any of ($obf*)) or
            (any of ($exec*) and (any of ($obf*) or any of ($include*))) or
            (any of ($rfi*) and any of ($exec*)) or
            (any of ($ico*) and 2 of ($obf*)) or
            (3 of ($obf*) and 1 of ($wp*))
        )
}
