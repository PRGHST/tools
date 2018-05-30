rule Link_Archive_File_Extension {
    meta:
        description = "This rule looks for a URL/URI link containing a file extension associated to an archive file format"
   
    strings:
        $b1 = ".rar" nocase
        $b2 = ".zip" nocase
        $b3 = ".7z" nocase
        $b4 = ".cab" nocase
        $b5 = ".ace" nocase
        $b6 = ".jar" nocase

    condition:
        1 of ($b*)
}

rule Link_Document_File_Extension {
    meta:
        description = "This rule looks for a URL/URI link containing a file extension associated to an document file format"
    
    strings:
        $b1 = ".pdf" nocase
        $b2 = ".text" nocase
        $b3 = ".ps" nocase
        $b4 = ".doc" nocase
        $b5 = ".rtf" nocase
        $b6 = ".ppt" nocase
        $b7 = ".xls" nocase
        $b8 = ".odp" nocase
        $b9 = ".hwp" nocase
        $b10 = ".lnk" nocase
        $b11 = ".hta" nocase

    condition:
        1 of ($b*)
}


rule Link_WordPress_Site_Directory {
    meta:
        description = "This rule looks for a URL/URI link with indication of a WordPress directory"

    strings:
        $b1 = "wp-admin" nocase
        $b2 = "wp-content" nocase
        $b3 = "wp-includes" nocase

    condition:
       1 of ($b*)

}

rule Link_Possible_Phishing_Variation_1 {
    meta:
        description = "This rule looks for URI/URL pattern(s) relatable to a phishing campaign(s)"

    strings:
        $a1 = "rechnung" nocase // Translated from German as "bill"
        $a2 = "invoice" nocase
        $a3 = "account" nocase
        $a4 = "paypal" nocase
        $a5 = "wire-form" nocase
        $a6 = "inv" nocase
    
        $b1 = /(rechnung|invoice|wire-form|ach-form|inv)\/([\S]{1,}\/)?/ nocase
    
    condition:
        1 of ($a*) and 1 of ($b*)

}

rule Link_Possible_Phishing_Variation_2 {
    meta:
        description = "This rule looks for URI/URL pattern(s) relatable to a phishing campaign(s)"
        reference = "https://pastebin.com/WuXJgUw5 - Emotet Phishing Links May 23, 2018"
    
    strings:
        $a1 = "WebTracking" nocase
        $b1 = /WebTracking\/[a-z]{1,3}-{4,}\/$/ nocase

    condition:
        all of them
}

rule Link_Possible_Phishing_Variation_3 {
    meta:
        description = "This rule looks for URI/URL pattern(s) relatable to phishing campaign(s)"
        reference = "https://pastebin.com/WuXJgUw5 - Emotet Phishing Links May 23, 2018"
    
    strings:
        $a1 = "Account" nocase
        $a2 = "File" nocase
        $a3 = "Status" nocase


        $b1 = /(ACCOUNT|FILE|STATUS)\/Invoice.*\/$/ nocase

    condition:
        1 of ($a*) and $b1
}

rule Link_Possible_Exploit_Kit_Variation_1 {
    meta:
        description = "This rule looks for URI/URL pattern(s) associated to web exploit kit(s)"
        reference = "https://zerophagemalware.com/2018/05/22/rig-ek-ngay-drops-smokeloader-xmr-miner/  - Rig Exploit Kit"

    strings:
        $a1 = "=cmVzb3J0"
        $a2 = "=Zmx5"
        $a3 = "=c3BvcnQ=" 

        $b1 = /[a-z]{3,}\:\/\/[\S]{100,}/ nocase // This looks for an URI/URL pattern longer than 100 characters
    
    condition:
        $b1 and 1 of ($a*)
}

rule Link_Explicit_Content {
    meta:
        description = "This rule looks for an URI/URL link with indication of possible explicit content"

    strings:
        $a1 = "sexy" nocase
        $a2 = "bikini" nocase
        $a3 = "nude" nocase
	    $a4 = "naked" nocase
	    $a5 = "porn" nocase
    
    condition:
        1 of ($a*)
}

rule Link_PHP_File {
    meta:
        description = "This rule looks for an URI/URL link with indication of a PHP page"
    
    strings:
        $a1 = ".php" nocase

    condition:
        1 of ($a*)
}


