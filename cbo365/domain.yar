rule Domain_URL_Shortener {
    meta:
        description = "This rule looks for a domain associated with shortened URLs"
    
    strings:
        $a1 = /goo\.gl$/ nocase // Google shorten URL domain
        $a2 = /bit\.ly$/ nocase // Bitly shorten URL domain
        $a3 = /t\.co$/ nocase // Twitter shorten URL domain
        $a4 = /db\.tt$/ nocase // Dropbox shorten URL domain
        $a5 = /lnkd\.in$/ nocase // LinkedIn shorten URL domain
        $a6 = /qr\.ae$/ nocase // Quora shorten URL domain
        $a7 = /adf\.ly$/ nocase
        $a8 = /bit\.do$/ nocase 
        $a9 = /bitly\.com$/ nocase 
        $a10 = /cur\.lv$/ nocase  
        $a11 = /tinyurl\.com$/ nocase 
        $a12 = /ow\.ly$/ nocase 
        $a13 = /ity\.im$/ nocase
        $a14 = /q\.gs$/ nocase
        $a15 = /is\.gd$/ nocase
        $a16 = /po\.st$/ nocase 
        $a17 = /bc\.vc$/ nocase 
        $a18 = /twitthis\.com$/ nocase
        $a19 = /u\.to$/ nocase // 
        $a20 = /j\.mp$/ nocase //Bitly shorten URL domain
        $a21 = /buzurl\.com$/ nocase
        $a22 = /cutt\.us$/ nocase
        $a23 = /u\.bb$/ nocase
        $a24 = /yourls\.org$/ nocase 
        $a25 = /x\.co$/ nocase
        $a26 = /prettylinkpro\.com$/ nocase
        $a27 = /scrnch\.me$/ nocase
        $a28 = /filoops\.info$/ nocase
        $a29 = /vzturl\.com$/ nocase
        $a30 = /qr\.net$/ nocase 
        $a31 = /1url\.com$/ nocase
        $a32 = /tweez\.me$/ nocase
        $a33 = /v\.gd$/ nocase
        $a34 = /tr\.im$/ nocase
        $a35 = /link\.zip\.net$/ nocase 
        $a36 = /youtu\.be$/ nocase // Youtube shorten URL domain
        $a37 = /aka\.ms$/ nocase // Akamai - Microsoft shorten URL domain
	    $a38 = /we\.tl$/ nocase // WeTransfer File Transfer Service
        $a39 = /tbf\.me$/ nocase // TransferBigFiles shorten URL domain
        $a40 = /fil\.email$/ nocase // FileMail shorten URL domain
        $a41 = /^g\.co$/ nocase // Google shorten URL domain
    condition:
        1 of ($a*)
}

rule Domain_File_Hosting_Transfer {
    meta:
        description = "This rule looks for a domain indicative of being a file transfer/hosting service domain site"

    strings:
        $a1 = "wetransfer.com" nocase
        $a2 = "dropbox.com" nocase
        $a3 = "wesendit.com" nocase
        $a4 = "pcloud.com" nocase
        $a5 = "nofile.io" nocase
        $a6 = "sabercathost.com" nocase
        $a7 = "mega.nz" nocase
        $a8 = "zippyshare.com" nocase
        $a9 = "4shared.com" nocase
        $a10 = "mediafire.com" nocase
        $a11 = "filemail.com" nocase
    
    condition:
        1 of ($a*)

}

rule Domain_Suspicious_TLD {
    meta:
        description = "This rule looks for a domain indicative of a suspicious TLD (top-level domain)"

    strings:
        $a1 = /.*\.zip$/ nocase
        $a2 = /.*\.review$/ nocase
        $a3 = /.*\.country$/ nocase
        $a4 = /.*\.kim$/ nocase
        $a5 = /.*\.science$/ nocase
        $a6 = /.*\.work$/ nocase
        $a7 = /.*\.party$/ nocase
        $a8 = /.*\.gq$/ nocase
        $a9 = /.*\.link$/ nocase
        $a10 = /.*\.stream$/ nocase
        $a11 = /.*\.gdn$/ nocase
        $a12 = /.*\.mom$/ nocase
        $a13 = /.*\.xin$/ nocase
        $a14 = /.*\.men$/ nocase
        $a15 = /.*\.loan$/ nocase
        $a16 = /.*\.download$/ nocase
        $a17 = /.*\.racing$/ nocase
        $a18 = /.*\.online$/ nocase
        $a19 = /.*\.ren$/ nocase
        $a20 = /.*\.gb$/ nocase
        $a21 = /.*\.win$/ nocase
        $a22 = /.*\.top$/ nocase
        $a23 = /.*\.review$/ nocase
        $a24 = /.*\.vip$/ nocase
        $a25 = /.*\.party$/ nocase
        $a26 = /.*\.click$/ nocase
        $a28 = /.*\.cricket$/ nocase
        $a29 = /.*\.webcam$/ nocase
        $a30 = /.*\.pictures$/ nocase
        $a31 = /.*\.consulting$/ nocase
        $a32 = /.*\.xyz$/ nocase
        $a33 = /.*\.club$/ nocase
        $a34 = /.*\.email$/ nocase
        $a35 = /.*\.solutions$/ nocase
        $a36 = /.*\.domains$/ nocase
        $a37 = /.*\.company$/ nocase
        $a38 = /.*\.photos$/ nocase
        $a39 = /.*\.directory$/ nocase
        $a40 = /.*\.enterprises$/ nocase
        $a41 = /.*\.guru$/ nocase
        $a42 = /.*\.cc$/ nocase
        $a43 = /.*\.hu$/ nocase
        $a44 = /.*\.ga$/ nocase
        $a45 = /.*\.ml$/ nocase
        $a46 = /.*\.bit$/ nocase
        $a47 = /.*\.co$/ nocase
        $a48 = /.*\.dz$/ nocase

    condition:
        1 of ($a*)
}

rule Domain_Hardcoded_IP {
    meta:
        description = "This rule looks for a domain indicative of an IP address"

    strings:
        $a = /[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}/
    
    condition:
        $a
}