rule Domain_URL_Shortener {
    meta:
        description = "This rule looks for a domain associated with shortened URLs"
    
    strings:
        $a1 = /^goo\.gl[\n]?$/ nocase // Google shorten URL domain
        $a2 = /^bit\.ly[\n]?$/ nocase // Bitly shorten URL domain
        $a3 = /^t\.co[\n]?$/ nocase // Twitter shorten URL domain
        $a4 = /^db\.tt[\n]?$/ nocase // Dropbox shorten URL domain
        $a5 = /^lnkd\.in[\n]?$/ nocase // LinkedIn shorten URL domain
        $a6 = /^qr\.ae[\n]?$/ nocase // Quora shorten URL domain
        $a7 = /^adf\.ly[\n]?$/ nocase
        $a8 = /^bit\.do[\n]?$/ nocase 
        $a9 = /^bitly\.com[\n]?$/ nocase 
        $a10 = /^cur\.lv[\n]?$/ nocase  
        $a11 = /^tinyurl\.com[\n]?$/ nocase 
        $a12 = /^ow\.ly[\n]?$/ nocase 
        $a13 = /^ity\.im[\n]?$/ nocase
        $a14 = /^q\.gs[\n]?$/ nocase
        $a15 = /^is\.gd[\n]?$/ nocase
        $a16 = /^po\.st[\n]?$/ nocase 
        $a17 = /^bc\.vc[\n]?$/ nocase 
        $a18 = /^twitthis\.com[\n]?$/ nocase
        $a19 = /^u\.to[\n]?$/ nocase // 
        $a20 = /^j\.mp[\n]?$/ nocase //Bitly shorten URL domain
        $a21 = /^buzurl\.com[\n]?$/ nocase
        $a22 = /^cutt\.us[\n]?$/ nocase
        $a23 = /^u\.bb[\n]?$/ nocase
        $a24 = /^yourls\.org[\n]?$/ nocase 
        $a25 = /^x\.co[\n]?$/ nocase
        $a26 = /^prettylinkpro\.com[\n]?$/ nocase
        $a27 = /^scrnch\.me[\n]?$/ nocase
        $a28 = /^filoops\.info[\n]?$/ nocase
        $a29 = /^vzturl\.com[\n]?$/ nocase
        $a30 = /^qr\.net[\n]?$/ nocase 
        $a31 = /^1url\.com[\n]?$/ nocase
        $a32 = /^tweez\.me[\n]?$/ nocase
        $a33 = /^v\.gd[\n]?$/ nocase
        $a34 = /^tr\.im[\n]?$/ nocase
        $a35 = /^link\.zip\.net[\n]?$/ nocase 
        $a36 = /^youtu\.be[\n]?$/ nocase // Youtube shorten URL domain
        $a37 = /^aka\.ms[\n]?$/ nocase // Akamai - Microsoft shorten URL domain
        $a38 = /^we\.tl[\n]?$/ nocase // WeTransfer File Transfer Service
        $a39 = /^tbf\.me[\n]?$/ nocase // TransferBigFiles shorten URL domain
        $a40 = /^fil\.email[\n]?$/ nocase // FileMail shorten URL domain
        $a41 = /^g\.co[\n]?$/ nocase // Google shorten URL domain
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
        $a1 = /\.zip[\n]?$/ nocase
        $a2 = /\.review[\n]?$/ nocase
        $a3 = /\.country[\n]?$/ nocase
        $a4 = /\.kim[\n]?$/ nocase
        $a5 = /\.science[\n]?$/ nocase
        $a6 = /\.work[\n]?$/ nocase
        $a7 = /\.party[[\n]?$/ nocase
        $a8 = /\.gq[\n]?$/ nocase
        $a9 = /\.link[\n]?$/ nocase
        $a10 = /\.stream[\n]?$/ nocase
        $a11 = /\.gdn[\n]?$/ nocase
        $a12 = /\.mom[\n]?$/ nocase
        $a13 = /\.xin[\n]?$/ nocase
        $a14 = /\.men[\n]?$/ nocase
        $a15 = /\.loan[\n]?$/ nocase
        $a16 = /\.download[\n]?$/ nocase
        $a17 = /\.racing[\n]?$/ nocase
        $a18 = /\.online[\n]?$/ nocase
        $a19 = /\.ren[\n]?$/ nocase
        $a20 = /\.gb[\n]?$/ nocase
        $a21 = /\.win[\n]?$/ nocase
        $a22 = /\.top[\n]?$/ nocase
        $a23 = /\.review[\n]?$/ nocase
        $a24 = /\.vip[\n]?$/ nocase
        $a25 = /\.party[\n]?$/ nocase
        $a26 = /\.click[\n]?$/ nocase
        $a28 = /\.cricket[\n]?$/ nocase
        $a29 = /\.webcam[\n]?$/ nocase
        $a30 = /\.pictures[\n]?$/ nocase
        $a31 = /\.consulting[\n]?$/ nocase
        $a32 = /\.xyz[\n]?$/ nocase
        $a33 = /\.club[\n]?$/ nocase
        $a34 = /\.email[\n]?$/ nocase
        $a35 = /\.solutions[\n]?$/ nocase
        $a36 = /\.domains[\n]?$/ nocase
        $a37 = /\.company[\n]?$/ nocase
        $a38 = /\.photos[\n]?$/ nocase
        $a39 = /\.directory[\n]?$/ nocase
        $a40 = /\.enterprises[\n]?$/ nocase
        $a41 = /\.guru[\n]?$/ nocase
        $a42 = /\.cc[\n]?$/ nocase
        $a43 = /\.hu[\n]?$/ nocase
        $a44 = /\.ga[\n]?$/ nocase
        $a45 = /\.ml[\n]?$/ nocase
        $a46 = /\.bit[\n]?$/ nocase
        $a47 = /\.co[\n]?$/ nocase
        $a48 = /\.dz[\n]?$/ nocase

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