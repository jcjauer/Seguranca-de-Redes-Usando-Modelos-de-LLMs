rule Trojan_Spambot
{
    meta:
        description = "Detecta spambot genérico (malware que envia spam em massa)"
        author = "GitHub Copilot"
        date = "2025-10-01"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spambot, https://www.trendmicro.com/vinfo/us/security/definition/spambot"
        malware_family = "Spambot"
        threat_type = "trojan, spambot, botnet"

    strings:
        // Strings comuns em spambots
        $str1 = "HELO spammer" ascii nocase
        $str2 = "MAIL FROM:" ascii nocase
        $str3 = "RCPT TO:" ascii nocase
        $str4 = "Subject: Buy now" ascii nocase
        $str5 = "Subject: Viagra" ascii nocase
        $str6 = "Subject: Free money" ascii nocase
        $str7 = "X-Mailer: Spambot" ascii nocase
        $str8 = "X-Spam-Flag: YES" ascii nocase
        $str9 = "Received: from spammer" ascii nocase
        $mtx1 = "spambot_mutex" ascii
        $url1 = "spambot[.]xyz" ascii
        $url2 = "spambot[.]top" ascii
        // Assinatura binária (exemplo)
        $bin1 = { 53 70 61 6D 62 6F 74 } // "Spambot" em ASCII

    condition:
        2 of ($str*,$mtx*,$url*,$bin1)
}
