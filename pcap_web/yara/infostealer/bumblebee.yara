rule Trojan_Bumblebee
{
    meta:
        description = "Detecta o loader Bumblebee"
        author = "GitHub Copilot"
        date = "2025-10-01"
        reference = "https://www.trendmicro.com/en_us/research/22/e/bumblebee-loader-abuses.html, https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee"
        malware_family = "Bumblebee"
        threat_type = "trojan, loader, infostealer"

    strings:
        // Strings e PDBs conhecidos
        $pdb1 = "C:\\Users\\user\\source\\repos\\Bumblebee\\Bumblebee\\obj\\Release\\Bumblebee.pdb" ascii nocase
        $pdb2 = "C:\\Users\\user\\source\\repos\\Bumblebee\\Bumblebee\\obj\\Debug\\Bumblebee.pdb" ascii nocase
        $str1 = "bumblebee" ascii nocase
        $str2 = "bumblebee_loader" ascii nocase
        $str3 = "bumblebee_module" ascii nocase
        $str4 = "bumblebee_mutex" ascii nocase
        $mtx1 = "bbee_mutex" ascii
        $mtx2 = "bumblebee_mutex" ascii
        $url1 = "bumblebee[.]xyz" ascii
        $url2 = "bumblebee[.]top" ascii
        // C2 patterns conhecidos (exemplo)
        $c2_1 = "POST /api/v1/upload" ascii
        $c2_2 = "User-Agent: bumblebee" ascii

        // Assinaturas binárias (exemplo, pode ser expandido)
        $bin1 = { 42 75 6D 62 6C 65 62 65 65 } // "Bumblebee" em ASCII

    condition:
        2 of ($pdb*,$str*,$mtx*,$url*,$c2_*, $bin1)
}
