rule Trojan_DarkGate
{
    meta:
        description = "Detecta o malware DarkGate (loader/trojan)"
        author = "GitHub Copilot"
        date = "2025-10-01"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate, https://www.trendmicro.com/en_us/research/23/i/darkgate-loader.html"
        malware_family = "DarkGate"
        threat_type = "trojan, loader, RAT"

    strings:
        // Strings e mutexes conhecidos
        $mtx1 = "DarkGateMutex" ascii
        $mtx2 = "DarkGate_Mutex" ascii
        $str1 = "DarkGate" ascii nocase
        $str2 = "DarkGateLoader" ascii nocase
        $str3 = "DarkGateRAT" ascii nocase
        $url1 = "darkgate[.]xyz" ascii
        $url2 = "darkgate[.]top" ascii
        $ua1 = "User-Agent: DarkGate" ascii
        $c2_1 = "POST /api/v1/darkgate" ascii
        $c2_2 = "GET /gate.php" ascii
        // PDBs conhecidos (exemplo)
        $pdb1 = "C:\\Users\\user\\source\\repos\\DarkGate\\DarkGate\\obj\\Release\\DarkGate.pdb" ascii nocase
        $pdb2 = "C:\\Users\\user\\source\\repos\\DarkGate\\DarkGate\\obj\\Debug\\DarkGate.pdb" ascii nocase
        // Assinatura binária (exemplo)
        $bin1 = { 44 61 72 6B 47 61 74 65 } // "DarkGate" em ASCII

    condition:
        2 of ($mtx*,$str*,$url*,$ua*,$c2_*,$pdb*,$bin1)
}
