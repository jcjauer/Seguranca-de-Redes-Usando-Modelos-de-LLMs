/*
    REGRAS YARA CONSOLIDADAS PARA BUMBLEBEE MALWARE - VERSÃO 3.0 REFINADA
    
    Versão refinada para evitar FALSOS POSITIVOS
    
    MUDANÇAS PRINCIPAIS:
    ✓ Removidos padrões LDAP/SMB genéricos que aparecem em qualquer exploit
    ✓ Adicionado requisito OBRIGATÓRIO de IOCs específicos de Bumblebee
    ✓ Aumentados os thresholds de detecção
    ✓ Meta-regra muito mais restritiva
    
    Autor: Sistema de Análise de Segurança Consolidado
    Data: 05/05/2026
    Versão: 3.0 Refinada para Evitar Falsos Positivos
*/

import "math"

// ═══════════════════════════════════════════════════════════
// SEÇÃO 1: NETWORK TRAFFIC ANALYSIS
// Requer IOCs MUITO ESPECÍFICOS de Bumblebee
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Core_Network_Traffic_v3 {
    meta:
        description = "Tráfego de rede específico do Bumblebee com IOCs únicos (v3 refinada)"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "critical"
        category = "network_traffic"
        confidence = "very_high"
        
    strings:
        // Domínios C2 MUITO específicos (não genéricos)
        $domain1 = "alwaysopen.studio" ascii nocase
        $domain2 = "mediaclickinc.net" ascii nocase
        $domain3 = "mediaclickinc" ascii nocase
        
        // Hostname único observado em Bumblebee
        $hostname = "WIN-G2YBXE8XMCG" ascii nocase
        
        // User-Agents específicos
        $ua1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" ascii
        $ua2 = "User-Agent: WINDOWS-NO-BROWSER" ascii nocase
        
        // Parâmetros HTTP únicos
        $param1 = "ref=mediaclickinc" ascii nocase
        $param2 = "gate=" ascii nocase
        
        // Marcadores de comando C2
        $marker1 = "GATE" ascii nocase
        $marker2 = "not_defined_in_RFC4178@please_ignore" ascii
        
        // HTTP específico
        $http1 = "GET /gate" ascii nocase
        $http2 = "POST /gate" ascii nocase
        
    condition:
        (filesize > 1KB and filesize < 100MB) and
        (
            // Par de IOC extremamente específico já observado no Bumblebee real
            (any of ($domain*) and $hostname) or

            // Domínio + pelo menos 2 marcadores específicos
            (any of ($domain*) and 2 of ($param*, $marker*, $http*, $ua*)) or
            
            // HTTP específico + pelo menos 2 marcadores
            (any of ($http*) and 2 of ($param*, $marker*, $ua*, $domain*)) or
            
            // UA específica + domínio + parâmetro
            (any of ($ua*) and any of ($domain*)) and any of ($param*) or
            
            // Hostname + domínio + parâmetro
            ($hostname and any of ($domain*) and any of ($param*))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 2: IOC DETECTION
// IOCs muito específicos encontrados em campanhas Bumblebee
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Specific_IOCs {
    meta:
        description = "IOCs específicos observados em campanhas Bumblebee reais"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "critical"
        category = "ioc_detection"
        confidence = "very_high"
        
    strings:
        // IOCs de campanhas reais (strings encontradas em extrações)
        $ioc1 = "ipmieh" ascii nocase
        $ioc2 = "bzuvnae" ascii nocase 
        $ioc3 = "emebqylmdd" ascii nocase
        $ioc4 = "surevbu" ascii nocase
        $ioc5 = "kgxxghrzjvzbkq" ascii nocase
        
        // Arquivos específicos
        $file1 = "dj.js" ascii nocase
        $file2 = "index.php" ascii nocase
        
        // Parâmetros únicos
        $param1 = "ref=mediaclickinc" ascii nocase
        $param2 = "gate=" ascii nocase
        
    condition:
        // Requer pelo menos 2 IOCs específicos ou uma combinação mais forte
        (2 of ($ioc*)) or
        ($file1 and $file2 and any of ($param*)) or
        (any of ($file*) and 2 of ($param*))
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 3: BEHAVIORAL PATTERNS
// Comunicação C2 específica de Bumblebee
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Behavioral_C2_Communication {
    meta:
        description = "Padrões C2 específicos do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "high"
        category = "behavioral"
        
    strings:
        // Domínios C2 Bumblebee
        $c2_1 = "alwaysopen.studio" ascii nocase
        $c2_2 = "mediaclickinc" ascii nocase
        
        // HTTP específico
        $http_post = "POST /" ascii
        $http_get = "GET /" ascii
        
        // Parâmetros Bumblebee
        $param1 = "ref=mediaclickinc" ascii nocase
        $param2 = "gate=" ascii nocase
        
        // Strings específicas
        $gate = "GATE" ascii nocase
        
        // JSON com contexto Bumblebee
        $json1 = "\"cmd\":" ascii
        $json2 = "\"gate\":" ascii
        
    condition:
        (filesize > 1KB and filesize < 1MB) and
        (
            // HTTP + domínio específico Bumblebee + parâmetro
            ((any of ($http_post, $http_get)) and any of ($c2_1, $c2_2) and any of ($param*)) or
            
            // HTTP + 2 parâmetros/markers específicos
            ((any of ($http_post, $http_get)) and 2 of ($param*, $gate, $c2_1, $c2_2)) or
            
            // JSON com markers Bumblebee + domínio
            (any of ($json1, $json2) and any of ($c2_1, $c2_2, $gate) and any of ($param*)) or
            
            // Múltiplos indicadores específicos
            (any of ($gate, $param*) and any of ($c2_1, $c2_2) and any of ($http_post, $http_get))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 4: LDAP + CONTEXTO BUMBLEBEE
// LDAP SOMENTE com IOCs específicos de Bumblebee
// ═══════════════════════════════════════════════════════════

rule Bumblebee_LDAP_with_Bumblebee_Context {
    meta:
        description = "LDAP + IOCs Bumblebee (não LDAP genérico)"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "high"
        category = "reconnaissance"
        
    strings:
        // IOCs OBRIGATÓRIOS de Bumblebee
        $bumblebee_marker1 = "alwaysopen.studio" ascii nocase
        $bumblebee_marker2 = "mediaclickinc" ascii nocase
        $bumblebee_marker3 = "WIN-G2YBXE8XMCG" ascii nocase
        
        // LDAP com contexto
        $ldap_search = "SearchRequest" ascii nocase
        $ldap_user = "sAMAccountName" ascii nocase
        $ldap_computer = "objectCategory=computer" ascii nocase
        
    condition:
        (filesize > 512 and filesize < 50KB) and
        // REQUER IOC específico Bumblebee
        any of ($bumblebee_marker*) and
        // MAIS LDAP
        (2 of ($ldap_search, $ldap_user, $ldap_computer))
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 5: SMB + CONTEXTO BUMBLEBEE
// SMB SOMENTE com IOCs específicos de Bumblebee
// ═══════════════════════════════════════════════════════════

rule Bumblebee_SMB_with_Bumblebee_Context {
    meta:
        description = "SMB lateral movement + IOCs Bumblebee (não SMB genérico)"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "high"
        category = "lateral_movement"
        
    strings:
        // IOCs OBRIGATÓRIOS de Bumblebee
        $bumblebee_ioc1 = "alwaysopen.studio" ascii nocase
        $bumblebee_ioc2 = "mediaclickinc" ascii nocase
        $bumblebee_ioc3 = "WIN-G2YBXE8XMCG" ascii nocase
        
        // SMB header
        $smb_sig = { FE 53 4D 42 }
        
        // Movimento lateral específico (PsExec)
        $psexec1 = "ADMIN$\\system32" ascii nocase
        $psexec2 = "\\pipe\\svcctl" ascii nocase
        
    condition:
        (filesize > 2KB and filesize < 500KB) and
        any of ($bumblebee_ioc*) and
        $smb_sig and
        (2 of ($psexec*))
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 6: ENCRYPTION WITH BUMBLEBEE CONTEXT
// ═══════════════════════════════════════════════════════════

rule Bumblebee_High_Entropy_with_Context {
    meta:
        description = "Alta entropia + IOCs Bumblebee (não entropia genérica)"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "medium"
        category = "encryption"
        
    strings:
        // IOCs específicos Bumblebee
        $bumblebee_string1 = "GATE" ascii nocase
        $bumblebee_string2 = "alwaysopen.studio" ascii nocase
        $bumblebee_string3 = "mediaclickinc" ascii nocase
        
    condition:
        (filesize > 5KB and filesize < 50KB) and
        // REQUER contexto específico + alta entropia
        any of ($bumblebee_string*) and
        (any of ($bumblebee_string2, $bumblebee_string3) or math.entropy(0, filesize) >= 7.8) and
        (math.entropy(0, filesize) >= 7.5)
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 7: PERSISTENCE WITH BUMBLEBEE CONTEXT
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Persistence_with_Context {
    meta:
        description = "Persistência + IOCs Bumblebee (não registry genérico)"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "high"
        category = "persistence"
        
    strings:
        // IOCs OBRIGATÓRIOS
        $bumblebee_mark1 = "alwaysopen.studio" ascii nocase
        $bumblebee_mark2 = "mediaclickinc" ascii nocase
        $bumblebee_mark3 = "GATE" ascii nocase
        
        // Registry
        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        
        // Execução
        $exec1 = "cmd.exe" ascii nocase
        $exec2 = "powershell" ascii nocase
        
    condition:
        (filesize > 1KB and filesize < 100KB) and
        any of ($bumblebee_mark*) and
        ($reg_run and any of ($exec*))
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 8: META-REGRA - MUITO RESTRITIVA
// Requer IOC específico + UMA evidência adicionalsettings
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Confirmed_Detection {
    meta:
        description = "[VERSÃO 3.0] Detecção confirmada de Bumblebee - MUITO RESTRITIVA"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "3.0"
        family = "Bumblebee"
        severity = "critical"
        category = "general_detection"
        note = "REFINADO: Requer IOC Bumblebee MUITO ESPECÍFICO (domínio/hostname/param) + UMA regra de evidência"
        
    strings:
        // IOCs MUITO ESPECÍFICOS (não genéricos)
        $domain1 = "alwaysopen.studio" ascii nocase
        $domain2 = "mediaclickinc" ascii nocase
        $hostname = "WIN-G2YBXE8XMCG" ascii nocase
        $param = "ref=mediaclickinc" ascii nocase
        $gate_mark = "GATE" ascii nocase
        
        // IOCs desde a regra de IOCs
        $ioc1 = "ipmieh" ascii nocase
        $ioc2 = "bzuvnae" ascii nocase
        
    condition:
        // OBRIGATÓRIO: IOC Bumblebee MUITO específico
        (
            (any of ($domain*) and $hostname) or
            (any of ($domain*) and any of ($param, $gate_mark)) or
            ($hostname and any of ($domain*)) or
            (2 of ($ioc*))
        ) and
        // MAIS pelo menos UMA das regras específicas:
        (
            Bumblebee_Core_Network_Traffic_v3 or
            Bumblebee_Specific_IOCs or
            Bumblebee_Behavioral_C2_Communication or
            Bumblebee_LDAP_with_Bumblebee_Context or
            Bumblebee_SMB_with_Bumblebee_Context
        )
}
