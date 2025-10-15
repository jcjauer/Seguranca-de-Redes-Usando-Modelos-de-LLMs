/*
    REGRAS YARA CONSOLIDADAS PARA BUMBLEBEE MALWARE
    
    Este arquivo consolida todas as regras Bumblebee em um único módulo otimizado
    baseado em análise de tráfego real e IOCs coletados de múltiplas campanhas.
    
    CATEGORIES:
    ├── Network Traffic Analysis (regras baseadas em padrões de tráfego)
    ├── IOC Detection (indicadores específicos observados)
    ├── Behavioral Patterns (padrões comportamentais típicos)
    ├── Encryption & Obfuscation (técnicas de evasão)
    └── Post-Exploitation (movimento lateral e persistência)
    
    Autor: Sistema de Análise de Segurança Consolidado
    Data: 08/10/2025
    Versão: 2.0 Consolidated
    Referência: Análise de múltiplos PCAPs Bumblebee (2022-2025)
*/

import "math"

// ═══════════════════════════════════════════════════════════
// SEÇÃO 1: NETWORK TRAFFIC ANALYSIS
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Core_Network_Traffic {
    meta:
        description = "Detecta tráfego de rede principal do Bumblebee baseado em múltiplas campanhas"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "critical"
        category = "network_traffic"
        confidence = "high"
        
    strings:
        // Domínios C2 conhecidos de múltiplas campanhas
        $domain1 = "ALWAYSOPEN.STUDIO" nocase
        $domain2 = "alwaysopen.studio" nocase
        $domain3 = "mediaclickinc" nocase
        
        // Hostnames específicos observados
        $hostname1 = "WIN-G2YBXE8XMCG" nocase
        
        // LDAP reconnaissance (técnica principal do Bumblebee)
        $ldap1 = "objectclass" nocase
        $ldap2 = "subschemaSubentry" nocase
        $ldap3 = "dsServiceName" nocase
        $ldap4 = "namingContexts" nocase
        $ldap5 = "defaultNamingContext" nocase
        $ldap6 = "configurationNamingContext" nocase
        $ldap7 = "supportedCapabilities" nocase
        $ldap8 = "supportedLDAPVersion" nocase
        $ldap9 = "dnsHostName" nocase
        $ldap10 = "ldapServiceName" nocase
        
        // SMB/SMB2 exploitation patterns
        $smb1 = "NT LM 0.12" nocase
        $smb2 = "SMB 2.002" nocase
        $smb3 = "SMB 2.???" nocase
        $smb4 = { FE 53 4D 42 } // SMB2 signature
        
        // Group Policy abuse (movimento lateral)
        $gpo1 = "\\Policies\\" nocase
        $gpo2 = "Machine\\Registry.pol" nocase
        $gpo3 = "GptTmpl.inf" nocase
        $gpo4 = "gpt.ini" nocase
        $gpo5 = "SYSVOL" nocase
        $gpo6 = "NETLOGON" nocase
        
        // Gateway patterns (C2 communication)
        $gate1 = "GATE" nocase
        
    condition:
        (filesize > 1KB and filesize < 100MB) and
        (
            // Detecção forte: Domínio + LDAP reconnaissance
            (any of ($domain*) and 4 of ($ldap*)) or
            
            // Detecção moderada: SMB + GPO abuse
            (any of ($smb*) and 2 of ($gpo*)) or
            
            // Detecção por volume de LDAP queries (reconnaissance massivo)
            (6 of ($ldap*)) or
            
            // Detecção por hostname específico + qualquer técnica
            ($hostname1 and (any of ($ldap*) or any of ($smb*))) or
            
            // Detecção por gateway + técnicas
            ($gate1 and (2 of ($ldap*) or any of ($gpo*)))
        )
}

rule Bumblebee_LDAP_Advanced_Reconnaissance {
    meta:
        description = "Detecta reconnaissance LDAP avançado típico do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "high"
        category = "reconnaissance"
        
    strings:
        // LDAP queries avançadas
        $ldap_adv1 = "supportedSASLMechanisms" nocase
        $ldap_adv2 = "serverName" nocase
        $ldap_adv3 = "schemaUpdateNow" nocase
        $ldap_adv4 = "highestCommittedUSN" nocase
        
        // OIDs específicos do Active Directory
        $oid1 = "1.2.840.113556.1.4.800"  // AD_GUID_CONTAINERS
        $oid2 = "1.2.840.113556.1.4.1670" // AD_GUID_USERS  
        $oid3 = "1.2.840.113556.1.4.1791" // AD_GUID_COMPUTERS
        $oid4 = "1.2.840.113556.1.4.1935" // AD_GUID_GROUPS
        $oid5 = "1.3.6.1.4.1.1466.101.119.1" // LDAP_CONTROL_PAGED_RESULTS
        
        // Filtros LDAP suspeitos
        $filter1 = "objectCategory=person" nocase
        $filter2 = "objectCategory=computer" nocase
        $filter3 = "objectClass=group" nocase
        $filter4 = "adminCount=1" nocase
        
    condition:
        (filesize > 512 and filesize < 50KB) and
        (
            // Múltiplas queries avançadas
            (3 of ($ldap_adv*)) or
            
            // OIDs específicos + queries básicas
            (2 of ($oid*) and any of ($ldap_adv*)) or
            
            // Filtros específicos de enumeração
            (2 of ($filter*))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 2: IOC DETECTION (Indicadores Específicos)
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Specific_IOCs {
    meta:
        description = "IOCs específicos observados em campanhas Bumblebee reais"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
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
        $ioc6 = "zrmhjutbxjxck" ascii nocase
        $ioc7 = "fylmrxm" ascii nocase
        
        // Arquivos específicos de campanhas
        $file1 = "dj.js" ascii nocase
        $file2 = "index.php" ascii nocase
        $file3 = "jquery.min.js" ascii nocase
        
        // Parâmetros únicos observados
        $param1 = "ref=mediaclickinc" ascii nocase
        $param2 = "gate=" ascii nocase
        $param3 = "data=" ascii nocase
        
        // User-Agents específicos
        $ua1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" ascii
        $ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        
    condition:
        // Qualquer IOC específico é evidência forte
        any of ($ioc*) or
        
        // Combinação de arquivos suspeitos
        ($file1 and $file3) or
        ($file2 and any of ($param*)) or
        
        // User-Agent + parâmetros
        (any of ($ua*) and any of ($param*))
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 3: BEHAVIORAL PATTERNS
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Behavioral_C2_Communication {
    meta:
        description = "Padrões comportamentais específicos de comunicação C2 do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.1"
        family = "Bumblebee"
        severity = "high"
        category = "behavioral"
        
    strings:
        // Padrões HTTP específicos do Bumblebee (não genéricos)
        $bumblebee_post = "POST /" ascii
        $bumblebee_get = "GET /" ascii
        
        // Domínios C2 específicos do Bumblebee
        $c2_domain1 = "alwaysopen.studio" ascii nocase
        $c2_domain2 = "mediaclickinc" ascii nocase
        
        // Headers específicos observados no Bumblebee
        $ua_bumblebee = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" ascii
        
        // Padrões específicos de payload Bumblebee
        $bumblebee_gate = "GATE" ascii nocase
        $bumblebee_param1 = "ref=mediaclickinc" ascii nocase
        $bumblebee_param2 = "gate=" ascii nocase
        
        // Strings específicas de comando Bumblebee
        $cmd_bumblebee1 = "WIN-G2YBXE8XMCG" ascii nocase
        $cmd_bumblebee2 = "Policies" ascii nocase
        
        // JSON específico com contexto Bumblebee
        $json_cmd = "\"cmd\":" ascii
        $json_gate = "\"gate\":" ascii
        
    condition:
        (filesize > 1KB and filesize < 1MB) and
        (
            // HTTP + domínio específico Bumblebee (alta confiança)
            ((any of ($bumblebee_post, $bumblebee_get)) and any of ($c2_domain*)) or
            
            // HTTP + parâmetros específicos Bumblebee
            ((any of ($bumblebee_post, $bumblebee_get)) and any of ($bumblebee_param*)) or
            
            // User-Agent específico + qualquer padrão Bumblebee
            ($ua_bumblebee and (any of ($bumblebee_gate, $cmd_bumblebee*))) or
            
            // JSON com contexto específico Bumblebee
            (any of ($json_cmd, $json_gate) and any of ($c2_domain*, $bumblebee_gate)) or
            
            // Múltiplos indicadores específicos Bumblebee
            (any of ($bumblebee_gate, $cmd_bumblebee*) and any of ($bumblebee_param*))
        )
}

rule Bumblebee_SMB_Lateral_Movement_Advanced {
    meta:
        description = "Movimento lateral avançado via SMB do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "high"
        category = "lateral_movement"
        
    strings:
        // SMB2/3 headers
        $smb_header = { FE 53 4D 42 } // SMB2 signature
        
        // SAMR (Security Account Manager Remote) abuse
        $samr1 = "samr" ascii nocase
        $samr2 = "SamrConnect" ascii nocase
        $samr3 = "SamrEnumerateUsersInDomain" ascii nocase
        
        // Named pipes abuse
        $pipe1 = "\\pipe\\samr" ascii nocase
        $pipe2 = "\\pipe\\lsarpc" ascii nocase
        $pipe3 = "\\pipe\\netlogon" ascii nocase
        
        // Registry operations via SMB
        $reg1 = "HKEY_LOCAL_MACHINE" ascii nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii nocase
        $reg3 = "SYSTEM\\CurrentControlSet" ascii nocase
        
    condition:
        (filesize > 2KB and filesize < 500KB) and
        $smb_header and
        (
            // SAMR enumeration
            any of ($samr*) or
            
            // Named pipes abuse
            any of ($pipe*) or
            
            // Registry manipulation
            (2 of ($reg*))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 4: ENCRYPTION & OBFUSCATION
// ═══════════════════════════════════════════════════════════

rule Bumblebee_High_Entropy_Encrypted_Payload {
    meta:
        description = "Detecta payloads criptografados/obfuscados específicos do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.1"
        family = "Bumblebee"
        severity = "medium"
        category = "encryption"
        
    strings:
        // Padrões específicos encontrados em streams Bumblebee reais
        $bumblebee_entropy1 = { 5B 51 ?? 4B ?? ?? 4F ?? ?? ?? }
        $bumblebee_entropy2 = "not_defined_in_RFC4178@please_ignore" ascii
        
        // TLS patterns específicos + domínios Bumblebee
        $tls1 = { 16 03 ?? ?? ?? } // TLS handshake
        $tls2 = { 17 03 ?? ?? ?? } // TLS application data
        
        // Certificados específicos Bumblebee
        $cert_bumblebee1 = "alwaysopen.studio" ascii nocase
        $cert_bumblebee2 = "mediaclickinc" ascii nocase
        
        // Crypto patterns específicos + contexto Bumblebee
        $crypto_bumblebee = { 30 ?? ?? ?? ?? ?? 2A 48 ?? ?? ?? ?? 2A 48 ?? ?? ?? ?? }
        
        // Strings específicas do Bumblebee (não genéricas)
        $bumblebee_string1 = "GATE" ascii nocase
        $bumblebee_string2 = "WIN-G2YBXE8XMCG" ascii nocase
        
    condition:
        (filesize > 5KB and filesize < 50KB) and
        (
            // Padrões específicos do Bumblebee (não genéricos)
            (#bumblebee_entropy1 >= 3 and any of ($bumblebee_string*)) or 
            
            // TLS com certificado específico Bumblebee
            (any of ($tls*) and any of ($cert_bumblebee*)) or
            
            // Crypto patterns + strings específicas Bumblebee
            ($crypto_bumblebee and $bumblebee_entropy2) or
            
            // Alta entropia APENAS com contexto Bumblebee específico
            (math.entropy(0, filesize) >= 7.5 and filesize >= 15KB and any of ($bumblebee_string*))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 5: POST-EXPLOITATION & PERSISTENCE
// ═══════════════════════════════════════════════════════════

rule Bumblebee_Registry_Persistence_Mechanisms {
    meta:
        description = "Mecanismos de persistência via registro do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "high"
        category = "persistence"
        
    strings:
        // Registry persistence locations
        $reg_run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg_run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
        $reg_services = "SYSTEM\\CurrentControlSet\\Services" ascii nocase
        
        // Scheduled tasks
        $sched1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule" ascii nocase
        $sched2 = "TaskCache" ascii nocase
        
        // WMI persistence
        $wmi1 = "ROOT\\cimv2" ascii nocase
        $wmi2 = "Win32_Process" ascii nocase
        $wmi3 = "__EventFilter" ascii nocase
        
        // Common persistence names
        $name1 = "WindowsUpdate" ascii nocase
        $name2 = "SecurityUpdate" ascii nocase
        $name3 = "SystemUpdate" ascii nocase
        
    condition:
        (filesize > 1KB and filesize < 100KB) and
        (
            // Registry Run keys
            (any of ($reg_run*) and any of ($name*)) or
            
            // Services persistence
            ($reg_services and any of ($name*)) or
            
            // Scheduled tasks
            (any of ($sched*) and any of ($name*)) or
            
            // WMI persistence
            (2 of ($wmi*))
        )
}

rule Bumblebee_Process_Injection_Patterns {
    meta:
        description = "Padrões de injeção de processo do Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "high"
        category = "process_injection"
        
    strings:
        // API calls para process injection
        $api1 = "OpenProcess" ascii
        $api2 = "VirtualAllocEx" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "CreateRemoteThread" ascii
        $api5 = "SetThreadContext" ascii
        $api6 = "ResumeThread" ascii
        
        // Process hollowing patterns
        $hollow1 = "NtUnmapViewOfSection" ascii
        $hollow2 = "ZwUnmapViewOfSection" ascii
        
        // Target processes
        $target1 = "explorer.exe" ascii nocase
        $target2 = "svchost.exe" ascii nocase
        $target3 = "winlogon.exe" ascii nocase
        $target4 = "csrss.exe" ascii nocase
        
    condition:
        (filesize > 2KB and filesize < 200KB) and
        (
            // Classic DLL injection
            (3 of ($api1, $api2, $api3, $api4)) or
            
            // Process hollowing
            (any of ($hollow*) and 2 of ($api*)) or
            
            // Thread context manipulation
            ($api5 and $api6 and any of ($target*))
        )
}

// ═══════════════════════════════════════════════════════════
// SEÇÃO 6: META-RULE (Detecção Geral)
// ═══════════════════════════════════════════════════════════

rule Bumblebee_General_Detection {
    meta:
        description = "Regra geral que combina múltiplos indicadores Bumblebee"
        author = "Security Analysis System"
        date = "2025-10-08"
        version = "2.0"
        family = "Bumblebee"
        severity = "medium"
        category = "general_detection"
        
    condition:
        // Ativa se 2 ou mais regras específicas detectarem
        (
            Bumblebee_Core_Network_Traffic or
            Bumblebee_Specific_IOCs or
            Bumblebee_LDAP_Advanced_Reconnaissance
        ) and
        (
            Bumblebee_Behavioral_C2_Communication or
            Bumblebee_SMB_Lateral_Movement_Advanced or
            Bumblebee_High_Entropy_Encrypted_Payload or
            Bumblebee_Registry_Persistence_Mechanisms or
            Bumblebee_Process_Injection_Patterns
        )
}