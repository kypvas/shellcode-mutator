import os
import yara
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    strings: List[Dict]
    meta: Dict

class YaraScanner:
    DEFAULT_RULES_DIR = Path(__file__).parent.parent / 'rules'
    
    PUBLIC_RULE_URLS = [
        'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_metasploit_payloads.yar',
        'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_cobaltstrike.yar',
        'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_cobaltstrike.yar',
    ]
    
    BUILTIN_RULES = r'''
rule Shellcode_Common_Patterns {
    meta:
        description = "Detects common shellcode patterns"
    strings:
        $api_hash_ror13 = { 41 C1 C? 0D }
        $api_hash_ror7 = { C1 C? 07 }
        $getpc_call = { E8 00 00 00 00 }
        $getpc_fpu = { D9 EE D9 74 24 F4 }
        $kernel32_hash = { 6A 30 59 64 8B }
        $peb_access_x64 = { 65 48 8B 04 25 60 00 00 00 }
        $peb_access_x86 = { 64 8B 35 30 00 00 00 }
        $syscall_x64 = { 0F 05 }
        $int_2e = { CD 2E }
    condition:
        any of them
}

rule Shellcode_Reflective_Loader {
    meta:
        description = "Detects reflective DLL loader patterns"
    strings:
        $mz_header = { 4D 5A }
        $pe_sig = { 50 45 00 00 }
        $reflective_call = { E8 ?? ?? ?? ?? 58 }
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz_header at 0 or any of them
}

rule Shellcode_Cobalt_Strike_Indicators {
    meta:
        description = "Detects Cobalt Strike shellcode indicators"
    strings:
        $beacon_config = { 00 01 00 01 00 02 }
        $sleep_mask = { 48 8B 44 24 08 48 89 44 }
        $pipe_default = "\\\\.\\pipe\\msagent_"
        $beacon_dll = "beacon.dll"
        $beacon_x64 = { FC 48 83 E4 F0 E8 }
        $beacon_x86 = { FC E8 ?? 00 00 00 }
    condition:
        any of them
}

rule Shellcode_Metasploit_Indicators {
    meta:
        description = "Detects Metasploit shellcode indicators"
    strings:
        $shikata = { D9 74 24 F4 5? }
        $meterpreter = "metsrv"
        $reverse_tcp = { 6A 10 56 57 }
        $bind_tcp = { 6A 02 6A 01 6A 06 }
        $rc4_loop = { 30 0C ?? 4? }
    condition:
        any of them
}

rule Shellcode_API_Hashing {
    meta:
        description = "Detects API hashing techniques"
    strings:
        $djb2_hash = { 6B C0 21 }
        $ror13_loop = { 41 C1 C9 0D 41 01 C1 }
        $crc32_init = { 35 20 83 B8 ED }
        $sdbm_hash = { C1 E0 06 01 C8 }
    condition:
        any of them
}
'''
    
    def __init__(self, rules_dir: Optional[str] = None, include_builtin: bool = True):
        self.rules_dir = Path(rules_dir) if rules_dir else self.DEFAULT_RULES_DIR
        self.compiled_rules = []
        self.include_builtin = include_builtin
        self._load_rules()
    
    def _load_rules(self):
        if self.include_builtin:
            try:
                builtin = yara.compile(source=self.BUILTIN_RULES)
                self.compiled_rules.append(('builtin', builtin))
            except yara.Error as e:
                print(f"Warning: Failed to compile builtin rules: {e}")
        
        if self.rules_dir.exists():
            for rule_file in self.rules_dir.glob('*.yar'):
                try:
                    compiled = yara.compile(filepath=str(rule_file))
                    self.compiled_rules.append((rule_file.stem, compiled))
                except yara.Error as e:
                    print(f"Warning: Failed to compile {rule_file}: {e}")
            
            for rule_file in self.rules_dir.glob('*.yara'):
                try:
                    compiled = yara.compile(filepath=str(rule_file))
                    self.compiled_rules.append((rule_file.stem, compiled))
                except yara.Error as e:
                    print(f"Warning: Failed to compile {rule_file}: {e}")
    
    def scan(self, data: bytes) -> List[YaraMatch]:
        matches = []
        for namespace, rules in self.compiled_rules:
            try:
                rule_matches = rules.match(data=data)
                for match in rule_matches:
                    strings_info = []
                    for string_match in match.strings:
                        for instance in string_match.instances:
                            strings_info.append({
                                'identifier': string_match.identifier,
                                'offset': instance.offset,
                                'data': bytes(instance.matched_data),
                                'length': instance.matched_length
                            })
                    
                    matches.append(YaraMatch(
                        rule_name=match.rule,
                        namespace=namespace,
                        tags=list(match.tags),
                        strings=strings_info,
                        meta=dict(match.meta)
                    ))
            except yara.Error as e:
                print(f"Warning: Scan error with {namespace}: {e}")
        return matches
    
    def get_matched_offsets(self, data: bytes) -> Dict[str, List[Tuple[int, int, bytes]]]:
        result = {}
        matches = self.scan(data)
        for match in matches:
            if match.rule_name not in result:
                result[match.rule_name] = []
            for string_info in match.strings:
                result[match.rule_name].append((
                    string_info['offset'],
                    string_info['length'],
                    string_info['data']
                ))
        return result
    
    def scan_file(self, filepath: str) -> List[YaraMatch]:
        with open(filepath, 'rb') as f:
            return self.scan(f.read())
    
    def add_rule_file(self, filepath: str):
        try:
            compiled = yara.compile(filepath=filepath)
            self.compiled_rules.append((Path(filepath).stem, compiled))
        except yara.Error as e:
            raise ValueError(f"Failed to compile rule file: {e}")
    
    def add_rule_source(self, source: str, namespace: str = 'custom'):
        try:
            compiled = yara.compile(source=source)
            self.compiled_rules.append((namespace, compiled))
        except yara.Error as e:
            raise ValueError(f"Failed to compile rule source: {e}")
    
    def get_signature_bytes(self, data: bytes) -> List[Tuple[int, bytes, str]]:
        signatures = []
        matched = self.get_matched_offsets(data)
        for rule_name, offsets in matched.items():
            for offset, length, matched_bytes in offsets:
                signatures.append((offset, matched_bytes, rule_name))
        return sorted(signatures, key=lambda x: x[0])
