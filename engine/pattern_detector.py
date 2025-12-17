from typing import List, Dict, Tuple, Set
from collections import Counter
import math
from dataclasses import dataclass

@dataclass
class DetectedPattern:
    offset: int
    length: int
    pattern_bytes: bytes
    pattern_type: str
    confidence: float
    description: str

class PatternDetector:
    SHELLCODE_IDIOMS = {
        'ror13_api_hash': (b'\x41\xc1\xc9\x0d', 'ROR 13 API hashing (Cobalt Strike style)'),
        'ror7_api_hash': (b'\xc1\xc9\x07', 'ROR 7 API hashing'),
        'djb2_multiply': (b'\x6b\xc0\x21', 'DJB2 hash multiply by 33'),
        'getpc_call': (b'\xe8\x00\x00\x00\x00', 'Get PC via CALL $+5'),
        'getpc_fpu': (b'\xd9\xee\xd9\x74\x24\xf4', 'Get PC via FPU'),
        'peb_x64': (b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00', 'PEB access x64 (gs:[0x60])'),
        'peb_x86': (b'\x64\x8b\x35\x30\x00\x00\x00', 'PEB access x86 (fs:[0x30])'),
        'syscall': (b'\x0f\x05', 'Syscall instruction'),
        'sysenter': (b'\x0f\x34', 'Sysenter instruction'),
        'int_2e': (b'\xcd\x2e', 'INT 0x2E (legacy syscall)'),
        'xor_key_loop': (b'\x30\x0c', 'XOR decryption loop pattern'),
        'stack_string_push': (b'\x68', 'Stack string construction (PUSH immediate)'),
        'ws2_32': (b'ws2_32', 'ws2_32.dll string'),
        'wininet': (b'wininet', 'wininet.dll string'),
        'kernel32': (b'kernel32', 'kernel32.dll string'),
        'ntdll': (b'ntdll', 'ntdll.dll string'),
        'virtualalloc': (b'VirtualAlloc', 'VirtualAlloc string'),
        'loadlibrary': (b'LoadLibrary', 'LoadLibrary string'),
        'getprocaddress': (b'GetProcAddress', 'GetProcAddress string'),
        'beacon_config': (b'\x00\x01\x00\x01\x00\x02', 'Beacon config marker'),
        'mz_header': (b'MZ', 'PE/DOS header'),
        'pe_signature': (b'PE\x00\x00', 'PE signature'),
    }
    
    SUSPICIOUS_ENTROPY_THRESHOLD = 7.0
    NGRAM_MIN_LENGTH = 8
    NGRAM_MAX_LENGTH = 32
    
    def __init__(self):
        self.detected_patterns = []
    
    def detect_all(self, data: bytes) -> List[DetectedPattern]:
        self.detected_patterns = []
        self._detect_known_idioms(data)
        self._detect_repeated_sequences(data)
        self._detect_high_entropy_regions(data)
        self._detect_suspicious_ngrams(data)
        return sorted(self.detected_patterns, key=lambda x: x.confidence, reverse=True)
    
    def _detect_known_idioms(self, data: bytes):
        for idiom_name, (pattern, description) in self.SHELLCODE_IDIOMS.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                self.detected_patterns.append(DetectedPattern(
                    offset=pos,
                    length=len(pattern),
                    pattern_bytes=pattern,
                    pattern_type='known_idiom',
                    confidence=1.0,
                    description=f"{idiom_name}: {description}"
                ))
                offset = pos + 1
    
    def _detect_repeated_sequences(self, data: bytes, min_occurrences: int = 2):
        for length in range(self.NGRAM_MIN_LENGTH, min(self.NGRAM_MAX_LENGTH, len(data) // 2)):
            seen = {}
            for i in range(len(data) - length + 1):
                seq = data[i:i+length]
                if seq in seen:
                    seen[seq].append(i)
                else:
                    seen[seq] = [i]
            
            for seq, offsets in seen.items():
                if len(offsets) >= min_occurrences:
                    entropy = self._calculate_entropy(seq)
                    if entropy > 3.0:
                        self.detected_patterns.append(DetectedPattern(
                            offset=offsets[0],
                            length=length,
                            pattern_bytes=seq,
                            pattern_type='repeated_sequence',
                            confidence=min(0.9, 0.5 + (len(offsets) * 0.1)),
                            description=f"Repeated {len(offsets)} times (signature candidate)"
                        ))
    
    def _detect_high_entropy_regions(self, data: bytes, window_size: int = 64):
        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i:i+window_size]
            entropy = self._calculate_entropy(window)
            if entropy > self.SUSPICIOUS_ENTROPY_THRESHOLD:
                self.detected_patterns.append(DetectedPattern(
                    offset=i,
                    length=window_size,
                    pattern_bytes=window[:16],
                    pattern_type='high_entropy',
                    confidence=min(0.8, (entropy - 7.0) / 1.0),
                    description=f"High entropy region ({entropy:.2f} bits/byte) - possible encoded data"
                ))
    
    def _detect_suspicious_ngrams(self, data: bytes):
        common_shellcode_ngrams = [
            b'\xfc\x48\x83\xe4\xf0',
            b'\x48\x31\xc0\xac',
            b'\x41\x51\x41\x50',
            b'\x48\x89\xe5',
            b'\x4d\x5a\x41\x52\x55',
            b'\x31\xc0\x50\x68',
            b'\x89\xe5\x31\xc0',
        ]
        
        for ngram in common_shellcode_ngrams:
            offset = 0
            while True:
                pos = data.find(ngram, offset)
                if pos == -1:
                    break
                self.detected_patterns.append(DetectedPattern(
                    offset=pos,
                    length=len(ngram),
                    pattern_bytes=ngram,
                    pattern_type='suspicious_ngram',
                    confidence=0.85,
                    description=f"Common shellcode n-gram at offset {pos}"
                ))
                offset = pos + 1
    
    def _calculate_entropy(self, data: bytes) -> float:
        if len(data) == 0:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return entropy
    
    def get_transformation_targets(self, data: bytes, min_confidence: float = 0.5) -> List[Tuple[int, int]]:
        patterns = self.detect_all(data)
        targets = []
        covered = set()
        
        for pattern in patterns:
            if pattern.confidence >= min_confidence:
                range_start = pattern.offset
                range_end = pattern.offset + pattern.length
                is_covered = any(start <= range_start < end for start, end in covered)
                if not is_covered:
                    targets.append((range_start, range_end))
                    covered.add((range_start, range_end))
        
        return sorted(targets)
    
    def analyze(self, data: bytes) -> Dict:
        patterns = self.detect_all(data)
        overall_entropy = self._calculate_entropy(data)
        
        return {
            'size': len(data),
            'overall_entropy': overall_entropy,
            'pattern_count': len(patterns),
            'patterns_by_type': self._group_by_type(patterns),
            'high_confidence_patterns': [p for p in patterns if p.confidence >= 0.8],
            'transformation_targets': self.get_transformation_targets(data)
        }
    
    def _group_by_type(self, patterns: List[DetectedPattern]) -> Dict[str, int]:
        groups = {}
        for pattern in patterns:
            if pattern.pattern_type not in groups:
                groups[pattern.pattern_type] = 0
            groups[pattern.pattern_type] += 1
        return groups
