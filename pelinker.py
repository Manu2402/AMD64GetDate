from os import linesep
import struct
import sys
import time

SECTION_EXECUTABLE = 0x20000020
SECTION_READABLE = 0x40000000
SECTION_WRITABLE = 0x80000000
SECTION_DISCARDABLE = 0x02000000


def align(value, alignment):
    r = value % alignment
    if r > 0:
        return value + (alignment - r)
    return value


def pad(data, size):
    return data.ljust(size, b"\0")


def pad_align(data, alignment):
    return pad(data, align(len(data), alignment))


def le32(*args):
    data = b""
    for arg in args:
        data += struct.pack("<I", arg)
    return data


def le16(*args):
    data = b""
    for arg in args:
        data += struct.pack("<H", arg)
    return data


def le64(*args):
    data = b""
    for arg in args:
        data += struct.pack("<Q", arg)
    return data


def permissions_str(permissions):
    permissions_string = ""
    if permissions & SECTION_READABLE:
        permissions_string += "r"
    if permissions & SECTION_WRITABLE:
        permissions_string += "w"
    if permissions & SECTION_EXECUTABLE:
        permissions_string += "x"
    if permissions & SECTION_DISCARDABLE:
        permissions_string += "d"
    return permissions_string


class Section:
    def __init__(self, name, rva, permissions):
        self.name = name
        self.rva = rva
        self.content = None
        self.relocation_symbols = []
        if isinstance(permissions, str):
            permissions_map = {
                "r": SECTION_READABLE,
                "w": SECTION_WRITABLE,
                "x": SECTION_EXECUTABLE,
                "d": SECTION_DISCARDABLE,
            }
            self.permissions = 0
            for character in permissions.lower():
                if character in permissions_map:
                    self.permissions |= permissions_map[character]
                else:
                    raise Exception("unknown section permissions mask")
        else:
            self.permissions = permissions

        self.symbols = {}

    def add_relocation_symbol(self, symbol, offset, relocation_type=4):
        self.relocation_symbols.append((symbol, offset, relocation_type))

    def add_symbol(self, name, value):
        self.symbols[name] = value


class Symbol:
    def __init__(self, name, rva):
        self.name = name
        self.rva = rva

    def __eq__(self, other):
        return self.name == other.name and self.rva == other.rva


class ImportLibrary:
    def __init__(self, libname, symbols):
        self.libname = libname
        if isinstance(symbols, str):
            raise Exception("ImportLibrary expects an iterable of strings")
        if not symbols:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.LoadLibraryExW.restype = wintypes.HMODULE
            kernel32.LoadLibraryExW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.HANDLE,
                wintypes.DWORD,
            )
            kernel32.FreeLibrary.restype = wintypes.BOOL
            kernel32.FreeLibrary.argtypes = (wintypes.HMODULE,)

            kernel32.GetModuleFileNameW.restype = wintypes.DWORD
            kernel32.GetModuleFileNameW.argtypes = (
                wintypes.HMODULE,
                wintypes.LPWSTR,
                wintypes.DWORD,
            )

            h_module = kernel32.LoadLibraryExW(libname, None, 0)
            if not h_module:
                raise Exception("Unable to load library {0}".format(libname))
            unicode_filename = ctypes.create_unicode_buffer(0x1000)
            kernel32.GetModuleFileNameW(h_module, unicode_filename, 0x1001)

            if not unicode_filename.value:
                raise Exception(
                    "Unable to retrieve library path for {0}".format(libname)
                )

            with open(unicode_filename.value, "rb") as handle:
                data = handle.read()

            kernel32.FreeLibrary(h_module)

            symbols = []

            # get PE header
            (offset,) = struct.unpack("<I", data[0x3C:0x40])
            offset += 4
            (number_of_sections,) = struct.unpack("<H", data[offset + 2 : offset + 4])
            offset += 20

            # get Import Table offset
            (import_table_virtual_address,) = struct.unpack(
                "<I", data[offset + 112 : offset + 116]
            )
            # sections
            offset += 240
            sections = []
            for _ in range(0, number_of_sections):
                (virtual_address,) = struct.unpack(
                    "<I", data[offset + 12 : offset + 16]
                )
                (ptr_to_raw_data,) = struct.unpack(
                    "<I", data[offset + 20 : offset + 24]
                )
                sections.append((virtual_address, ptr_to_raw_data))
                offset += 40

            self.sections = sorted(sections, key=lambda x: x[0])

            best_section = self._get_section_by_address(import_table_virtual_address)

            edata_offset = best_section[1] + (
                import_table_virtual_address - best_section[0]
            )

            number_of_entries, number_of_names = struct.unpack(
                "<II", data[edata_offset + 20 : edata_offset + 28]
            )

            offset = edata_offset + 40 + (4 * number_of_entries)

            for _ in range(0, number_of_names):
                (symbol_address,) = struct.unpack("<I", data[offset : offset + 4])
                name_section, name_ptr = self._get_section_by_address(symbol_address)
                name_offset = name_ptr + (symbol_address - name_section)
                symbols.append(self._get_cstring(data, name_offset).decode())
                offset += 4

        self.symbols = symbols

    def _get_section_by_address(self, address):
        # find export section
        best_section = None
        for section_address, section_data_offset in self.sections:
            if address >= section_address:
                best_section = section_address, section_data_offset
        return best_section

    def _get_cstring(self, data, offset):
        final = b""
        while True:
            byte = data[offset]
            if byte == 0:
                return final
            final += bytes((byte,))
            offset += 1


class Image:
    def __init__(self, image_base, characteristics=0x22):
        self.image_base = image_base
        self.alignment = 0x1000
        self.file_alignment = 0x200
        self.characteristics = characteristics
        self.entry_point = self.alignment
        self.export_table = (0, 0)
        self.import_table = (0, 0)
        self.relocation_table = (0, 0)
        self.sections = []
        self.symbols = []
        self.imports = []
        self.relocations = []
        self.iat_map = {}
        self.plt = None
        self.show_iat = True
        self.show_patched_rva = True
        self.use_plt = False
        self.minimal_import = False
        self.join_sections = False

    def get_executable_sections_size(self):
        total = 0
        for section in self.sections:
            if section.content and section.permissions & SECTION_EXECUTABLE:
                total += align(
                    len(section.content),
                    self.alignment,
                )
        return total

    def get_initialized_sections_size(self):
        total = 0
        for section in self.sections:
            if (
                section.content
                and (
                    (section.permissions & SECTION_WRITABLE)
                    or (section.permissions & SECTION_READABLE)
                )
                and not (section.permissions & SECTION_EXECUTABLE)
                and not isinstance(section.content, int)
            ):
                total += align(
                    len(section.content),
                    self.alignment,
                )
        return total

    def get_uninitialized_sections_size(self):
        total = 0
        for section in self.sections:
            if (
                section.content
                and (
                    (section.permissions & SECTION_WRITABLE)
                    or (section.permissions & SECTION_READABLE)
                )
                and not (section.permissions & SECTION_EXECUTABLE)
                and isinstance(section.content, int)
            ):
                total += align(
                    section.content,
                    self.alignment,
                )
        return total

    def get_sections_aligned_size(self):
        total = 0
        for section in self.sections:
            if section.content:
                total += align(
                    len(section.content)
                    if not isinstance(section.content, int)
                    else section.content,
                    self.alignment,
                )
        return total

    def get_text_base(self):
        for section in self.sections:
            if section.content and section.permissions & SECTION_EXECUTABLE:
                return section.rva
        return 0

    def _get_next_section_rva(self):
        if self.sections:
            last_section = self.sections[-1]
            if last_section.content:
                return last_section.rva + align(
                    len(last_section.content)
                    if not isinstance(last_section.content, int)
                    else last_section.content,
                    self.alignment,
                )
            else:
                raise Exception("Section {0} has no size!".format(last_section.name))

        return self.alignment

    def add_section(self, name, permissions, content=None):
        rva = self._get_next_section_rva()
        section = Section(name, rva, permissions)
        section.content = content
        self.sections.append(section)
        return section

    def _append_edata_section(self):
        if not self.symbols:
            return

        section = self.add_section(".edata", "r")

        strings_data = b""
        offset = 0
        offsets = []
        for symbol in self.symbols:
            ascii_data = symbol.name.encode("ascii")
            strings_data += ascii_data + b"\0"
            offsets.append(offset)
            offset = len(strings_data)

        strings_base = section.rva + 40 + len(self.symbols) * 10

        section.content = le32(0)
        section.content += le32(int(time.time()))
        section.content += le16(0, 0)
        # points to an empty string
        section.content += le32(strings_base + offset - 1)
        section.content += le32(1)  # Ordinal Base
        section.content += le32(len(self.symbols))
        section.content += le32(len(self.symbols))
        section.content += le32(section.rva + 40)  # Export Address Table RVA
        # Name Pointer RVA
        section.content += le32(section.rva + 40 + len(self.symbols) * 4)
        # Ordinal Table RVA
        section.content += le32(section.rva + 40 + len(self.symbols) * 8)

        for symbol in self.symbols:
            section.content += le32(symbol.rva)

        for index, symbol in enumerate(self.symbols):
            section.content += le32(strings_base + offsets[index])

        for index, symbol in enumerate(self.symbols):
            section.content += le16(index)

        section.content += strings_data

        self.export_table = (
            section.rva,
            len(section.content),
        )

    def get_symbol_rva(self, symbol_name):
        for section in self.sections:
            for symbol in section.symbols:
                if symbol == symbol_name:
                    return section.rva + section.symbols[symbol]
        raise Exception("Unable to find symbol {0}".format(symbol_name))

    def _append_idata_section(self):
        self.iat_map = {}

        if not self.imports:
            return

        section = self.add_section(".idata", "r")

        if self.minimal_import:
            required_symbols = set()
            for section in self.sections:
                for reloc_name, _, _ in section.relocation_symbols:
                    required_symbols.add(reloc_name)
            for libimport in self.imports:
                symbols = []
                for symbol in libimport.symbols:
                    if symbol in required_symbols:
                        symbols.append(symbol)
                libimport.symbols = symbols

        strings_data = b""
        offset = 0
        offsets = []
        libname_offsets = []
        for libimport in self.imports:
            ascii_data = libimport.libname.encode("ascii")
            strings_data += ascii_data + b"\0"
            libname_offsets.append(offset)
            offset = len(strings_data)
            for symbol in libimport.symbols:
                ascii_data = symbol.encode("ascii") + b"\0"
                additional = b""
                if len(ascii_data) % 2 != 0:
                    additional = b"\0"
                strings_data += le16(0) + ascii_data + additional
                offsets.append(offset)
                offset = len(strings_data)

        section.content = b""

        directory_tables_size = (len(self.imports) + 1) * 20
        import_lookup_tables_size = (
            sum([(len(libimport.symbols) + 1) for libimport in self.imports]) * 8
        )
        import_address_tables_size = import_lookup_tables_size
        strings_data_index = (
            section.rva
            + directory_tables_size
            + import_lookup_tables_size
            + import_address_tables_size
        )

        entries = []
        symbols_counter = 0
        for libimport in self.imports:
            entries.append(symbols_counter)
            symbols_counter += (len(libimport.symbols) + 1) * 8

        for index, libimport in enumerate(self.imports):
            section.content += le32(
                section.rva + directory_tables_size + entries[index]
            )
            section.content += le32(0)
            section.content += le32(0)
            section.content += le32(strings_data_index + libname_offsets[index])
            section.content += le32(
                section.rva
                + directory_tables_size
                + import_lookup_tables_size
                + entries[index]
            )

        # end of import directory table
        section.content += le32(0, 0, 0, 0, 0)

        string_index = 0
        for libimport in self.imports:
            for symbol in libimport.symbols:
                section.content += le64(strings_data_index + offsets[string_index])
                string_index += 1
            section.content += le64(0)

        string_index = 0
        for libimport in self.imports:
            for symbol in libimport.symbols:
                symbol_rva = section.rva + len(section.content)
                if self.show_iat:
                    print(
                        "Added IAT for {1}@{0} for RVA 0x{2:08X}".format(
                            libimport.libname, symbol, symbol_rva
                        )
                    )
                self.iat_map[symbol] = (libimport.libname, symbol_rva)
                section.content += le64(strings_data_index + offsets[string_index])
                string_index += 1
            section.content += le64(0)

        section.content += strings_data

        if self.use_plt:
            self.plt = self.add_section(".plt", "rx", b"")

        self.import_table = (
            section.rva,
            len(section.content),
        )

    def _patch_section_symbol(
        self,
        section,
        symbol_name,
        relocation_offset,
        relocation_type,
        symbol_rva,
        symbol_full_name=None,
    ):
        if symbol_full_name is None:
            symbol_full_name = symbol_name

        if not section.content:
            return

        struct_format = "<i"
        struct_size = 4
        if relocation_type == 4:
            relative_relocation = symbol_rva - (section.rva + relocation_offset) - 4
        elif relocation_type == 2:
            relative_relocation = self.image_base + symbol_rva
        elif relocation_type == 3:
            relative_relocation = symbol_rva
        elif relocation_type == 1:
            relative_relocation = self.image_base + symbol_rva
            struct_format = "<q"
            struct_size = 8
        elif relocation_type == 0:
            return
        else:
            raise Exception(
                "Unsupported relocation type {0} for {1}".format(
                    hex(relocation_type), symbol_full_name
                )
            )
        user_section_content = bytearray(section.content)
        original_value = struct.unpack(
            struct_format,
            user_section_content[relocation_offset : relocation_offset + struct_size],
        )[0]

        user_section_content[
            relocation_offset : relocation_offset + struct_size
        ] = struct.pack(struct_format, relative_relocation + original_value)
        section.content = user_section_content
        if self.show_patched_rva:
            print(
                "Patched RVA 0x{0:08X} with {1} from 0x{2:016X} to 0x{3:016X}".format(
                    section.rva + relocation_offset,
                    symbol_full_name,
                    original_value,
                    relative_relocation + original_value,
                )
            )

    def has_section(self, name):
        for section in self.sections:
            if section.name == name:
                return True
        return False

    def get_section(self, name):
        for section in self.sections:
            if section.name == name:
                return section

    def has_known_section_symbol(self, name):
        for section in self.sections:
            if name in section.symbols:
                return True
        return False

    def get_known_section_symbol(self, name):
        for section in self.sections:
            if name in section.symbols:
                return section.symbols[name], section

    def _append_reloc_section(self):
        if not self.relocations:
            return

        section = self.add_section(".reloc", "rd")

        # build the pages list
        pages = {}
        for relocation in self.relocations:
            page = relocation & 0xFFFFFFFFFFF000
            offset = relocation & 0xFFF
            if not page in pages:
                pages[page] = []
            pages[page].append(offset)

        section.content = b""

        sorted_pages = sorted(pages.keys())

        for sorted_page in sorted_pages:
            offsets = pages[sorted_page]
            block = b""
            for offset in offsets:
                block += le16(offset | 0x0A << 12)
            section.content += le32(sorted_page & 0xFFFFFFFF)
            section.content += le32(len(block) + 8)
            section.content += block

        self.relocation_table = (section.rva, len(section.content))

    def export_symbol(self, name, rva):
        symbol = Symbol(name, rva)
        if not symbol in self.symbols:
            self.symbols.append(symbol)
        return symbol

    def import_symbols(self, libname, symbols=None):
        importlib = ImportLibrary(libname, symbols)
        self.imports.append(importlib)
        return importlib

    def _patch_relocations(self):
        for section in self.sections:
            for reloc_name, reloc_offset, reloc_type in section.relocation_symbols:
                if reloc_name in self.iat_map:
                    libname, symbol_rva = self.iat_map[reloc_name]

                    if self.plt is not None:
                        jmp_offset = self.plt.rva + len(self.plt.content)
                        self.plt.content += b"\xFF\x25" + struct.pack(
                            "<i", symbol_rva - jmp_offset - 6
                        )
                    else:
                        jmp_offset = symbol_rva
                    self._patch_section_symbol(
                        section,
                        reloc_name,
                        reloc_offset,
                        reloc_type,
                        jmp_offset,
                        "{0}@{1}".format(reloc_name, libname),
                    )
                elif self.has_known_section_symbol(reloc_name):
                    reloc_value, reloc_section = self.get_known_section_symbol(
                        reloc_name
                    )
                    self._patch_section_symbol(
                        section,
                        reloc_name,
                        reloc_offset,
                        reloc_type,
                        reloc_section.rva + reloc_value,
                        "{0}@{1}".format(reloc_name, reloc_section.name),
                    )
                else:
                    raise Exception("Unable to resolve symbol {0}".format(reloc_name))

    def _join_sections(self):
        discovered_sections_list = []
        discovered_sections = {}
        previous_section_name = None
        for section in self.sections:
            if (
                previous_section_name is not None
                and section.name != previous_section_name
            ) or previous_section_name is None:
                if section.name in discovered_sections:
                    raise Exception("Detected sparse section {0}".format(section.name))
                discovered_sections[section.name] = section
                discovered_sections_list.append(section.name)
                if not isinstance(section.content, int):
                    section.content = pad_align(section.content, self.alignment)
                else:
                    section.content = align(section.content, self.alignment)
            else:
                if not isinstance(section.content, int):
                    discovered_sections[section.name].content += pad_align(
                        section.content, self.alignment
                    )
                else:
                    discovered_sections[section.name].content += align(
                        section.content, self.alignment
                    )
            previous_section_name = section.name

        self.sections = []
        for section_name in discovered_sections_list:
            self.sections.append(discovered_sections[section_name])

    def link(self):
        # append .edata section
        if self.symbols:
            self._append_edata_section()

        # append .idata section
        if self.imports:
            self._append_idata_section()

        # append .reloc section
        if self.relocations:
            self._append_reloc_section()

        # patch relocations
        self._patch_relocations()

        # join sections by name
        if self.join_sections:
            self._join_sections()

        dos_header = bytearray(b"MZ" + b"\0" * 62)
        dos_header[0x3C] = 0x40  # offset of the pe_header

        pe_header = b"PE\0\0"
        pe_header += le16(0x8664)  # Machine
        pe_header += le16(len(self.sections))
        pe_header += le32(int(time.time()))  # TimeDateStamp
        pe_header += le32(0, 0)  # PointerToSymbolTable, NumberOfSymbols
        pe_header += le16(0xF0)  # SizeOfOptionalHeader
        pe_header += le16(self.characteristics)  # Characteristics

        optional_header = le16(0x020B)  # Magic
        optional_header += b"\x01\x01"
        optional_header += le32(self.get_executable_sections_size())
        # SizeOfInitializedData
        optional_header += le32(self.get_initialized_sections_size())
        optional_header += le32(
            self.get_uninitialized_sections_size()
        )  # SizeOfUninitializedData
        optional_header += le32(self.entry_point)
        optional_header += le32(self.get_text_base())

        optional_header += le64(self.image_base)
        optional_header += le32(self.alignment)
        optional_header += le32(self.file_alignment)
        # MajorOperatingSystemVersion, MinorOperatingSystemVersion
        optional_header += le16(6, 0)
        # MajorImageVersion, MinorImageVersion
        optional_header += le16(0, 0)
        # MajorSubsystemVersion , MinorSubsystemVersion
        optional_header += le16(6, 0)
        optional_header += le32(0)  # Win32VersionValue

        headers_size = align(
            len(dos_header) + len(pe_header) + 0xF0 + (len(self.sections) * 40),
            self.file_alignment,
        )
        headers_size_in_image = align(
            len(dos_header) + len(pe_header) + 0xF0 + (len(self.sections) * 40),
            self.alignment,
        )

        # SizeOfImage
        optional_header += le32(
            headers_size_in_image + self.get_sections_aligned_size()
        )

        optional_header += le32(headers_size)  # SizeOfHeaders

        optional_header += le32(0)  # CheckSum
        optional_header += le16(3)  # Subsystem
        optional_header += le16(
            0x8100 | 0x60 if self.relocations else 0
        )  # DllCharacteristics
        optional_header += le64(0x10000)  # SizeOfStackReserve
        optional_header += le64(0x10000)  # SizeOfStackCommit
        optional_header += le64(0x10000)  # SizeOfHeapReserve
        optional_header += le64(0x10000)  # SizeOfHeapCommit
        optional_header += le32(0)  # LoaderFlags
        optional_header += le32(0x10)  # NumberOfRvaAndSizes

        optional_header += le32(*self.export_table)  # Export Table
        optional_header += le32(*self.import_table)  # Import Table
        optional_header += le32(0, 0)  # Resource Table
        optional_header += le32(0, 0)  # Exception Table
        optional_header += le32(0, 0)  # Certificate Table
        optional_header += le32(*self.relocation_table)  # Base Relocation Table
        optional_header += le32(0, 0)  # Debug
        optional_header += le32(0, 0)  # Architecture
        optional_header += le32(0, 0)  # Global Ptr
        optional_header += le32(0, 0)  # TLS Table
        optional_header += le32(0, 0)  # Local Config Table
        optional_header += le32(0, 0)  # Bound Import
        optional_header += le32(0, 0)  # IAT
        optional_header += le32(0, 0)  # Delay Import
        optional_header += le32(0, 0)  # CLR
        optional_header += le32(0, 0)  # Reserved

        sections_header = b""
        data_offset = headers_size

        for section in self.sections:
            ascii_name = section.name.encode("ascii")
            if len(ascii_name) > 8:
                raise Exception("invalid section name size")
            section_size = 0
            section_file_size = 0
            if section.content:
                if isinstance(section.content, int):
                    section_size = section.content
                    section.permissions |= 0x80
                else:
                    section_size = len(section.content)
                    section_file_size = section_size
                if not section.permissions & 0x20 and not section.permissions & 0x80:
                    section.permissions |= 0x40
            sections_header += pad(ascii_name, 8)
            sections_header += le32(align(section_size, self.alignment))
            sections_header += le32(section.rva)
            sections_header += le32(align(section_file_size, self.file_alignment))
            sections_header += le32(data_offset if section_file_size > 0 else 0)
            sections_header += le32(0)  # PointerToRelocations
            sections_header += le32(0)  # PointerToLinenumbers
            sections_header += le16(0)  # NumberOfRelocations
            sections_header += le16(0)  # NumberOfLinenumbers
            sections_header += le32(section.permissions)  # Characteristics

            print(
                "Added section {0} at RVA 0x{1:08X} permissions {2} size 0x{3:08X} filesize 0x{4:08X}".format(
                    section.name,
                    section.rva,
                    permissions_str(section.permissions),
                    align(section_size, self.alignment),
                    align(section_file_size, self.file_alignment),
                )
            )

            data_offset += align(section_file_size, self.file_alignment)

        blob = pad_align(
            dos_header + pe_header + optional_header + sections_header,
            self.file_alignment,
        )

        for section in self.sections:
            if section.content:
                if not isinstance(section.content, int):
                    blob += pad_align(section.content, self.file_alignment)

        print(
            "Successfully linked at base 0x{0:016X} (entry point at RVA 0x{1:08X})".format(
                self.image_base, self.entry_point
            )
        )

        return blob


class Executable(Image):
    def __init__(self, image_base=0x00400000):
        super().__init__(image_base)

    def add_relocation(self, rva):
        self.relocations.append(rva)


class SharedLibrary(Image):
    def __init__(self, image_base=0x10000000):
        super().__init__(image_base, 0x2022)
        self.entry_point = 0


class COFF:
    def __init__(self, data):
        self.data = data
        (
            self.machine,
            self.number_of_sections,
            self.time_date_stamp,
            self.pointer_to_symbol_table,
            self.number_of_symbols,
            self.size_of_optional_header,
            self.characteristics,
        ) = struct.unpack("<HHIIIHH", data[0:20])
        self.sections = []

        self.string_table_offset = self.pointer_to_symbol_table + (
            self.number_of_symbols * 18
        )

        skip = 0
        symbols_table = {}
        for symbol_index in range(0, self.number_of_symbols):
            if skip > 0:
                skip -= 1
                continue
            (
                symbol_name,
                symbol_section_index,
                symbol_value,
                symbol_storage_class,
                symbol_aux,
            ) = self.get_symbol_by_index(symbol_index)

            if not symbol_section_index in symbols_table:
                symbols_table[symbol_section_index] = []

            symbols_table[symbol_section_index].append((symbol_name, symbol_value))
            skip = symbol_aux

        offset = 20
        for section_index in range(0, self.number_of_sections):
            (
                name,
                _,
                _,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                _,
                number_of_relocations,
                _,
                characteristics,
            ) = struct.unpack("<8sIIIIIIHHI", data[offset : offset + 40])

            # skip section?
            if characteristics & 0x00000800 or size_of_raw_data == 0:
                offset += 40
                continue

            new_section_name = name.rstrip(b"\0").decode()
            new_section_permissions = permissions_str(characteristics)

            if pointer_to_raw_data > 0:
                new_section_data = (
                    data[pointer_to_raw_data : pointer_to_raw_data + size_of_raw_data]
                    if pointer_to_raw_data
                    else b""
                )
            else:
                # uninitialized data?
                new_section_data = size_of_raw_data

            new_section_relocation_symbols = []
            for relocation_index in range(0, number_of_relocations):
                relocation = data[
                    pointer_to_relocations
                    + (relocation_index * 10) : pointer_to_relocations
                    + ((relocation_index + 1) * 10)
                ]
                (
                    relocation_symbol_address,
                    relocation_symbol_index,
                    relocation_symbol_type,
                ) = struct.unpack("<IIH", relocation)

                symbol_name, _, _, _, _ = self.get_symbol_by_index(
                    relocation_symbol_index
                )

                new_section_relocation_symbols.append(
                    (
                        symbol_name,
                        relocation_symbol_address,
                        relocation_symbol_type,
                    )
                )

            section_symbols = {}
            if (section_index + 1) in symbols_table:
                for symbol_name, symbol_value in symbols_table[section_index + 1]:
                    section_symbols[symbol_name] = symbol_value

            self.sections.append(
                (
                    new_section_name,
                    new_section_permissions,
                    new_section_data,
                    new_section_relocation_symbols,
                    section_symbols,
                )
            )

            offset += 40

        self.sections = sorted(self.sections, key=COFF.section_order)

    def get_symbol_by_index(self, symbol_index):
        relocation_symbol_offset = self.pointer_to_symbol_table + (symbol_index * 18)
        (
            symbol_name,
            symbol_value,
            symbol_section_index,
            _,
            symbol_storage_class,
            symbol_aux,
        ) = struct.unpack(
            "<8sIhHBB",
            self.data[relocation_symbol_offset : relocation_symbol_offset + 18],
        )

        if symbol_name[0:4] == b"\0\0\0\0":
            symbol_name = (
                self.data[
                    self.string_table_offset
                    + struct.unpack("<I", symbol_name[4:8])[0] :
                ]
                .split(b"\0")[0]
                .decode()
            )
        else:
            symbol_name = symbol_name.rstrip(b"\0").decode()

        return (
            symbol_name,
            symbol_section_index,
            symbol_value,
            symbol_storage_class,
            symbol_aux,
        )

    @staticmethod
    # this allows to group sections
    def section_order(value):
        try:
            return "." + str((".text", ".data", ".bss", ".rdata").index(value[0]))
        except ValueError:
            return value[0]

    @staticmethod
    def get_ordered_sections(coffs):
        sections = []
        for coff in coffs:
            sections += coff.sections
        return sorted(sections, key=COFF.section_order)


class COFFArchive:
    def __init__(self, data):
        self.coffs = []

        if data[0:8] != b"!<arch>\n":
            raise Exception("Invalid COFF Archive")

        offset = 8
        counter = 0
        while offset < len(data):
            size = int(data[offset + 48 : offset + 48 + 10])
            if counter > 2:
                self.coffs.append(COFF(data[offset + 60 : offset + 60 + size]))
            if size % 2 != 0:
                size += 1
            offset += 60 + size
            counter += 1


if __name__ == "__main__":
    exe = Executable()

    text = exe.add_section(".text", "rx")
    text.content = open(sys.argv[1], "rb").read()

    exe.entry_point = text.rva

    open(sys.argv[2], "wb").write(exe.link())
