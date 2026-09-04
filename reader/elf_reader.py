import struct

class ELFReader:

    def __init__(self, path):
        self.path = path
        self.data = None

        self.bits = None
        self.endian = None
        self.machine = None

    def read(self):

        with open(self.path, "rb") as file:
            self.data = file.read()

        if len(self.data) < 20:
            raise ValueError(
                "Arquivo muito pequeno para ser um ELF."
            )

        # ==========================================
        # MAGIC
        # ==========================================

        if self.data[0:4] != b"\x7fELF":
            raise ValueError(
                "O arquivo não é um ELF válido."
            )

        # ==========================================
        # CLASS
        # ==========================================

        elf_class = self.data[4]

        if elf_class == 1:
            self.bits = 32

        elif elf_class == 2:
            self.bits = 64

        else:
            raise ValueError(
                "Arquitetura ELF desconhecida."
            )

        # ==========================================
        # ENDIAN
        # ==========================================

        endian = self.data[5]

        if endian == 1:
            self.endian = "<"

        elif endian == 2:
            self.endian = ">"

        else:
            raise ValueError(
                "Endianness desconhecido."
            )

        # ==========================================
        # MACHINE
        # ==========================================

        self.machine = struct.unpack(
            self.endian + "H",
            self.data[18:20]
        )[0]

    # ==============================================
    # MACHINE NAME
    # ==============================================

    def get_machine_name(self):

        machines = {
            3: "x86",
            40: "ARM",
            62: "x86-64",
            183: "ARM64",
        }

        return machines.get(
            self.machine,
            f"Desconhecido ({self.machine})"
        )

    # ==============================================
    # SECTION TYPE
    # ==============================================

    def get_section_type_name(self, section_type):

        types = {
            0: "NULL",
            1: "PROGBITS",
            2: "SYMTAB",
            3: "STRTAB",
            4: "RELA",
            5: "HASH",
            6: "DYNAMIC",
            7: "NOTE",
            8: "NOBITS",
            9: "REL",
            11: "DYNSYM",
            14: "INIT_ARRAY",
            15: "FINI_ARRAY",
            0x70000000: "LOOS",
            0x6FFFFFFF: "HIOS",
        }

        return types.get(
            section_type,
            f"UNKNOWN ({section_type})"
        )

    # ==============================================
    # SECTION FLAGS
    # ==============================================

    def get_section_flags(self, flags):

        result = []

        # SHF_WRITE
        if flags & 0x1:
            result.append("WRITE")

        # SHF_ALLOC
        if flags & 0x2:
            result.append("ALLOC")

        # SHF_EXECINSTR
        if flags & 0x4:
            result.append("EXECINSTR")

        # SHF_MERGE
        if flags & 0x10:
            result.append("MERGE")

        # SHF_STRINGS
        if flags & 0x20:
            result.append("STRINGS")

        # SHF_INFO_LINK
        if flags & 0x40:
            result.append("INFO_LINK")

        # SHF_LINK_ORDER
        if flags & 0x80:
            result.append("LINK_ORDER")

        # SHF_OS_NONCONFORMING
        if flags & 0x100:
            result.append("OS_NONCONFORMING")

        # SHF_GROUP
        if flags & 0x200:
            result.append("GROUP")

        # SHF_TLS
        if flags & 0x400:
            result.append("TLS")

        if not result:
            return "NONE"

        return " | ".join(result)

    # ==============================================
    # SECTION PERMISSIONS
    # ==============================================

    def get_section_permissions(self, flags):

        write = bool(flags & 0x1)
        executable = bool(flags & 0x4)

        if executable and write:
            return "LEITURA / ESCRITA / EXECUÇÃO"

        if executable:
            return "LEITURA / EXECUÇÃO"

        if write:
            return "LEITURA / ESCRITA"

        return "SOMENTE LEITURA"

    # ==============================================
    # SECTION HEADERS
    # ==============================================

    def get_section_headers(self):

        if self.bits == 32:

            shoff = struct.unpack(
                self.endian + "I",
                self.data[32:36]
            )[0]

            shentsize = struct.unpack(
                self.endian + "H",
                self.data[46:48]
            )[0]

            shnum = struct.unpack(
                self.endian + "H",
                self.data[48:50]
            )[0]

            shstrndx = struct.unpack(
                self.endian + "H",
                self.data[50:52]
            )[0]

        else:

            shoff = struct.unpack(
                self.endian + "Q",
                self.data[40:48]
            )[0]

            shentsize = struct.unpack(
                self.endian + "H",
                self.data[58:60]
            )[0]

            shnum = struct.unpack(
                self.endian + "H",
                self.data[60:62]
            )[0]

            shstrndx = struct.unpack(
                self.endian + "H",
                self.data[62:64]
            )[0]

        sections = []

        for i in range(shnum):

            offset = shoff + i * shentsize

            if self.bits == 32:

                section_data = self.data[
                    offset:
                    offset + 40
                ]

                values = struct.unpack(
                    self.endian + "IIIIIIIIII",
                    section_data
                )

                name = values[0]
                section_type = values[1]
                flags = values[2]
                section_addr = values[3]
                section_offset = values[4]
                section_size = values[5]
                link = values[6]
                info = values[7]
                addralign = values[8]
                entsize = values[9]

            else:

                values = struct.unpack(
                    self.endian + "IIQQQQIIQQ",
                    self.data[
                        offset:
                        offset + 64
                    ]
                )

                name = values[0]
                section_type = values[1]
                flags = values[2]
                section_addr = values[3]
                section_offset = values[4]
                section_size = values[5]
                link = values[6]
                info = values[7]
                addralign = values[8]
                entsize = values[9]

            sections.append({
                "name_offset": name,
                "type": section_type,
                "flags": flags,
                "addr": section_addr,
                "offset": section_offset,
                "size": section_size,
                "link": link,
                "info": info,
                "addralign": addralign,
                "entsize": entsize,
            })

        # ==========================================
        # SECTION NAME STRING TABLE
        # ==========================================

        if not sections:
            return []

        if shstrndx >= len(sections):
            return sections

        string_section = sections[shstrndx]

        string_data = self.data[
            string_section["offset"]:
            string_section["offset"] +
            string_section["size"]
        ]

        for section in sections:

            name_offset = section["name_offset"]

            if name_offset >= len(string_data):

                section["name"] = ""

                continue

            end = string_data.find(
                b"\x00",
                name_offset
            )

            if end == -1:
                end = len(string_data)

            section["name"] = (
                string_data[
                    name_offset:end
                ].decode(
                    "utf-8",
                    errors="replace"
                )
            )

        return sections

    # ==============================================
    # FIND SECTION BY ADDRESS
    # ==============================================

    def find_section_by_address(self, address):

        sections = self.get_section_headers()

        if not sections:
            return None

        for section in sections:

            section_address = section.get(
                "addr",
                0
            )

            section_size = section.get(
                "size",
                0
            )

            # Sections sem endereço
            if section_address == 0:
                continue

            # Sections vazias
            if section_size == 0:
                continue

            section_end = (
                section_address +
                section_size
            )

            if (
                address >= section_address
                and address < section_end
            ):

                offset_in_section = (
                    address -
                    section_address
                )

                file_offset = (
                    section["offset"] +
                    offset_in_section
                )

                return {
                    "section": section.get(
                        "name",
                        ""
                    ),
                    "address": address,
                    "section_address":
                        section_address,
                    "section_size":
                        section_size,
                    "offset_in_section":
                        offset_in_section,
                    "file_offset":
                        file_offset,
                }

        return None

    # ==============================================
    # SYMBOL TABLE
    # ==============================================

    def _read_symbol_table(
        self,
        symbol_section,
        string_section
    ):

        symbols = []

        symbol_offset = symbol_section["offset"]
        symbol_size = symbol_section["size"]
        entry_size = symbol_section["entsize"]

        if entry_size == 0:

            if self.bits == 32:
                entry_size = 16

            else:
                entry_size = 24

        string_data = self.data[
            string_section["offset"]:
            string_section["offset"] +
            string_section["size"]
        ]

        count = symbol_size // entry_size

        for i in range(count):

            offset = (
                symbol_offset +
                i * entry_size
            )

            try:

                if self.bits == 32:

                    (
                        name_offset,
                        value,
                        size,
                        info,
                        other,
                        shndx
                    ) = struct.unpack(
                        self.endian + "IIIBBH",
                        self.data[
                            offset:
                            offset + 16
                        ]
                    )

                else:

                    (
                        name_offset,
                        info,
                        other,
                        shndx,
                        value,
                        size
                    ) = struct.unpack(
                        self.endian + "IBBHQQ",
                        self.data[
                            offset:
                            offset + 24
                        ]
                    )

            except struct.error:
                continue

            if name_offset >= len(string_data):

                name = ""

            else:

                end = string_data.find(
                    b"\x00",
                    name_offset
                )

                if end == -1:
                    end = len(string_data)

                name = string_data[
                    name_offset:end
                ].decode(
                    "utf-8",
                    errors="replace"
                )

            if not name:
                continue

            symbol_type = info & 0x0F
            binding = info >> 4

            symbols.append({
                "name": name,
                "value": value,
                "size": size,
                "type": symbol_type,
                "binding": binding,
                "shndx": shndx,
            })

        return symbols

    # ==============================================
    # IMPORTS
    # ==============================================

    def get_imports(self):

        sections = self.get_section_headers()

        dynsym = None
        dynstr = None

        for section in sections:

            if section["name"] == ".dynsym":
                dynsym = section

            elif section["name"] == ".dynstr":
                dynstr = section

        if not dynsym or not dynstr:
            return []

        symbols = self._read_symbol_table(
            dynsym,
            dynstr
        )

        imports = []

        for symbol in symbols:

            # SHN_UNDEF = 0
            if symbol["shndx"] == 0:

                if symbol["name"] not in imports:
                    imports.append(
                        symbol["name"]
                    )

        return imports

    # ==============================================
    # SYMBOL TYPE
    # ==============================================

    def get_symbol_type_name(self, symbol_type):

        types = {
            0: "NOTYPE",
            1: "OBJECT",
            2: "FUNC",
            3: "SECTION",
            4: "FILE",
            5: "COMMON",
            6: "TLS",
            10: "GNU_IFUNC",
        }

        return types.get(
            symbol_type,
            f"UNKNOWN ({symbol_type})"
        )

    # ==============================================
    # SYMBOL BINDING
    # ==============================================

    def get_symbol_binding_name(self, binding):

        bindings = {
            0: "LOCAL",
            1: "GLOBAL",
            2: "WEAK",
        }

        return bindings.get(
            binding,
            f"UNKNOWN ({binding})"
        )

    # ==============================================
    # EXPORTS
    # ==============================================

    def get_exports(self):

        sections = self.get_section_headers()

        symbol_sections = []
        string_sections = {}

        for section in sections:

            if section["name"] in (
                ".dynsym",
                ".symtab"
            ):
                symbol_sections.append(section)

            if section["name"] in (
                ".dynstr",
                ".strtab"
            ):
                string_sections[
                    section["name"]
                ] = section

        exports = {}

        for symbol_section in symbol_sections:

            if symbol_section["name"] == ".dynsym":

                string_section = string_sections.get(
                    ".dynstr"
                )

            else:

                string_section = string_sections.get(
                    ".strtab"
                )

            if not string_section:
                continue

            symbols = self._read_symbol_table(
                symbol_section,
                string_section
            )

            for symbol in symbols:

                # Símbolo definido
                if symbol["shndx"] == 0:
                    continue

                # GLOBAL ou WEAK
                if symbol["binding"] not in (1, 2):
                    continue

                name = symbol["name"]

                exports[name] = symbol

        return list(exports.values())

        # ==============================================
    # PROGRAM HEADER TYPE
    # ==============================================

    def get_program_type_name(self, program_type):

        types = {
            0: "NULL",
            1: "LOAD",
            2: "DYNAMIC",
            3: "INTERP",
            4: "NOTE",
            5: "SHLIB",
            6: "PHDR",
            7: "TLS",
            0x6474E550: "GNU_EH_FRAME",
            0x6474E551: "GNU_STACK",
            0x6474E552: "GNU_RELRO",
        }

        return types.get(
            program_type,
            f"UNKNOWN (0x{program_type:08X})"
        )

    # ==============================================
    # PROGRAM HEADER FLAGS
    # ==============================================

    def get_program_flags(self, flags):

        result = []

        # PF_X
        if flags & 0x1:
            result.append("EXEC")

        # PF_W
        if flags & 0x2:
            result.append("WRITE")

        # PF_R
        if flags & 0x4:
            result.append("READ")

        if not result:
            return "NONE"

        return " | ".join(result)

    # ==============================================
    # PROGRAM HEADERS
    # ==============================================

    def get_program_headers(self):

        if self.bits == 32:

            phoff = struct.unpack(
                self.endian + "I",
                self.data[28:32]
            )[0]

            phentsize = struct.unpack(
                self.endian + "H",
                self.data[42:44]
            )[0]

            phnum = struct.unpack(
                self.endian + "H",
                self.data[44:46]
            )[0]

        else:

            phoff = struct.unpack(
                self.endian + "Q",
                self.data[32:40]
            )[0]

            phentsize = struct.unpack(
                self.endian + "H",
                self.data[54:56]
            )[0]

            phnum = struct.unpack(
                self.endian + "H",
                self.data[56:58]
            )[0]

        programs = []

        for i in range(phnum):

            offset = (
                phoff +
                i * phentsize
            )

            try:

                if self.bits == 32:

                    values = struct.unpack(
                        self.endian + "IIIIIIII",
                        self.data[
                            offset:
                            offset + 32
                        ]
                    )

                    (
                        program_type,
                        file_offset,
                        virtual_address,
                        physical_address,
                        file_size,
                        memory_size,
                        flags,
                        align
                    ) = values

                else:

                    values = struct.unpack(
                        self.endian + "IIQQQQQQ",
                        self.data[
                            offset:
                            offset + 56
                        ]
                    )

                    (
                        program_type,
                        flags,
                        file_offset,
                        virtual_address,
                        physical_address,
                        file_size,
                        memory_size,
                        align
                    ) = values

            except struct.error:
                continue

            programs.append({
                "type": program_type,
                "offset": file_offset,
                "vaddr": virtual_address,
                "paddr": physical_address,
                "filesz": file_size,
                "memsz": memory_size,
                "flags": flags,
                "align": align,
            })

        return programs

    # ==============================================
    # FIND PT_LOAD BY ADDRESS
    # ==============================================

    def find_load_segment_by_address(self, address):

        programs = self.get_program_headers()

        for program in programs:

            # PT_LOAD
            if program["type"] != 1:
                continue

            start = program["vaddr"]
            end = (
                start +
                program["memsz"]
            )

            if (
                address >= start
                and address < end
            ):

                offset_in_segment = (
                    address -
                    start
                )

                # Endereço dentro da parte
                # realmente presente no arquivo
                if offset_in_segment >= program["filesz"]:
                    return {
                        "program": program,
                        "file_offset": None,
                        "offset_in_segment":
                            offset_in_segment,
                        "in_file": False,
                    }

                file_offset = (
                    program["offset"] +
                    offset_in_segment
                )

                return {
                    "program": program,
                    "file_offset": file_offset,
                    "offset_in_segment":
                        offset_in_segment,
                    "in_file": True,
                }

        return None

    # ==============================================
    # FIND ADDRESS - PT_LOAD + SECTION
    # ==============================================

    def resolve_address(self, address):

        load = self.find_load_segment_by_address(
            address
        )

        section = self.find_section_by_address(
            address
        )

        result = {
            "address": address,
            "load": load,
            "section": section,
        }

        if load and load["file_offset"] is not None:

            result["file_offset"] = (
                load["file_offset"]
            )

        else:

            result["file_offset"] = None

        return result
    

    # ==============================================
    # SHOW ELF INFO
    # ==============================================

    def show_info(self):

        print("\n" + "=" * 50)
        print("Informações da biblioteca")
        print("=" * 50)

        print(
            f"Arquivo:     {self.path}"
        )

        print(
            f"Tamanho:     {len(self.data):,} bytes"
        )

        print(
            "Formato:     ELF"
        )

        print(
            f"Arquitetura: {self.bits}-bit"
        )

        print(
            f"Endian:      "
            f"{'Little Endian' if self.endian == '<' else 'Big Endian'}"
        )

        print(
            f"CPU:         {self.get_machine_name()}"
        )

        print("=" * 50)