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
                section_offset = values[4]
                section_size = values[5]
                link = values[6]
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
                section_offset = values[4]
                section_size = values[5]
                link = values[6]
                entsize = values[9]

            sections.append({
                "name_offset": name,
                "type": section_type,
                "offset": section_offset,
                "size": section_size,
                "link": link,
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