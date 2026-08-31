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
            raise ValueError("Arquivo muito pequeno para ser um ELF.")

        # Magic ELF
        if self.data[0:4] != b"\x7fELF":
            raise ValueError("O arquivo não é um ELF válido.")

        # 1 = 32-bit
        # 2 = 64-bit
        elf_class = self.data[4]

        if elf_class == 1:
            self.bits = 32

        elif elf_class == 2:
            self.bits = 64

        else:
            raise ValueError("Arquitetura ELF desconhecida.")

        # 1 = Little Endian
        # 2 = Big Endian
        endian = self.data[5]

        if endian == 1:
            self.endian = "<"

        elif endian == 2:
            self.endian = ">"

        else:
            raise ValueError("Endianness desconhecido.")

        # e_machine fica nos bytes 18-19
        self.machine = struct.unpack(
            self.endian + "H",
            self.data[18:20]
        )[0]

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

    def show_info(self):

        print("\n" + "=" * 50)
        print("Informações da biblioteca")
        print("=" * 50)

        print(f"Arquivo:     {self.path}")
        print(f"Tamanho:     {len(self.data):,} bytes")
        print(f"Formato:     ELF")
        print(f"Arquitetura: {self.bits}-bit")
        print(
            f"Endian:      "
            f"{'Little Endian' if self.endian == '<' else 'Big Endian'}"
        )
        print(f"CPU:         {self.get_machine_name()}")

        print("=" * 50)