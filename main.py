from reader.elf_reader import ELFReader
from reader.string_reader import StringReader


def main():

    print("=" * 50)
    print("           WibWobLibReader")
    print("=" * 50)

    path = input("\nDigite o caminho da .so: ").strip().strip('"')

    reader = ELFReader(path)

    try:

        # Lê o ELF
        reader.read()

        # Mostra informações básicas
        reader.show_info()

        # ==========================================
        # STRINGS
        # ==========================================

        string_reader = StringReader(reader.data)

        strings = string_reader.read()

        print("\n" + "=" * 50)
        print("Strings encontradas")
        print("=" * 50)

        print(f"Total: {len(strings):,}")

        # Mostra as primeiras 100 strings

        for i, string in enumerate(strings[:100], 1):

            print(
                f"[{i:03}] "
                f"0x{string['offset']:08X} "
                f"{string['text']}"
            )

    except Exception as e:

        print(f"\n[ERRO] {e}")


if __name__ == "__main__":
    main()