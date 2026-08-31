from reader.elf_reader import ELFReader


def main():
    print("=" * 50)
    print("           WibWobLibReader")
    print("=" * 50)

    path = input("\nDigite o caminho da .so: ").strip()

    reader = ELFReader(path)

    try:
        reader.read()
        reader.show_info()

    except Exception as e:
        print(f"\n[ERRO] {e}")


if __name__ == "__main__":
    main()