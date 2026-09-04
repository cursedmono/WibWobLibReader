from reader.elf_reader import ELFReader
from reader.string_reader import StringReader

from reader.string_filters import (
    filter_cpp_symbols,
    filter_urls,
    filter_paths,
    filter_libraries
)

from reader.cpp_demangler import demangle_symbols

from reader.exporter import (
    export_strings,
    export_cpp_symbols,
    export_filter
)


def show_filter_results(title, results):

    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    print(f"Encontrados: {len(results):,}")

    if not results:
        print("\nNenhum resultado encontrado.")
        return

    for i, string in enumerate(results, 1):

        print(
            f"[{i:04}] "
            f"0x{string['offset']:08X} "
            f"{string['text']}"
        )


def show_search_results(strings, query):

    results = []

    query = query.lower()

    for string in strings:

        if query in string["text"].lower():
            results.append(string)

    show_filter_results(
        f"Resultados para: {query}",
        results
    )


def main():

    print("=" * 60)
    print("                    WibWobLibReader")
    print("=" * 60)

    path = input(
        "\nDigite o caminho da .so: "
    ).strip().strip('"')

    reader = ELFReader(path)

    try:

        # ==========================================
        # ELF
        # ==========================================

        reader.read()
        reader.show_info()

        # ==========================================
        # STRINGS
        # ==========================================

        print("\nLendo strings...")

        string_reader = StringReader(reader.data)

        strings = string_reader.read()

        print(
            f"Strings carregadas: "
            f"{len(strings):,}"
        )

        # ==========================================
        # MENU
        # ==========================================

        while True:

            print("\n" + "=" * 60)
            print("MENU")
            print("=" * 60)

            print("1 - Buscar string")
            print("2 - Mostrar primeiras strings")
            print("3 - Mostrar total")
            print("4 - C++ Symbols")
            print("5 - Imports")
            print("6 - Exports")
            print("7 - Sections")
            print("8 - URLs")
            print("9 - Caminhos")
            print("10 - Bibliotecas (.so)")
            print("11 - Exportar")
            print("0 - Sair")

            option = input("\nEscolha: ").strip()

            # ======================================
            # BUSCAR STRING
            # ======================================

            if option == "1":

                query = input("\nBuscar: ").strip()

                if query:
                    show_search_results(
                        strings,
                        query
                    )

            # ======================================
            # PRIMEIRAS STRINGS
            # ======================================

            elif option == "2":

                print(
                    "\n" + "=" * 60
                )

                print(
                    "Primeiras 100 strings"
                )

                print(
                    "=" * 60
                )

                for i, string in enumerate(
                    strings[:100],
                    1
                ):

                    print(
                        f"[{i:03}] "
                        f"0x{string['offset']:08X} "
                        f"{string['text']}"
                    )

            # ======================================
            # TOTAL
            # ======================================

            elif option == "3":

                print(
                    f"\nTotal de strings: "
                    f"{len(strings):,}"
                )

            # ======================================
            # C++ SYMBOLS
            # ======================================

            elif option == "4":

                results = filter_cpp_symbols(strings)

                print("\n" + "=" * 60)
                print("Símbolos C++")
                print("=" * 60)

                print(f"Encontrados: {len(results):,}")

                symbols = [
                    string["text"]
                    for string in results
                ]

                print("\nDemangling...")

                demangled = demangle_symbols(symbols)

                for i, string in enumerate(results):

                    original = string["text"]

                    readable = demangled[i]

                    print(
                        f"[{i + 1:04}] "
                        f"0x{string['offset']:08X}"
                    )

                    print(
                        f"       {readable}"
                    )

                    if readable != original:

                        print(
                            f"       [{original}]"
                        )

            # ======================================
            # IMPORTS
            # ======================================

            elif option == "5":

                results = reader.get_imports()

                print("\n" + "=" * 60)
                print("Imports ELF")
                print("=" * 60)

                print(
                    f"Encontrados: {len(results):,}"
                )

                for i, symbol in enumerate(
                    results,
                    1
                ):

                    print(
                        f"[{i:04}] {symbol}"
                    )

            # ======================================
            # EXPORTS
            # ======================================

            elif option == "6":

                results = reader.get_exports()

                print("\n" + "=" * 60)
                print("Exports ELF")
                print("=" * 60)

                print(
                    f"Encontrados: {len(results):,}"
                )

                symbols = [
                    symbol["name"]
                    for symbol in results
                ]

                print("\nDemangling exports...")

                demangled = demangle_symbols(
                    symbols
                )

                for i, symbol in enumerate(
                    results
                ):

                    original = symbol["name"]

                    readable = demangled[i]

                    symbol_type = (
                        reader.get_symbol_type_name(
                            symbol["type"]
                        )
                    )

                    binding = (
                        reader.get_symbol_binding_name(
                            symbol["binding"]
                        )
                    )

                    print(
                        f"\n[{i + 1:04}]"
                    )

                    print(
                        f"     Nome:      "
                        f"{original}"
                    )

                    if readable != original:

                        print(
                            f"     Readable:  "
                            f"{readable}"
                        )

                    print(
                        f"     Endereço:  "
                        f"0x{symbol['value']:08X}"
                    )

                    print(
                        f"     Tamanho:   "
                        f"{symbol['size']} bytes"
                    )

                    print(
                        f"     Tipo:      "
                        f"{symbol_type}"
                    )

                    print(
                        f"     Binding:   "
                        f"{binding}"
                    )

            # ======================================
            # SECTIONS
            # ======================================

            elif option == "7":

                sections = reader.get_section_headers()

                print("\n" + "=" * 60)
                print("Sections ELF")
                print("=" * 60)

                print(
                    f"Encontradas: {len(sections):,}"
                )

                for i, section in enumerate(
                    sections,
                    1
                ):

                    section_type = (
                        reader.get_section_type_name(
                            section["type"]
                        )
                    )

                    flags = (
                        reader.get_section_flags(
                            section["flags"]
                        )
                    )

                    permissions = (
                        reader.get_section_permissions(
                            section["flags"]
                        )
                    )

                    print(
                        f"\n[{i:02}] "
                        f"{section['name']}"
                    )

                    print(
                        f"     Endereço: "
                        f"0x{section['addr']:08X}"
                    )

                    print(
                        f"     Offset:   "
                        f"0x{section['offset']:08X}"
                    )

                    print(
                        f"     Tamanho:  "
                        f"{section['size']:,} bytes"
                    )

                    print(
                        f"     Tipo:     "
                        f"{section_type}"
                    )

                    print(
                        f"     Flags:    "
                        f"{flags}"
                    )

                    print(
                        f"     Permissão: "
                        f"{permissions}"
                    )

                    print(
                        f"     Entsize:  "
                        f"{section['entsize']} bytes"
                    )

            # ======================================
            # URLs
            # ======================================

            elif option == "8":

                results = filter_urls(
                    strings
                )

                show_filter_results(
                    "URLs",
                    results
                )

            # ======================================
            # CAMINHOS
            # ======================================

            elif option == "9":

                results = filter_paths(
                    strings
                )

                show_filter_results(
                    "Caminhos",
                    results
                )

            # ======================================
            # BIBLIOTECAS
            # ======================================

            elif option == "10":

                results = filter_libraries(
                    strings
                )

                show_filter_results(
                    "Bibliotecas (.so)",
                    results
                )

            # ======================================
            # EXPORTAR
            # ======================================

            elif option == "11":

                print("\nExportando análise...")

                output_dir = "output"

                cpp_symbols = filter_cpp_symbols(
                    strings
                )

                file1 = export_strings(
                    strings,
                    output_dir
                )

                file2 = export_cpp_symbols(
                    cpp_symbols,
                    output_dir
                )

                file3 = export_filter(
                    strings,
                    output_dir,
                    "urls.txt",
                    filter_urls
                )

                file4 = export_filter(
                    strings,
                    output_dir,
                    "paths.txt",
                    filter_paths
                )

                file5 = export_filter(
                    strings,
                    output_dir,
                    "libraries.txt",
                    filter_libraries
                )

                print("\nExportação concluída!")

                print(f"\n{file1}")
                print(file2)
                print(file3)
                print(file4)
                print(file5)

            # ======================================
            # SAIR
            # ======================================

            elif option == "0":

                print("\nSaindo...")

                break

            else:

                print("\nOpção inválida.")

    except Exception as e:

        print(f"\n[ERRO] {e}")


if __name__ == "__main__":
    main()