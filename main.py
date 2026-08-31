from reader.elf_reader import ELFReader
from reader.string_reader import StringReader

from reader.string_filters import (
    filter_cpp_symbols,
    filter_urls,
    filter_paths,
    filter_libraries
)

from reader.cpp_demangler import demangle_symbols


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
            print("5 - URLs")
            print("6 - Caminhos")
            print("7 - Bibliotecas (.so)")
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
            # URLs
            # ======================================

            elif option == "5":

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

            elif option == "6":

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

            elif option == "7":

                results = filter_libraries(
                    strings
                )

                show_filter_results(
                    "Bibliotecas (.so)",
                    results
                )

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