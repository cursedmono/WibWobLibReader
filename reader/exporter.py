from pathlib import Path


def export_strings(strings, output_dir):

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / "strings.txt"

    with open(file_path, "w", encoding="utf-8") as file:

        for string in strings:

            file.write(
                f"0x{string['offset']:08X} "
                f"{string['text']}\n"
            )

    return file_path


def export_cpp_symbols(strings, output_dir):

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / "cpp_symbols.txt"

    with open(file_path, "w", encoding="utf-8") as file:

        for string in strings:

            file.write(
                f"0x{string['offset']:08X} "
                f"{string['text']}\n"
            )

    return file_path


def export_filter(
    strings,
    output_dir,
    filename,
    filter_function
):

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = filter_function(strings)

    file_path = output_dir / filename

    with open(file_path, "w", encoding="utf-8") as file:

        for string in results:

            file.write(
                f"0x{string['offset']:08X} "
                f"{string['text']}\n"
            )

    return file_path