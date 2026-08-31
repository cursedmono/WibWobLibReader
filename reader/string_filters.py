def filter_cpp_symbols(strings):

    results = []

    for string in strings:

        text = string["text"]

        # Símbolos C++ mangled normalmente começam
        # com _Z
        if text.startswith("_Z"):

            results.append(string)

    return results


def filter_urls(strings):

    results = []

    for string in strings:

        text = string["text"].lower()

        if (
            "http://" in text
            or "https://" in text
            or "www." in text
        ):

            results.append(string)

    return results


def filter_paths(strings):

    results = []

    for string in strings:

        text = string["text"]

        if (
            "/" in text
            or "\\" in text
        ):

            results.append(string)

    return results


def filter_libraries(strings):

    results = []

    for string in strings:

        text = string["text"].lower()

        if (
            text.endswith(".so")
            or ".so." in text
        ):

            results.append(string)

    return results