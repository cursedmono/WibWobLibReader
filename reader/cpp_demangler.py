import subprocess


def demangle_symbols(symbols):

    if not symbols:
        return []

    try:

        process = subprocess.run(
            ["c++filt"],
            input="\n".join(symbols),
            capture_output=True,
            text=True,
            timeout=30
        )

        if process.returncode == 0:

            return process.stdout.splitlines()

    except Exception as e:

        print(f"[ERRO] Demangling: {e}")

    return symbols