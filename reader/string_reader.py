class StringReader:

    def __init__(self, data):
        self.data = data
        self.strings = []

    def read(self, min_length=4):

        current = bytearray()
        start_offset = 0

        for offset, byte in enumerate(self.data):

            # ASCII imprimível
            if 32 <= byte <= 126:

                if len(current) == 0:
                    start_offset = offset

                current.append(byte)

            else:

                if len(current) >= min_length:

                    try:
                        text = current.decode("ascii")

                        self.strings.append({
                            "offset": start_offset,
                            "text": text
                        })

                    except UnicodeDecodeError:
                        pass

                current = bytearray()

        # Última string do arquivo
        if len(current) >= min_length:

            try:
                text = current.decode("ascii")

                self.strings.append({
                    "offset": start_offset,
                    "text": text
                })

            except UnicodeDecodeError:
                pass

        return self.strings