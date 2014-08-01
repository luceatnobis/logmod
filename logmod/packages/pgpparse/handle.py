#!/usr/bin/env python3
# handle.py

from io import BytesIO

from pgpparse.exceptions import EOF


class Handle(BytesIO):
    """
    A small abstraction that just adds a method returning bytes interpreted
    as an int. Use with caution and against utmost prejudice.
    """

    def read_int(self, n, byteorder="big"):
        content = self.read(n)
        if not content:
            raise EOF
        return int.from_bytes(content, byteorder=byteorder)
