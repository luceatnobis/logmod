#!/usr/bin/env python3
# mpi.py

from pgpparse.funcs import bytes_for_int


class MPI:
    """
    An MPI (Multiple Precision Integer) is a data type used to contain and
    transmit a large number, often for cryptographic purposes. To achieve this,
    it first describes the number of bits required to store the number in
    question. The actual large number directly follows.

    It consists of two fields:
        - a two byte field containing the length of the integer
        - an integer of unpredictable length, see above
    """

    def __init__(self, handle):
        length_of_mpi = 2
        self.bit_length = handle.read_int(length_of_mpi)
        # we need a number of bytes for the read call, not a number of bits
        self.byte_length = bytes_for_int(self.bit_length, bit=True)
        self.value = handle.read_int(self.byte_length)

    def to_bytes(self):
        return b"".join([
            self.bit_length.to_bytes(2, "big"),
            self.value.to_bytes(bytes_for_int(self.value), "big")
        ])

    def __repr__(self):
        return "<MPI Value: %s; Length; %s>" % (self.value, self.byte_length)
