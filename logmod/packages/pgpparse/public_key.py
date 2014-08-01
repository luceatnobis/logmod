#!/usr/bin/env python3
# public_key.py

from pgpparse.mpi import MPI


class Public_Key:

    def __iter__(self):
        self._iter_counter = 0
        return self

    def __next__(self):
        if self._iter_counter == len(self.mpi):
            raise StopIteration
        val = self.mpi[self._iter_counter]
        self._iter_counter += 1
        return val

    def to_bytes(self):
        return b"".join(x.to_bytes() for x in self.mpi)


class RSA_Public(Public_Key):
    """
    The public portion of an RSA key is comprised of two elements: a large
    prime N and a comparatively small modulus e.

    See section 5.5.2
    """

    def __init__(self, handle):
        self.N = MPI(handle)
        self.e = MPI(handle)

        self.mpi = (self.N, self.e)


class DSA_Public(Public_Key):
    """
    The public portion of a DSA key is comprised of four MPI, p, q, g and y.

    See section 5.5.2
    """
    def __init__(self, handle):
        self.p = MPI(handle)
        self.q = MPI(handle)
        self.g = MPI(handle)
        self.y = MPI(handle)

        self.mpi = (self.p, self.q, self.g, self.y)


class Elgamal_Public(Public_Key):

    def __init__(self, handle):
        self.p = MPI(handle)
        self.g = MPI(handle)
        self.y = MPI(handle)

        self.mpi = (self.p, self.g, self.y)
