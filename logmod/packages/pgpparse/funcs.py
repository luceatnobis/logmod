#!/usr/bin/env python3
# funcs.py


def _check_new_packet(header):
    """
    Return the two rightmost bits.
    """
    _packet_header_genbit = 0x40
    return bool(header & _packet_header_genbit)


def bytes_for_int(n, bit=None):
    """
    Takes an int and returns the number of bytes it takes to store said int.
    If the bit Parameter is set, it will interpret n as a number of bits, not
    as an int.
    """
    if bit is True:
        bitnum = n
    else:
        bitnum = n.bit_length()

    byte, bits = divmod(bitnum, 8)

    if byte == 0 and bits == 0:
        return 1  # even 0 takes up a byte
    elif 0 < bits:
        byte += 1

    return byte


def mash_to_bytes(contents):
    """
    This is a function which takes a list of things and returns a flat list
    of the bytes from the list.

    The input [256, 4] would return a list of the bytes \x01\x00\x04.
    """
    collection = bytearray()
    for item in contents:
        if hasattr(item, "to_bytes"):
            collection += item.to_bytes(bytes_for_int(item), "big")
        elif type(item) == bytes:
            collection += bytes(item)
        else:
            raise NotImplementedError(type(item))

    return collection
    """
    split_ints = [x.to_bytes(bytes_for_int(x), "big") for x in int_list]
    byte_list = bytes([item for sublist in split_ints for item in sublist])

    return byte_list
    """
