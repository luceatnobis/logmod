#!/usr/bin/env python3
# packets.py

import hashlib

from pgpparse import public_key

from pgpparse.funcs import bytes_for_int, mash_to_bytes, _check_new_packet


class Generic_Packet:
    """
    This is a class that simply describes a generic package, it does not have
    information about packet contents or types. It merely adheres to the
    common length description and is only used to derive meta information from
    packets.
    """

    def __init__(self, header, handle):
        """
        This is only valid if we're dealing with an old package, indeterminate
        lengths are neither supported nor recommended for use.

        See Section 4.2.1 (http://tools.ietf.org/html/rfc4880#section-4.2.1)
        """

        self._new_packet_indicator_byte_len = 1
        self._packet_header_cancel_for_len_len = 0x03
        self._packet_header_cancel_for_packet_type = 0x3c

        self.header = header
        self.handle = handle

        self.new_packet = _check_new_packet(self.header)
        if self.new_packet:
            self.len_length_field, self.body_length = self._get_len_new()
        else:
            self.len_length_field, self.body_length = self._get_len_old()

        self.body_length_bytes = self.body_length.to_bytes(2, "big")
        self.size = bytes_for_int(header) + (
            self.len_length_field + self.body_length)

    def _get_len_new(self):
        indicator_byte = self.handle.read_int(
            self._new_packet_indicator_byte_len)

        if indicator_byte < 192:
            raise NotImplementedError
        elif indicator_byte >= 192 and indicator_byte <= 223:
            raise NotImplementedError
        elif indicator_byte == 255:
            length_octs = 4
            body_length = self.handle.read_int(length_octs)

        len_length_octs = length_octs + self._new_packet_indicator_byte_len

        return [len_length_octs, body_length]

    def _get_len_old(self):
        len_length_field_octs = [1, 2, 4]  # section 4.2.

        len_length = self._get_len_length(self.header)

        if len_length == 3:
            raise NotImplementedError("Indeterminate length not supported")

        len_length_octs = len_length_field_octs[len_length]
        body_length = self.handle.read_int(len_length_octs)

        return [len_length_octs, body_length]

    def _get_len_length(self, header):
        """
        We need the first two bytes, so we'll & with 3.
        """
        return header & self._packet_header_cancel_for_len_len


class Trash_Packet(Generic_Packet):
    """
    This class describes a packet we do not care to parse or store. It simply
    serves to set the position indicator to *after* the packet via read.
    """
    def __init__(self, header, handle):
        super().__init__(header, handle)
        self.packet_type = 0  # indicating its forbidden
        handle.read(self.body_length)


class Public_Key_Packet(Generic_Packet):
    """
    This is just a public key container, it contains
        - a length which is to be determined, 1, 2 and 4 byte are supported
        - a version number (one byte with value 4)
        - unix timestamp of the key creation, 4 byte
        - an algorithm marker, one byte
    """
    def __init__(self, header, handle):
        super().__init__(header, handle)  # call constructor of base class
        self.packet_tag = 6

        # definitions of field lengths in byte
        algo_field_len = 1
        version_field_len = 1
        timestamp_field_len = 4
        public_algorithms = {
            1: public_key.RSA_Public,
            16: public_key.Elgamal_Public,
            17: public_key.DSA_Public
        }

        self.version = handle.read_int(version_field_len)
        if self.version != 4:  # TODO: implement version 3 keys
            raise Exception("Invalid version number at", hex(handle.tell()))

        self.timestamp = handle.read_int(timestamp_field_len)
        self.algorithm = handle.read_int(algo_field_len)

        self.key_material = public_algorithms[self.algorithm](handle)
        self.fingerprint = self._create_fingerprint()

    def _create_fingerprint(self):
        """
        This function creates a version 4 fingerprint. See Section 12.2.
        """
        header = 0x99  # regardless of the actual header, for subkeys

        packet = mash_to_bytes([
            header, self.body_length_bytes, self.version, self.timestamp,
            self.algorithm]) + self.key_material.to_bytes()

        return hashlib.sha1(packet).hexdigest()


class Public_Subkey_Packet(Public_Key_Packet):
    """
    Subkeys are identical to actual keys, so this is basically a copy of the
    actual Public_Key_Packet, but they warrant differentiation because they
    have different packet tags. For example.
    """

    def __init__(self, header, handle):
        super().__init__(header, handle)
        self.packet_tag = 14


class User_Attribute_Packet(Generic_Packet):

    def __init__(self, header, handle):
        pass
