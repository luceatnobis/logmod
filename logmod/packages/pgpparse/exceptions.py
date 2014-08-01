#!/usr/bin/env python
# exceptions.py


class EOF(Exception):

    def __str__(self):
        return "EOF reached"


class TooManyPublicKeys(Exception):

    def __str__(self):
        return "More than one Public Key detected"
