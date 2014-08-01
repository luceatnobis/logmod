import os
import znc

from .packages import hkp
from .packages import pgpparse


class logmod(znc.Module):
    module_types = [znc.CModInfo.UserModule]
    description = "LogMod"

    def OnLoad(self, args, message):
        self.ddir = self.GetModDataDir()
        self.keyserver = "http://keys.gnupg.net"
        allowed_keywords = ["keyid", "fingerprint"]
        argstor = dict()

        for argpair in args.split(" "):
            try:  # we assume value=key
                param_key, value = argpair.split("=")  # should do the trick
                if param_key in allowed_keywords:
                    argstor[param_key] = value

            except ValueError:
                continue

        error = self._check_conf(argstor)
        if error:
            message.s = error  # return error message to znc
            return False

        server = hkp.KeyServer(self.keyserver)
        res = server.search(argstor["keyid"])

        # TODO: everything, checking for valid keys etc
        if not res:  # no key was found that matches the id
            message.s = "No key found for %s" % argstor["keyid"]

        return True

    def _check_conf(self, args):
        """
        Return a status message about what is wrong with the configuration
        Return None if everything is okay
        """
        if "keyid" not in args:
            return "No keyid parameter provided"
        elif not args["keyid"].startswith("0x"):
            return "Bad KeyID; does it start with 0x?"

        if "fingerprint" in args:
            fingerprint = args["fingerprint"].decode().lower()

            if not re.fullmatch("[a-z0-9]{40}", fingerprint):
                return "Provided fingrprint is not a valid SHA1 hash"

            self.fingerprint = fingerprint

        return None

    def GetWebMenuTitle(self):
        return "Logmod"

    def WebRequiresLogin(self):
        return True

    def OnChanMsg(self, nick, chan, msg):
        self.PutModule("I am working")
        self.PutModule("%s" % self.num_results)

        return znc.CONTINUE

    def OnWebRequest(self, sock, pagename, template):
        if sock.IsPost():
            pass
        return True
