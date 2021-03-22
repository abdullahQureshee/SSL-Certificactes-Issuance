from common import hash

class Block:
    def __init__(self, index, crt, gs, ids, domain, pk, sig, expiry, CAsig):
        '''
        Creates a Block that may become part of the global Blockchain.
        :param index: type int: height of block
        :param crt: type string: initial/revoke
        :param gs: type Block: previous different domain block
        :param ids: type Block: previous same domain block
        :param domain: type str: name of the domain within this block
        :param pk: type [userdefined]: public key of the domain owner
        :param sig: type [userdedfined]: signature of the doamin owner
        :param expiry: type [userdefined]: expiry date of the certificate
        :param CAsig: type [userdefined]: signature of the verifier
        '''
        self.index = index
        self.crt = crt
        self.gs = gs
        self.ids = ids
        self.domain = domain
        self.pk = pk
        self.sig = sig
        self.expiry = expiry
        self.CAsig = CAsig

    @property
    def hash(self):
        '''
        Has of this block.
        :param :
        :returns: type [userdefined]: hash digest
        '''
        return hash(vars(self))

    def __repr__(self):
        t = "Block: index = {0} domain = {1} pk = {2} expiry = {3} status = {4}"
        return t.format(self.index, self.domain, self.pk, self.expiry, self.crt)

    def __str__(self):
        return self.__repr__()