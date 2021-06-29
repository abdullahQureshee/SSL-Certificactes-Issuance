from common import hash

class Transaction:
    def __init__(self, domain, pk, sig, crt):
        '''
        Creates a Trasaction for domain holded by sig.
        :param domain: type str: name of domain
        :param pk: type [userdefined]: public key of the domain owner
        :param sig: type [userdefined]: signature of the domain owner
        :param crt: type str: initial/revoke
        '''
        self.domain = domain
        self.pk = pk
        self.sig = sig
        self.crt = crt

    def hash(self):
        '''
        Get hash of the transaction.
        :param:
        :returns: type [userdefined]: hash of this transaction
        '''
        return hash(vars(self))

    def __repr__(self):
        return "TX: domain = {0} pk = {1} type = {2}".format(self.domain,self.pk,self.crt)
