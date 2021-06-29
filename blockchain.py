from miner import Miner
from block import Block
from transaction import Transaction
from OpenSSL import crypto


class Blockchain:
    '''
    Class: Blockchain: Provides with all the basic functionality of 'proofchain'
        which includes,
            abstraction for entity creation (block, trans, miner etc.)
            sign/verify for signatures
            load/dump for various data
            file handling
    '''
    GENESIS = {
        "index": 0,
        "crt": None,
        "gs": None,
        "ids": None,
        "domain": None,
        "pk": None,
        "sig": None,
        "expiry": None,
        "CAsig": None
    }

    def __init__(self):
        self.chain = []
        self.chain.append(self.createBlock(Blockchain.GENESIS))
        self.utp = {}  # unvalidated transactions pool
        self.miners = []
        self.registereds = {}  # storageArray for verifieds
        self.tokened = {}  # those domains who have been given a token
        self.users = {}

    def create_csr(self, key=None, **kwargs):
        '''
        Returns a CSR object signed with key - if provided.
        :param key: type [userdefined]: key to sign CSR with
        :param kwargs: type (str, str): various possible attributes as defined
          by X509 standard. Some include: CN, ST, L, O, OU, emailAddress
        '''
        req = crypto.X509Req()
        if key is None:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 1024)
        s = req.get_subject()
        s.CN = kwargs['CN']
        s.ST = kwargs['ST']
        s.L = kwargs['L']
        s.O = kwargs['O']
        s.OU = kwargs['OU']
        s.emailAddress = kwargs['emailAddress']
        req.set_pubkey(key)
        req.sign(key, 'sha256')
        return req

    def mine(self, block):
        self.chain.append(block)
        if block.crt == 'initial':
            self.registereds.setdefault(block.domain, True)
        else:
            self.registereds.setdefault(block.domain, False)

    @property
    def top(self):
        return self.chain[-1]

    def createMiner(self):
        m = Miner(self)
        self.miners.append(m)
        return m

    def createBlock(self, blockdata):
        return Block(**blockdata)

    def createTrans(self, transdata):
        t = Transaction(**transdata)
        return t

    def sign(self, key, data, digest='sha256'):
        return crypto.sign(key, data, digest)

    def create_certificate(self, key):
        c = crypto.X509()
        c.set_pubkey(key)
        # c.set_notBefore()
        # c.set_notAfter()
        return c

    def create_cert_for(self, csr):
        pkey = csr.get_pubkey()
        cert = self.create_certificate(pkey)
        cert.set_subject(csr.get_subject())  # req added
        cert.gmtime_adj_notAfter(365)
        cert.gmtime_adj_notBefore(0)  # valid after 0 seconds
        # sign requires secret key
        pkey = self.load(
            self.dump(pkey, 'sk'),
            'sk'
        )
        cert.sign(pkey, 'sha256')
        return cert

    def verify(self, cert, sig, data, digest='sha256'):
        try:
            crypto.verify(cert, sig, data, digest)
            return True
        except:
            return False

    def extract_signature(self, data, what, encoding):
        if what == 'csr':
            if encoding != 'b16':
                data = crypto.b16encode(data)
            return data[-289:-33]

    def dump(self, data, what, _type=crypto.FILETYPE_PEM):
        if what == 'cert':
            data = crypto.dump_certificate(_type, data)
        elif what == 'csr':
            data = crypto.dump_certificate_request(_type, data)
        elif what == 'pk':
            data = crypto.dump_publickey(_type, data)
        elif what == 'sk':
            data = crypto.dump_privatekey(_type, data)
        else:
            raise Exception(
                "Invalid type specified in arg 'what'. Can only be cert, csr, pk, sk.\n")
        return data

    def load(self, data, what, _type=crypto.FILETYPE_PEM):
        if what == 'cert':
            return crypto.load_certificate(_type, data)
        if what == 'csr':
            return crypto.load_certificate_request(_type, data)
        if what == 'pk':
            return crypto.load_publickey(_type, data)
        if what == 'sk':
            return crypto.load_privatekey(_type, data)
        raise Exception(
            "Invalid type specified. Can only be cert, csr, pk, sk.\n")

    def create_key(self):
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        return k

    def b16encode(self, data):
        return crypto.b16encode(data)

    def create_user(self, name):
        return {'name': name, 'tokens': [], 'domains': []}
