from miner import Miner
from block import Block
from transaction import Transaction
from random import randint
from OpenSSL import crypto
from os import path
class Proofchain:
    '''
    Class: Proofchain: Provides with all the basic functionality of 'proofchain'
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
        self.chain.append(self.createBlock(Proofchain.GENESIS))
        self.utp = {} #unvalidated transactions pool
        self.miners = []
        self.registereds = {} #storageArray for verifieds
        self.tokened = {} #those domains who have been given a token

    def gen_csr(self, key=None, **kwargs):
        '''
        Returns a CSR object signed with key - if provided.
        :param key: type [userdefined]: key to sign CSR with
        :param kwargs: type (str, str): various possible attributes as defined
          by X509 standard. Some include: CN, ST, L, O, OU, emailAddress
        '''
        req = crypto.X509Req()
        if key is None:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA,1024)
        s = req.get_subject()
        s.CN = kwargs['CN']
        s.ST = kwargs['ST']
        s.L = kwargs['L']
        s.O = kwargs['O']
        s.OU = kwargs['OU']
        s.emailAddress = kwargs['emailAddress']
        req.set_pubkey(key)
        req.sign(key,'sha256')
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
        #self.utp.append(t)
        return t

    def sign(self, key, data, digest = 'sha256'):
        return crypto.sign(key, data, digest)
        
    def load_privatekey(self, key, _type=crypto.FILETYPE_PEM):
        return crypto.load_privatekey(_type, key)
        
    def create_certificate(self, key):
        c = crypto.X509()
        c.set_pubkey(key)
        #c.set_notBefore()
        #c.set_notAfter()
        return c

    def write(self, _path, mode, data):
        #if path.exists(_path):
        f = open(_path, 'w' + mode)
        count = f.write(data)
        f.close()
        return count
        raise Exception("Path Doesn't Exist\n")

    def read(self, _path, mode=""):
        if path.exists(_path):
            return open(_path, 'r' + mode).read()
        raise Exception("Path Doesn't Exist\n")
            
    def get_file_descriptor(self, _path, mode):
        if path.exists(_path):
            return open(p, mode)
        raise Exception("Path Doesn't Exist\n")

    def file_exists(self, _path):
        if path.exists(_path):
            return True
        return False

    def path_join(self, *args):
        return path.join(*args)

    def verify(self, cert, sig, data, digest='sha256'):
        try:
            crypto.verify(cert, sig, data, digest)
            return True
        except:
            return False

    def dump(self, cert, what, _type=crypto.FILETYPE_PEM):
        if what == 'cert':
            return crypto.dump_certificate(_type, cert)
        if what == 'csr':
            return crypto.dump_certificate_request(_type, cert)
        if what == 'pk':
            return crypto.dump_publickey(_type, cert)
        if what == 'sk':
            return crypto.dump_privatekey(_type, cert)
        raise Exception("Invalid type specified. Can only be cert, csr, pk, sk.\n")