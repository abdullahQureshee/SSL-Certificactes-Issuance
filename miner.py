from common import hash

class Miner:
    def __init__(self, blockchain):
        
        '''
        :class Miner: Provides Control for various Proofchain Functions
        :param blockchain: Blockchain the miner is associated to.
        '''
        self.bc = blockchain

        #mixture of public private key within the Openssl module
        #generates a key object not keys
        self.key = self.bc.create_key()
        
        #tokens issued by miner. entries will be popped out once mined
        self.mytokens = {}
        
        #Certificate of CA miner.
        self.identity = self.bc.create_csr(
            CN="ROOTCA",L="RAM",ST="Tense",O="Intel",
            OU="One Block", emailAddress="miner.root@proofchain.com"
        )
        self.signature = self.bc.extract_signature(
            self.bc.dump(self.identity, 'csr'),
            'csr',
            'b16'
        )
        self.identity = self.create_cert_for(self.identity)

        #public key also extracted similar to the signature
        self.pk = bytes.decode(self.bc.dump(self.key, 'pk'))

    def key_check(self, pk, sig):
        #not yet implemented
        '''
        Checks if public key is consistent/binded with private key.
        :param pk: type [userdefined]: public key associated with sig
        :param sig: type [userdefined]: signature associated with pk
        :returns: bool
        '''
        if decrypt_sig(pk, sig) == gen_sigstr(pk):
            return True
        return False

    def domain_check(self, domain, pk):
        '''
        Checks if domain exists in the chain. Returns True if domain doesn't
        exist or domain and pk doesn't match or domain has been revoked.
        :param domain: type str: domain name to search in chain
        :param pk: type [userdefined]: Public key associated with domain
        :returns: bool
        '''
        for block in reversed(self.bc.chain):
            if block.domain == domain:
                if block.crt == 'revoked':
                    return True
                else:
                    return False
                #if block.pk == pk:
                    #if decrypt_sig(pk, block.sig) == gen_sigstr(pk):
                    #return False
        return True

    def token_placement(self, trans):
        '''
        Returns a signed token based on hash of trans.
        :param trans: type Transaction: trans to be included in a block
        :returns: signature
        '''
        t = self.bc.sign(self.key, hash(hash(trans)+ self.pk))
        self.mytokens.setdefault(trans.domain, t)
        return t

    def token_validation(self, issuedtoken, signedToken, cert,digest='sha256'):
        '''
        Veifies signedToken with cert to compare issuedToken.
        :param issuedToken: signature
        :param signedToken: signature
        :param cert: X509 object
        :param digest: Leave it as is
        :returns: bool
        '''
        try:
            self.bc.verify(cert, signedToken, issuedtoken, digest)
        except:
            return False
        return True

    def mine(self,trans,expiry):
        pk, sig = trans.pk, trans.sig
        if True:
            top = self.bc.top
            ids = top if top.domain == trans.domain else None
            gs = top if ids is None else self.bc.chain[-2]
            for block in reversed(self.bc.chain):
                if block.domain == trans.domain:
                    ids = block
                    break
            block = {
                "index": len(self.bc.chain),
                "crt": trans.crt,
                "gs": gs,
                "ids": ids,
                "domain": trans.domain,
                "pk": self.bc.b16encode(self.bc.dump(pk,'pk')),
                "sig": sig,
                "expiry": expiry,
                "CAsig": self.signature
            }
            self.bc.mine(self.bc.createBlock(block))
            self.bc.utp.pop(trans.domain)
            self.mytokens.pop(trans.domain)
            return True
        return False

    def create_cert_for(self,csr):
        cert = self.bc.create_cert_for(csr)
        cert.set_issuer(self.identity.get_subject())
        return cert
