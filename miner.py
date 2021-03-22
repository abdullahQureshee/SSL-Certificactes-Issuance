from OpenSSL import crypto
from common import hash
from time import time

class Miner:
    def __init__(self, blockchain):
        
        '''
        :class Miner: Provides Control for various Proofchain Functions
        :param blockchain: Blockchain the miner is associated to.
        '''
        
        #mixture of public private key within the Openssl module
        #generates a key object not keys
        self.key = crypto.PKey()
        #generates keys
        self.key.generate_key(crypto.TYPE_RSA,1024)
        
        self.bc = blockchain
        
        #tokens issued by miner. entries will be popped out once mined
        self.mytokens = {}
        
        #Certificate of CA miner.
        self.identity = self.bc.gen_csr(
            CN="ROOTCA",L="RAM",ST="Tense",O="Intel",
            OU="One Block", emailAddress="miner.root@proofchain.com"
        )
        #first dumps the certificate to str and then extracts signature from
        #it. Direct extraction is not available in Openssl
        self.signature = str(
            crypto.b16encode(
                crypto.dump_certificate_request(
                    crypto.FILETYPE_PEM,self.identity
                )
            )
        )[-289:-33]
        self.identity = self.create_cert_for(self.identity)

        #public key also extracted similar to the signature
        self.pk = str(
            crypto.b16encode(
                crypto.dump_publickey(crypto.FILETYPE_ASN1,self.key)
            )
        )

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
        t = ((#crypto.b16encode(
            crypto.sign(self.key,hash(hash(trans)+ self.pk),'sha256')
            ))
        self.mytokens.setdefault(trans.domain, t)
        print("Token for",t,"set")
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
            crypto.verify(cert, signedToken, issuedtoken, digest)
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
                "pk": crypto.b16encode(crypto.dump_publickey(crypto.FILETYPE_PEM,pk)),
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
        cert = self.bc.create_certificate(csr.get_pubkey())
        cert.set_subject(csr.get_subject())#req added
        cert.gmtime_adj_notAfter(365)
        cert.gmtime_adj_notBefore(0)#valid after 0 seconds
        cert.set_issuer(self.identity.get_subject())
        #cert.set_pubkey(csr.get_pubkey())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM,
            crypto.dump_privatekey(crypto.FILETYPE_PEM,csr.get_pubkey())
        )
        cert.sign(key,'sha256')
        return cert
