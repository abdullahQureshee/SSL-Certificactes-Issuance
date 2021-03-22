from hashlib import sha256

def hash(m):
    '''
    Returns hash of a message encoded in hex
    :param m: message to hash
    :returns: type bytes: hash of m
    '''
    return sha256(str(m).encode()).hexdigest()
