from OpenSSL import crypto
from os import path

class FileHandler:
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
