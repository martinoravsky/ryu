import hashlib,binascii,hmac


def unhex(hex_string):
    return binascii.unhexlify(hex_string)


def compute_hash(keya, keyb, noncea, nonceb):
    key = unhex(keya+keyb)
    msg = unhex(noncea+nonceb)
    return hmac.new(key, msg, hashlib.sha1).hexdigest()


if __name__ == '__main__':
    print(compute_hash("8829e42a588d64e8","9af32c68f8b9b2f3","63d79859","89dd3bf8"))


