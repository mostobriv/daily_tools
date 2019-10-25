def chunks(l,n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def xchunks(l,n):
    for i in range(0, len(l), n):
        yield l[i:i + n]
