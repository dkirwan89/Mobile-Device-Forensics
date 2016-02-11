#Lab Sheet 2
#Dearbhail Kirwan
#Student No. D13128910

import hashlib
import sha3

print("Welcome to the SHA checker!\n")

loop = 0
while loop == 0: #loop for checking another string or file
    choice = input("Would you like to check the hash of a file(f) or a string(s)?\n")
    print("\n")
    choice.lower()
    if choice == "f": #calculate hashes for file
        loop += 1
        get_filename = input("Please enter filepath of file to be hashed:\n")
        print("\n")

        #Calculate SHA-1:
        BLOCKSIZE = 65536
        hasher1 = hashlib.sha1()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher1.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA-1 of",get_filename,":\n", hasher1.hexdigest(), "\n")

        #Calculate SHA-256:
        BLOCKSIZE = 65536
        hasher256 = hashlib.sha256()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher256.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA-256 of",get_filename,":\n",hasher256.hexdigest(),"\n")

        #Calculate SHA-512:
        BLOCKSIZE = 65536
        hasher512 = hashlib.sha512()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher512.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA-512 of",get_filename,":\n",hasher512.hexdigest(),"\n")

        #Calculate SHA3-256:
        BLOCKSIZE = 65536
        hasher3_256 = hashlib.sha3_256()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher3_256.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA3-256 of",get_filename,":\n",hasher3_256.hexdigest(),"\n")

        #Calculate SHA3-384:
        BLOCKSIZE = 65536
        hasher3_384 = hashlib.sha3_384()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher3_384.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA3-384 of",get_filename,":\n",hasher3_384.hexdigest(),"\n")

        #Calculate SHA3-512:
        BLOCKSIZE = 65536
        hasher3_512 = hashlib.sha3_512()
        with open(get_filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher3_512.update(buf)
                buf = afile.read(BLOCKSIZE)
        print("SHA3-512 of",get_filename,":\n",hasher3_512.hexdigest(),"\n")

    if choice == "s": #calculate hashes for string
        loop += 1
        string = input("Enter string to be checked:\n")
        print("\n")

        #calculate SHA-1:
        sha1_string = hashlib.sha1(string.encode())
        print("SHA-1 of string:\n", sha1_string.hexdigest(),"\n")

        #calculate SHA-256:
        sha256_string = hashlib.sha256(string.encode())
        print("SHA-256 of string:\n", sha256_string.hexdigest(),"\n")

        #calculate SHA-512:
        sha512_string = hashlib.sha512(string.encode())
        print("SHA-512 of string:\n", sha512_string.hexdigest(),"\n")

        #calculate SHA3-256:
        sha3_256_string = hashlib.sha3_256(string.encode())
        print("SHA3-256 of string:\n", sha3_256_string.hexdigest(),"\n")

        #calculate SHA3-384:
        sha3_384_string = hashlib.sha3_384(string.encode())
        print("SHA3-384 of string:\n", sha3_384_string.hexdigest(),"\n")

        #calculate SHA3-512:
        sha3_512_string = hashlib.sha3_512(string.encode())
        print("SHA3-512 of string:\n", sha3_512_string.hexdigest(),"\n")


    if choice != "s" and choice != "f": #loop for if user doesn't hit s or f 
        loop += 1
        print("I'm sorry, that is not a valid choice.\n ")


    loop_q = input("Would you like to check another string or file?(y/n)") #go again loop
    print("\n")
    loop_q.lower()

    if loop_q == "y": #restarts loop
        loop = 0
    if loop_q == "n": #ends program
        exit
