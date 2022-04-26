from asyncore import write
import argparse
from fileinput import close
import hashlib
import time 

#Argument Parser Setup
parser = argparse.ArgumentParser(description = "Just parses the arguments")
parser.add_argument("-d", help="Filepath of dictionary of bad passwords.")
parser.add_argument("-i", help="Filepath of dictionary passwords to be tested.")
parser.add_argument("-o3", help="Filepath of output file for passwords tested with 3 hash functions.")
parser.add_argument("-o5", help="Filepath of output file for passwords tested with 5 hash functions.")
args = parser.parse_args()

#Bit Array Setup
threeHashBitArray = [0] * 16777216 # ~16 Mb
fiveHashBitArray = [0] * 10700000 # 10.7Mb

#Encrypts the plaintext with md5
#   Salt is added uniformly to all passwords, both trained and tested
#       This makes the cryptographic hashes independent
#   Salt is just integers counting up from 0 added to the end of the passwords 
def encrypt(plaintext):
    crypt = hashlib.md5() # Gonna use just md5 ; Security w/e, this is faster
    ptBytes = plaintext.encode('utf-8')
    crypt.update(ptBytes)
    ciphertext = crypt.hexdigest()
    #First 6 Bytes of the hash selected
    #   This gives (2^4)^6 or 2^24 potential slots;
    #   I.E. 16 Kilobytes of potential bits
    #   Given the password file is only 6k, I think this is good
    ciphertext = ciphertext[:6]
    return ciphertext


def fullEncrypt(plaintext, hashCount):
    encArray = []
    for x in range(0, hashCount):
        encArray.append( encrypt( plaintext + str(x) ) )

    return encArray


#Trains the bit array with the given set of hashes
#   Does so by converting the hash to an int, then setting that value in the bit array
#   Thus this needs to be called per bad password
#   In the case of 5-bit array, also mod the numbers by the size of the bit array
def trainBitArray(encArray, bitArray):
    numArray = []
    for item in encArray:
        numArray.append( int( item, base = 16 ) )

    #Making sure 5-bit hashes fits in bit array size 
    if len(numArray) == 5:
        for i in range(len(numArray)):
            numArray[i] %= 10700000
            

    for index in numArray:
        bitArray[index] = 1
    
# Returns 1 if a all bits at a password's hash are set
# Returns a 0 if not every bit is found
def testBitArray(encArray, bitArray):
    numArray = []
    for item in encArray:
        numArray.append( int( item, base = 16 ) )

    #Making sure 5-bit hashes fits in bit array size 
    if len(numArray) == 5:
        for i in range(len(numArray)):
            numArray[i] %= 10700000

    counter = 0

    for index in numArray:
        if (bitArray[index] == 1):
            counter += 1
    
    if (counter == len(encArray)):
        return 1
    else:
        return 0
    

def main(): 

    with open(args.d, 'r') as f:
        #For every line in the dictionary (i.e. a bad password)
        #   Encrypt the line with MD5 N times with salt
        #   Then, train the bit array by setting the bits at the indices given by the hashes
        startTrain3 = time.time()
        for line in f:
            currLine = line.rstrip()
            threeEncArray = fullEncrypt(currLine, 3)
            trainBitArray(threeEncArray, threeHashBitArray)
        endTrain3 = time.time()

    with open(args.d, 'r') as f:
        startTrain5 = time.time()
        for line in f:
            currLine = line.rstrip()
            fiveEncArray = fullEncrypt(currLine, 5)
            trainBitArray(fiveEncArray, fiveHashBitArray)
        endTrain5 = time.time()

        print("Time it took to train the 3-hash bit array: ~%.2f seconds" % (endTrain3 - startTrain3) )
        print("Time it took to train the 5-hash bit array: ~%.2f seconds" % (endTrain5 - startTrain5) )


    #For every line in the input file (i.e. a password to test)
    #   Encrypt the line with MD5 N times with the same salt as above
    #   Then, check the bit array at the indices specified by the hashes
    #   If there are N collisions, then the password is marked as potentially bad
    #   Otherwise, the password is good
    with open(args.i, 'r') as f:
        output3 = open(args.o3, 'w')
        output5 = open(args.o5, 'w')
        for line in f:
            currLine = line.rstrip()

            threeEncArray = fullEncrypt(currLine, 3)
            if ( testBitArray(threeEncArray, threeHashBitArray) == 1 ):
                output3.write(currLine + ": MAYBE\n")
            else:
                output3.write(currLine + ": NO\n")

            fiveEncArray = fullEncrypt(currLine, 5)
            if ( testBitArray(fiveEncArray, fiveHashBitArray) == 1 ):
                output5.write(currLine + ": MAYBE\n")
            else:
                output5.write(currLine + ": NO\n")

        output3.close()
        output5.close()

 

#cmd to run
# .\script.py -d .\dictionary.txt -i .\sample_input.txt -o3 .\output3.txt -o5 .\output5.txt



#And now actually calling the program
main()