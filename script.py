from asyncore import write
import argparse
import hashlib
import time # Just to sate my curiosity

#Argument Parser Setup
parser = argparse.ArgumentParser(description = "Just parses the arguments")
parser.add_argument("-d", help="Filepath of dictionary of bad passwords.")
parser.add_argument("-i", help="Filepath of dictionary passwords to be tested.")
parser.add_argument("-o3", help="Filepath of output file for passwords tested with 3 hash functions.")
parser.add_argument("-o5", help="Filepath of output file for passwords tested with 5 hash functions.")
args = parser.parse_args()

#Bit Array Setup
threeHashBitArray = [0] * 16777216 # 16 kb
fiveHashBitArray = [0] * 16777216 # 16 kb

#Salt added after
#   Salt just makes the cryptographic cipher independent
def encrypt(plaintext):
    crypt = hashlib.md5() # Gonna use just md5 ; Security w/e, this is faster
    ptBytes = plaintext.encode('utf-8')
    crypt.update(ptBytes)
    ciphertext = crypt.hexdigest()
    #6 Bytes of the hash selected
    #   This gives (2^4)^6 or 2^24 potential slots;
    #   I.E. 16 Kilobytes of potential bits
    #   Given the password file is only 6k, I think this is good
    ciphertext = ciphertext[:6]
    return ciphertext


def fullEncrypt(plaintext, hashCount):
    encArray = []
    for x in range(0, hashCount):
        #print(plaintext + str(x))
        encArray.append( encrypt( plaintext + str(x) ) )
    #print(encArray)
    return encArray




#Trains the bit array with the given set of hashes
#   Does so by converting the hash to an int, then setting that value in the bit array
#   Thus this needs to be called per bad password
def trainBitArray(encArray, bitArray):
    numArray = []
    for item in encArray:
        numArray.append( int( item, base = 16 ) )

    #print(numArray)

    for index in numArray:
        bitArray[index] = 1
        #print(bitArray[index])
    
# Returns 1 if a bad password is found;
def testBitArray(encArray, bitArray, hashCount):
    numArray = []
    for item in encArray:
        numArray.append( int( item, base = 16 ) )

    #print(numArray)
    counter = 0

    for index in numArray:
        if (bitArray[index] == 1):
            counter += 1
        #print(bitArray[index])
    
    if (counter == hashCount):
        #print("BAD PASSWORD FOUND")
        return 1
    else:
        #print("GOOD PASSWORD FOUND")
        return 0
    

def main(): 

    with open(args.d, 'r') as f:
        #For every line in the dictionary (i.e. a bad password)
        #   Encrypt the line with MD5 N times with salt
        #   Then, train the bit array by setting the bits at the indices given by the hashes
        startTrain = time.time()
        for line in f:
            currLine = line.rstrip()
            threeEncArray = fullEncrypt(currLine, 3)
            trainBitArray(threeEncArray, threeHashBitArray)

            fiveEncArray = fullEncrypt(currLine, 5)
            trainBitArray(fiveEncArray, fiveHashBitArray)
        endTrain = time.time()

        print("Time it took to train both bit arrays: ~%.2f seconds" % (endTrain - startTrain) )
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
            if ( testBitArray(threeEncArray, threeHashBitArray, 3) == 1 ):
                output3.write(currLine + ": maybe (POTENTIAL BAD PASSWORD)\n")
            else:
                output3.write(currLine + ": no (GOOD PASSWORD)\n")


            fiveEncArray = fullEncrypt(currLine, 5)
            if ( testBitArray(fiveEncArray, fiveHashBitArray, 5) == 1 ):
                output5.write(currLine + ": maybe (POTENTIAL BAD PASSWORD)\n")
            else:
                output5.write(currLine + ": no (GOOD PASSWORD)\n")

 

    



#And now actually calling the program
main()