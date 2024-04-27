#Evan Bourgoine
import hashlib, binascii
import time
from itertools import combinations, permutations

#Evan Bourgoine (ebourgoine25)
#2104 Class Project
#Option B: Dictionary Attack using different hash algorithms

#Step 1: Read Dictionary
#Step 2: User inputs
#Step 3: Hash user input with different SHA256 - SHA512
#Step 4: Perform dictionary attack
#Step 5: Measure time it takes to guess password
#Step 6: Present results in a graphical way

#hash the user password using SHA256
def hash256(password):
    hashed_pwd = hashlib.pbkdf2_hmac('sha256', #later you will changes this to sha512
                         password.encode('utf-8'),# passowrd is encoded into binary  
                         'saltPhrase'.encode('utf-8'),# 'salt' is an extra bit of info added to the password. When using randomized 'salt' dictionary attacks becomes nealry impossible. For this project keep 'salt' static. In the real world 'salt' is randomized and later exctracted from the hashed password during the verififcation process. Essentially, the 'salt' portion of the hash can be separated from the password portion.
                         100000) # number of iterations ('resolution') of the hashing computation)
    return binascii.hexlify(hashed_pwd)# converting binary to hex 

#hash the user password using SHA512
def hash512(password):
    hashed_pwd = hashlib.pbkdf2_hmac('sha512', #later you will changes this to sha512
                         password.encode('utf-8'),# passowrd is encoded into binary  
                         'saltPhrase'.encode('utf-8'),# 'salt' is an extra bit of info added to the password. When using randomized 'salt' dictionary attacks becomes nealry impossible. For this project keep 'salt' static. In the real world 'salt' is randomized and later exctracted from the hashed password during the verififcation process. Essentially, the 'salt' portion of the hash can be separated from the password portion.
                         100000) # number of iterations ('resolution') of the hashing computation)
    return binascii.hexlify(hashed_pwd)# converting binary to hex 

#check if user password is in the dictionary, or combination of dictionary words
#uses recursion to check combination of words
def check_validity(password, dictionary):
    if password in dictionary:
        return True
    
    for i in range(1, len(password)):
        pre = password[:i]
        suff = password[i:]
        if pre in dictionary and check_validity(suff, dictionary):
            return True
        
    return False

#parameter password is the password given in hashed form
#dictionary parameter is the dictionary of possible passwords
def dict_attack256(hash_password, combo_dict):
    count = 1
    for word in combo_dict:
        hashed_word = hash256(word)
        if hashed_word == hash_password:
            break
        else:
            count = count + 1

#perform attack using the SHA512 hashed password
def dict_attack512(hash_password, combo_dict):
    count = 1
    for word in combo_dict:
        hashed_word = hash512(word)
        if hashed_word == hash_password:
            break
        else:
            count = count + 1

#will eliminate words in the dictionary if they are not the correct length 
def eliminate_words(password, dictionary):
    updated_dictionary = []
    for word in dictionary:
        if len(word) == len(password):
            updated_dictionary.append(word)
    return updated_dictionary
    
#will generate all possible combinations of up to 3 words in the dictionary
def generate_combinations(dictionary):
    combos = []
    for i in range(1, 4):
        for combo in combinations(dictionary, i):
            for perm in permutations(combo):
                combos.append(''.join(perm))
    return combos
    
def main():

    #Creates dictionary of words from text file given
    dict_array = []
    dict_file = open("smallSample.txt", "r")

        #add each word in file to the dictionary
    for line in dict_file:
        dict_array.append(line.rstrip('\n'))

    #Prompts user for password
    password = input("Enter password: \t")

    #Create boolean value to store validity of password for searching
    is_valid = False
    while password != "q": #Check if user is done checking passwords
        #Check if password given is in the text file, combinations are acceptible
        if check_validity(password, dict_array): 
            is_valid = True
        else:
            is_valid = False
            print("Invalid password to check.") #program will not attempt to crack in invalid password

        #If password given is valid, perform dict. attack to find password in dictionary
        if is_valid: 
            #hash user password to SHA256
            hashed_password256 = hash256(password)
            print("\nSHA256: ", hashed_password256)
            
            #hash user password to SHA512
            hashed_password512 = hash512(password)
            print("SHA512: ", hashed_password512, "\n")

            #generate all possible combinations of dictionary words that the password could be
            combo_dict = generate_combinations(dict_array)
            #elimate passwords that are not the correct length
            updated_dict = eliminate_words(password, combo_dict)

            #begin SHA256 attack, track time
            start256 = time.time()
            dict_attack256(hashed_password256, updated_dict)
            end256 = time.time()

            #begin SHA512 attack, track time
            start512 = time.time()
            dict_attack512(hashed_password512, updated_dict)
            end512 = time.time()

            #print time it takes to crack both attacks
            print("Time to crack SHA256: ", end256 - start256)
            print("Time to crack SHA512: ", end512 - start512)
    
        password = input("Enter password: \t") #prompt for anothr password, or 'q'
    
        

if __name__ == "__main__":
    main()