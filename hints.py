
# Hint1: how to produce hashes? Source: https://docs.python.org/2/library/hashlib.html#key-derivation
import hashlib, binascii #will use a built-in library called 'hashlib'

import time

start = time.time()

def hash(password):
    hashed_pwd = hashlib.pbkdf2_hmac('sha256', #later you will changes this to sha512
                         password.encode('utf-8'),# passowrd is encoded into binary  
                         'saltPhrase'.encode('utf-8'),# 'salt' is an extra bit of info added to the password. When using randomized 'salt' dictionary attacks becomes nealry impossible. For this project keep 'salt' static. In the real world 'salt' is randomized and later exctracted from the hashed password during the verififcation process. Essentially, the 'salt' portion of the hash can be separated from the password portion.
                         100000) # number of iterations ('resolution') of the hashing computation)
    return binascii.hexlify(hashed_pwd)# converting binary to hex


hashed_pwd_hex=hash("Some_paSsWord")


print(hashed_pwd_hex)


#Hint2: User prompt, input and password length
password = input("Enter password:")

print("Pwd is:"+password+" Length is: ",len(password))



#Hint3:reading txt files, adding words to array 

#Create a file named 'dictionary.txt' next to the python file!
#Paste the words (one word per line!)


dict_array=[]
dict_file = open("dict.txt","r") 

for line in dict_file:
  dict_array.append(line.rstrip('\n')) # rstrip('\n') removes newline characters from the words, you might not need this. 

print(dict_array)



#Hint4: iterating over the word list comparing the hashes 
for word in dict_array:
    if hash(word) == hashed_pwd_hex:
        print("Guessed it! " + word)
    else:
        print("Wrong:"+word)
        
        

#Hint5: measuring time difference.
print("Elpased time: ",(time.time()-start)+" seconds.")