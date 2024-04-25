#Evan Bourgoine
import hashlib, binascii
import time

start = time.time()

#create hash definition
def hash(password):
    hashed_pwd = hashlib.pbkdf2_hmac('sha256', #later you will changes this to sha512
                         password.encode('utf-8'),# passowrd is encoded into binary  
                         'saltPhrase'.encode('utf-8'),# 'salt' is an extra bit of info added to the password. When using randomized 'salt' dictionary attacks becomes nealry impossible. For this project keep 'salt' static. In the real world 'salt' is randomized and later exctracted from the hashed password during the verififcation process. Essentially, the 'salt' portion of the hash can be separated from the password portion.
                         100000) # number of iterations ('resolution') of the hashing computation)
    return binascii.hexlify(hashed_pwd)# converting binary to hex 

def check_validity(password):
    if password in dict_array:
        return True
    
    for i in range(1, len(password)):
        pre = password[:i]
        suff = password[i:]
        if pre in dict_array and check_validity(suff):
            return True
        
    return False

def find_password(password):
    #placeholder
    print("Word found! ")
        
    



    

#Step 1: Read Dictionary

dict_array = []
dict_file = open("testDict.txt", "r")

#add each word in file to the dictionary
for line in dict_file:
    dict_array.append(line.rstrip('\n'))


#print(dict_array)

#Step 2: User inputs


#Step 3: Hash user input with different SHA256 - SHA512


        

#Step 4: Perform dictionary attack


#Step 5: Measure time it takes to guess password
#total_time = time.time() - start
#print("Time Elapsed: ",total_time,"seconds")

#Step 6: Present results in a graphical way
    
def main():
    password = input("Enter password: ")
    is_valid = False
    while password != "q":
        if check_validity(password):
            is_valid = True
        else:
            is_valid = False
            print("Invalid password to check.")
        
        if is_valid:
            hashed_password = hash(password)
            print("Hashed password: ", hashed_password)
            find_password(hashed_password)
        password = input("Enter password: ")
    
        

if __name__ == "__main__":
    main()