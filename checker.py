import requests
import hashlib
import sys

# wecan use the SHA1 generator to generate a random passoword instead of giving real and we can just put first 5 characteres in it to check



def request_api_data(query_char):
    url = 'z/'+ query_char
    res = requests.get(url)
    if res.status_code !=200:
        raise RuntimeError(f'Error fetching : {res.status_code}, check the api and try again')
    return res       
               
def get_password_leaks_counts(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        
        if h == hash_to_check:
            return count
    return 0
    
def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)   
    return get_password_leaks_counts(response, tail)
    
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found{count} times..you should change your password')
        else:
            print(f'{password} was not found CARRY ON!')
    return 'done!'

if __name__ == '__main__':
    #sys.exit(main(sys.argv[1:]))
    
    with open('./password.txt','r') as file:
      sys.argv[0] = file.readlines()
      sys.exit(main(sys.argv[0]))
      
     
      
      
      
      