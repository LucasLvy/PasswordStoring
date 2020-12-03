import os

import argon2
import tink
from tink import _keyset_writer
from tink import cleartext_keyset_handle
from tink import daead


"""only use once"""
def generate_and_save_key():
    daead.register()
    keyset = open('keys.json', 'w')
    cleartext_keyset_handle.write(_keyset_writer.JsonKeysetWriter(keyset),tink.new_keyset_handle(
        daead.deterministic_aead_key_templates.AES256_SIV))  # we save the generated key in a txt file
    keyset.close()

"""hashes the password with a given salt"""
def hash_password(salt, pwd):
    return argon2.hash_password_raw(password=pwd, salt=salt, time_cost=16, memory_cost=2 ** 15, parallelism=1,
                                    hash_len=32, type=argon2.low_level.Type.ID)


"""cipher the given message (the password hash here)"""
def encryption_machine(msg):
    daead.register()
    return cleartext_keyset_handle.read(tink.JsonKeysetReader(open('keys.json', 'r').read())).primitive(
        daead.DeterministicAead).encrypt_deterministically(msg, b'a')


"""saves the username, the password and the salt in the database"""
def save_to_database(user, pwd):
    salt = os.urandom(20)  # salt generation
    db = open(database, 'a')  # append mode so it doesn't delete the previously saved data
    db.write(user + ':' + salt.hex() + ':' + encryption_machine(hash_password(salt,
                                                                              pwd)).hex() + '\n')  # storing the data in hexadecimal so it's easier to check if the password is good
    db.close()

"""checks if the password corresponds to the username"""
def check_password(user, pwd):
    data = []
    db = open(database, 'r')
    for lines in db:
        data.append(lines.rstrip('\n').split(':'))  # separates the username, the salt and the password
    db.close()
    for x in data:
        if x[0] == user:  # looks for the given username
            return str(encryption_machine(hash_password(bytes.fromhex(x[1]), pwd)).hex()) == x[
                2]  # returns if the password is good or not
    return False  # if the username is wrong returns false


database = 'database.txt'
generate_and_save_key()  # only use the first time or when we want to change the key
save_to_database('john', b'panda')
save_to_database('johnny', b'pandy')
save_to_database('johnou', b'pandou')
print(check_password('johnou', b'pandou'))
