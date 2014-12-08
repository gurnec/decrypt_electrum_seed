#!/usr/bin/python

# decrypt_electrum_seed.py
# Copyright (C) 2014 Christopher Gurnee
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           1Lj3kXWTuYaRxvLndi6VZKj8AYa3KP929B
#
#                      Thank You!

__version__ = '0.2.2'

import sys, warnings, ast, hashlib, getpass, atexit, unicodedata
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
import mnemonic


def simple_warn(message, *ignored):
    print >> sys.stderr, message

warnings.showwarning = simple_warn
warn = warnings.warn


def decrypt_electrum_seed(wallet_file, get_password_fn):
    """decrypt the seed in an Electrum wallet file

    :param wallet_file: an open Electrum file
    :type wallet_file: file
    :param get_password_fn: a callback returning a password that's called iff one is required
    :type get_password_fn: function
    :return: the (typically hex-encoded) decrypted key and the mnemonic
    :rtype: (str, str)
    """

    with wallet_file:
        wallet = ast.literal_eval(wallet_file.read())

    seed_version = wallet.get('seed_version')
    if seed_version is None:
        warn('seed_version not found')
    elif seed_version != 4:
        warn('unexpected seed_version: ' + str(seed_version))

    if wallet.get('use_encryption'):

        b64_encrypted_data = wallet['seed']

        # Carefully check base64 encoding and truncate it at the first unrecoverable character group
        b64_chars_set = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
        assert len(b64_chars_set) == 64
        for i in xrange(0, len(b64_encrypted_data), 4):  # iterate over 4-character long groups
            char_group_len = len(b64_encrypted_data[i:])

            if char_group_len == 1:
                warn("ignoring unrecoverable base64 suffix {!r} in encrypted seed".format(b64_encrypted_data[i:]))
                b64_encrypted_data = b64_encrypted_data[:i]
                break

            elif 2 <= char_group_len <= 3:
                warn("adding padding to incomplete base64 suffix {!r} in encrypted seed".format(b64_encrypted_data[i:]))
                b64_encrypted_data += '=' * (4 - char_group_len)

            for j,c in enumerate(b64_encrypted_data[i:i+4]):  # check the 4 characters in this group
                if c not in b64_chars_set:
                    if j > 1 and c == '=':   # padding characters are allowed in positions 2 and 3 of a group,
                        b64_chars_set = '='  # and once one is found all the rest must be padding
                    else:
                        warn("found invalid base64 char {!r} at position {} in encrypted seed; ignoring the rest".format(c, i+j))
                        if j <= 1:  # character groups of length 0 or 1 are invalid: the entire group is truncated
                            b64_encrypted_data = b64_encrypted_data[:i]
                        else:       # else truncate and replace invalid characters with padding
                            b64_encrypted_data = b64_encrypted_data[:i+j]
                            b64_encrypted_data += '=' * (4-j)
                        break

        # Decode base64 and then extract the IV and encrypted_seed
        iv_and_encrypted_seed = b64_encrypted_data.decode('base64')
        if len(iv_and_encrypted_seed) != 64:
            warn('encrypted seed plus iv is {} bytes long; expected 64'.format(len(iv_and_encrypted_seed)))
        iv             = iv_and_encrypted_seed[:16]
        encrypted_seed = iv_and_encrypted_seed[16:]
        if len(encrypted_seed) < 16:
            warn('length of encrypted seed, {}, is less than one AES block (16), giving up'.len(encrypted_seed))
            return None, None
        encrypted_seed_mod_blocksize = len(encrypted_seed) % 16
        if encrypted_seed_mod_blocksize != 0:
            warn('length of encrypted seed, {}, is not a multiple of the AES block size (16); truncating {} bytes'
                 .format(len(encrypted_seed), encrypted_seed_mod_blocksize))
            encrypted_seed = encrypted_seed[:-encrypted_seed_mod_blocksize]

        password = get_password_fn()  # get a password via the callback
        if not password:
            return None, None
        if unicodedata.normalize('NFC', password) != unicodedata.normalize('NFD', password):
            if password == unicodedata.normalize('NFC', password):
                the_default = 'NFC'
            elif password == unicodedata.normalize('NFD', password):
                the_default = 'NFD'
            else:
                the_default = 'a combination'
            warn('password has different NFC and NFD encodings; only trying the default ({})'.format(the_default))
        password = password.encode('UTF-8')

        # Derive the encryption key
        key = hashlib.sha256( hashlib.sha256( password ).digest() ).digest()

        # Decrypt the seed
        key_expander  = aespython.key_expander.KeyExpander(256)
        block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key)) )
        stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
        stream_cipher.set_iv(bytearray(iv))
        seed = bytearray()
        for i in xrange(0, len(encrypted_seed), 16):
            seed.extend( stream_cipher.decrypt_block(map(ord, encrypted_seed[i:i+16])) )
        padding_len = seed[-1]
        # check for PKCS7 padding
        if not (1 <= padding_len <= 16 and seed.endswith(chr(padding_len) * padding_len)):
            warn('not removing invalid PKCS7 padding (the password was probably entered wrong)')
            seed = str(seed)
        else:
            seed = str(seed[:-padding_len])

    else:
        seed = wallet['seed']

    if len(seed) != 32:
        warn('decrypted seed is {} characters long, expected 32'.format(len(seed)))

    # Carefully check hex encoding and truncate it at the first non-hex digit
    hex_seed = seed
    for i,h in enumerate(hex_seed):
        if not ('0' <= h <= '9' or 'a' <= h <= 'f'):
            if 'A' <= h <= 'F':
                warn('found unexpected capital hex digit')
            else:
                warn("found invalid hex digit {!r} at position {} in decrypted seed; ignoring the rest".format(h, i))
                hex_seed = hex_seed[:i]
                break

    # Count number of hex digits for informational purposes
    if len(hex_seed) != len(seed):
        hex_digit_count = 0
        for h in seed:
            if '0' <= h <= '9' or 'a' <= h <= 'f':
                hex_digit_count += 1
        warn('info: {} out of {} characters in decrypted seed are lowercase hex digits'
             .format(hex_digit_count, len(seed)))

    if len(hex_seed) < 8:
        warn('length of valid hex-encoded digits is less than 8, giving up')
        return seed, None
    else:
        if len(hex_seed) % 8 != 0:
            warn('length of hex-encoded digits is not divisible by 8, some digits will not be included in the mnemonic')
        return seed, ' '.join(mnemonic.mn_encode(hex_seed))


if __name__ == '__main__':

    if len(sys.argv) > 1:

        if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
            sys.exit('usage: decrypt_electrum_seed.py electrum-wallet-file')

        wallet_file = open(sys.argv[1])

        def get_password():
            encoding = sys.stdin.encoding or ''
            if 'utf' not in encoding.lower():
                warn('terminal does not support UTF; passwords with non-ASCII chars might not work')
            password = getpass.getpass('This wallet is encrypted, please enter its password:')
            if isinstance(password, str) and encoding:
                password = password.decode(encoding)  # convert from terminal's encoding to unicode
            return password

    else:

        atexit.register(lambda: raw_input("\nPress Enter to exit ..."))

        import Tkinter, tkFileDialog, tkSimpleDialog

        Tkinter.Tk().withdraw()  # initialize library but don't display a window

        wallet_file = tkFileDialog.askopenfile(title='Load wallet file')
        if not wallet_file:
            sys.exit('no wallet file selected')

        get_password = lambda: tkSimpleDialog.askstring('Password', "This wallet is encrypted, please enter its password:", show='*')

    seed_str, mnemonic_str = decrypt_electrum_seed(wallet_file, get_password)

    if seed_str:
        print "\nWARNING: seed information is sensitive, do not share"
        print 'decrypted seed (should be hex-encoded):', repr(seed_str)
        if mnemonic_str:
            print 'mnemonic-encoded seed:\n ', mnemonic_str
