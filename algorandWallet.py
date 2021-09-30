import algosdk

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Algorand Wallet class
class algoWallet:

    # class constructor
    def __init__(self,filename = "algoWallet"):
        """
        Algorand Wallet class for handling of multiple wallets as well as encryption and decryption of private keys.
        Also contains functionality to send simple transactions and go online/offline for consensus.

        Args:
            filename (str) : Name of file that will be saved to and loaded from.
        
        Returns : wallet object
        """
        self.walletFileName = filename
        self.internalWallet = {}
        try:
            self.importWallet(filename)
        except FileNotFoundError:
            self.exportWallet(filename)
        self.generate = generate()

    ## ========================== ##
    ## BASIC WALLET FUNCTIONALITY ##
    ## ========================== ##

    # sets the disired name of the wallet file
    def setWalletFileName(self,fileName):
        """
        Changes the default wallet file

        Args:
            fileName (str) : name of file to use for importing and exporting
        """
        self.walletFileName = fileName

    # import wallet from wallet file
    def importWallet(self,fileName = None):
        """
        Imports wallet from file to internal wallet

        Args:
            fileName (str) : File to import, leave blank for default
        """

        import json
        if not fileName:
            fileName = self.walletFileName
        self.internalWallet = json.load(open(fileName,'r'))

    # export wallet to a file
    def exportWallet(self,fileName = None):
        """
        Exports internal wallet to file with certain file name

        Args:
            fileName (str) : File to save to, leave blank for default
        """
        import json
        if not fileName:
            fileName = self.walletFileName
        with open(fileName,'w') as file:
            json.dump(self.internalWallet,file,indent=4)

    # generates a new wallet
    def genAccount(self,name:str,password:str = None): 
        """
        Generates random account and adds it to internal wallet

        Args:
            name (str) : Name for the account, as it will appear in wallet
            password (str) : Password to use for encryption, leave blank for no encryption
        """

        private, public = algosdk.account.generate_account()
        self.makeAccount(name,private,password)

    # accept either mnemonic or private key as input to recover account
    def importAccount(self,name:str,private:str, password:str = None):
        """
        Import an account from an existing private key or mnemonic

        Args:
            name (str) : Name for the account, as it will appear in wallet
            private (str) : Private key OR mnemonic of account to add
            password (str) : Password to use for encryption, leave blank for no encryption
        """
        # check if given key is valid private key or mnemonic
        try:
            algosdk.account.address_from_private_key(private)
            private = private
        except:
            try:
                private = algosdk.mnemonic.to_private_key(private)
            except ValueError:
                raise ValueError("***Invalid private key/phrase. Please double check that it is correct.***")


        self.makeAccount(name,private,password)

    # make an account from private key (not for users)
    def makeAccount(self,name:str,private:str,password:str = None):
        """
        Generates account dictionary and appends it to the wallet file, encrypts if needed

        Args:
            name (str) : Name for the account, as it will appear in wallet
            private (str) : Private key (not mnemonic) of account to add
            password (str) : Password to use for encryption, leave blank for no encryption
        """
        # derive pubilc and mnemonic from private key
        public = algosdk.account.address_from_private_key(private)
        mnemonic = algosdk.mnemonic.from_private_key(private)

        # if password is given, encrypt all all contents
        if password:
            [public,private,mnemonic],salt = self.encryptContents([public,private,mnemonic],password)
        else:
            salt = ""

        # create wallet dict
        newWallet = {
            str(name) : { 
                "account": {
                    "public" : public,
                    "private" : private,
                    "mnemonic" : mnemonic
                },
                "fernetsalt" : salt
            }
        }

        # update internal wallet file with information
        try:
            self.internalWallet[name]
            print("An account with this name already exists. If you want to overwrite it, type 'yes', anything else will cancel.")
            if (input().lower() != "yes"):
                return
        except:
            pass

        self.internalWallet.update(newWallet)

    # TODO (func) renames an existing account.
    def renameAccount(self,oldName,newName,password = False):
        """
        "Functionality not yet implemented"
        """
        print("Functionality not yet implemented")
    
    # TODO (func) delete an existing account.
    def removeAccount(self,name):
        """
        "Functionality not yet implemented"
        """
        print("Functionality not yet implemented")

    ## ================ ##
    ## GET ACCOUNT INFO ##
    ## ================ ##

    # gets the public address for an account in wallet
    def getPublic(self,account:str,pw:str = None):
        """
        Gets encrypted or unencrypted public key from some account in wallet file

        Args:
            account (str) : Name of account to retrieve public key from
            pw (str) : Password for encrypted account (if needed)

        Returns: Public key (str)
        """
        try:
            if self.getSalt(account) == "":
                return self.internalWallet[account]["account"]["public"]
            else:
                if pw:
                    return self.decryptPublic(account,pw)
                else:
                    return self.decryptPublic(account,password(account))
        except KeyError:

            # also try contact
            try:
                return self.internalWallet[account]["contact"]["public"]
            except KeyError:
                print("No account or contact named '" + account + "' exists.")

    # gets the private key for an account in wallet
    def getPrivate(self,account:str,pw:str = None):
        """
        Gets encrypted or unencrypted private key from some account in wallet file

        Args:
            account (str) : Name of account to retrieve private key from
            pw (str) : Password for encrypted account (if needed)

        Returns: Private key (str)
        """
        try:
            if self.getSalt(account) == "":
                return self.internalWallet[account]["account"]["private"]
            else:
                if pw:
                    return self.decryptPrivate(account,pw)
                else:
                    return self.decryptPrivate(account,password(account))
        except KeyError:
            print("No account named '" + account + "' exists.")

    # gets the private mnemonic for an account in wallet
    def getMnemonic(self,account:str,pw:str = None):
        """
        Gets encrypted or unencrypted mnemonic from some account in wallet file

        Args:
            account (str) : Name of account to retrieve mnemonic from
            pw (str) : Password for encrypted account (if needed)
    
        Returns: Private mnemonic (str)
        """

        try:
            if self.getSalt(account) == "":
                return self.internalWallet[account]["account"]["mnemonic"]
            else:
                if pw:
                    return self.decryptMnemonic(account,pw)
                else:
                    return self.decryptMnemonic(account,password(account))
        except KeyError:
            print("No account named '" + account + "' exists.")

    ## ====================== ##
    ## CONACTS / ADDRESS BOOK ##
    ## ====================== ##

    # add a contact to address book for certain account
    def addContact(self,contact:str,publicAddr:str):
        """
        Add a contact with a certain name to the wallet

        Args:
            contact (str) : Name of contact as it will appear in wallet file
            publicAddr (str) : Public address of contact
        """
        if  algosdk.encoding.is_valid_address(publicAddr):
            try:
                self.internalWallet[contact]["contact"].update({contact:publicAddr})
            except KeyError:
                try:
                    self.internalWallet[contact]["account"]
                    print("An account with this name already exists. If you want to overwrite it, type 'yes', anything else will cancel.")
                    if (input().lower() != "yes"):
                        return
                except:
                    pass    
                self.internalWallet.update({contact:{"contact" : {"public":publicAddr}}})
        else:
            raise Exception("Invalid Algorand account address.")

    # removes contact from certain accounts addressbook
    def removeContact(self,contact:str):
        """
        Remove contact from wallet

        Args:
            contact (str) : Contact to remove
        """
        try:
            del self.internalWallet[contact]
        except KeyError:
            print("No contact named " + contact + " exists.")

    ## ============================== ##
    ## WALLET ENCRYPTION / DECRYPTION ##
    ## ============================== ##

    # returns the salt value for any account or contact
    def getSalt(self,name:str):
        """
        Returns the salt of some account

        Args: name (str) : Name of account to retrieve salt from
        Returns : salt (str)
        """
        return self.internalWallet[name]["fernetsalt"]
   
    # generate fernet key with given salt and password
    def fernetGenerator(self,salt:bytes,password:str):
        """
        Generates Fernet key from some salt and password

        Args:
            salt (str) or (bytes) : Salt to use for encryption
            password (str) : Password to use for enctyption

        Returns: Fernet key used for encryption and decryption
        """
        wallet_password_byte = password.encode()
        import base64

        #if provided salt was encoded as as a string, decode it
        if type(salt) is str:
            salt = base64.b64decode(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length = 32,
            salt = salt,
            iterations = 100000,
            backend=default_backend()
        )
        # generate fernet key
        return Fernet(base64.urlsafe_b64encode(kdf.derive(wallet_password_byte)))

    # encrypts the contents using a specific password
    def encryptContents(self,contents:str,password:str):

        """
        Encrypts any content

        Args:
            contents (str) or list(str) : Content to encrypt
            password (str) : Password to use for encryption

        Returns: Encrypted contents (str) or list(str)
        """

        # Encryption of private information
        # creates Fernet compatible password key
        import os
        import base64
        salt = os.urandom(32)
        fern = self.fernetGenerator(salt,password)
    
        # iterate and encrypt input if given as a list
        if type(contents) is list:
            output = []
            for i in range(len(contents)):
                output.append(fern.encrypt(bytes(contents[i], 'utf-8')).decode())
            return output , base64.b64encode(salt).decode()
        else:
            return fern.encrypt(bytes(contents, 'utf-8')).decode() , base64.b64encode(salt).decode()
    
    # encrypt the contents of an account
    def encryptAccount(self,name:str,password:str):
        """
        Encrypts all the contents of an account and saves it to the internalWallet object

        Args:
            name (str) : Name of account to decrypt
            password (str) : Password for encrypted account
        """

        # check if account does not exist or is encrypted
        try:
            if self.getSalt(name) != "":
                print("This account is already encrypted.")
                return
        except:
            raise KeyError("This account does not have a fetnet salt")

        try:
            private = self.internalWallet[name]["account"]["private"]
        except KeyError:
            private = algosdk.mnemonic.to_private_key(self.internalWallet[name]["account"]["mnemonic"])

        self.makeAccount(name,private,password)

    # decrypt the contents of an account
    def decryptAccount(self,name:str,password:str):

        """
        Decrypts all the contents of an account and saves it to the internalWallet object

        Args:
            name (str) : Name of account to decrypt
            password (str) : Password for encrypted account
        """

        # check if account is even encrypted
        try:
            if self.getSalt(name) == "":
                print("This account is not encrypted.")
                return
        except:
            raise KeyError("This account does not have a fetnet salt")

        private = self.decryptPrivate(name,password)
        self.makeAccount(name,private)

    # decrypt any encrypted content if has salt and password
    def decryptContents(self,contents,salt,password):
        fern = self.fernetGenerator(salt,password)
        return fern.decrypt(bytes(contents, 'utf-8')).decode()

    # decrypt and get the public address of account or contact
    def decryptPublic(self,name:str,password:str):
        """
        Decrypts the public key of an account in the Wallet

        Args:
            name (str) : Name of account to decrypt
            password (str) : Password for encrypted account

        Returns: Decrypted public key
        """
        fern = self.fernetGenerator(self.getSalt(name),password)
        # first, try to look for matching account
        try:
            try:
                public = fern.decrypt(bytes(self.internalWallet[name]["account"]["public"], 'utf-8')).decode()
            except cryptography.fernet.InvalidToken:
                raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
        except KeyError:

            # second, try to look for a contact
            try:
                try:
                    public = fern.decrypt(bytes(self.internalWallet[name]["contact"]["public"], 'utf-8')).decode()
                except cryptography.fernet.InvalidToken:
                    print("Invalid password for '{}', decryption failed.".format(name))
            except KeyError:
                raise KeyError("This account or contact does not exist.")
        
        # finally return
        return public

    # decrypt and get the private key of an account
    def decryptPrivate(self,name:str,password:str):
        """
        Decrypts the private key of an account in the Wallet

        Args:
            name (str) : Name of account to decrypt
            password (str) : Password for encrypted account

        Returns: Decrypted private key
        """

        fern = self.fernetGenerator(self.getSalt(name),password)
        try:
            return fern.decrypt(bytes(self.internalWallet[name]["account"]["private"], 'utf-8')).decode()
        except cryptography.fernet.InvalidToken:
            raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
        
    # decrypt and get the private mnemonic of an account
    def decryptMnemonic(self,name:str,password:str):
        """
        Decrypts the Mnemonic of an account in the Wallet

        Args:
            name (str) : Name of account to decrypt
            password (str) : Password for encrypted account

        Returns: Decrypted private mnemonic
        """
        fern = self.fernetGenerator(self.getSalt(name),password)
        try:
            return fern.decrypt(bytes(self.internalWallet[name]["account"]["mnemonic"], 'utf-8')).decode()
        except cryptography.fernet.InvalidToken:
            raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
    
    ## ============================= ##
    ## TRANSACTION / SIGNATURE STUFF ##
    ## ============================= ##

    # TODO algosdk.encoding.transaction.xxxxxx is outdated and it should be using algosdk.future.transaction.xxxxxx instead

    # transact algos offline (you must supply all parameters manually)
    def makeSendAlgoTx(self,name:str,reciever,amount, params, password = None, microAlgos = False):

        """
        Simple function for creating a signed Algo transaction

        Args:
            name (str) : Account used to send Algos from
            reciever : Address or name in wallet file of recipient
            amount : Number of algos to send to recipient
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            password (str) : If needed, password used to decrypt wallet.
            microAlgos (bool) : Switch to micro Algos instead of full algos (muiltiply by 1_000_000)

        Returns: signed transaction
        """
        
        # try to convert to dictionary
        try:
            params = vars(params)
        except:
            pass

        rcv_address = reciever
        public = self.getPublic(name,password)
        private = self.getPrivate(name,password)

        # check if wallet wallet is encrypted and password is provided
        try:
            if ((self.getSalt(name) != "") and not password):
                raise UserWarning("This wallet is encrypted, please provide a password.")
        except KeyError as e:
            raise KeyError("No account exists with that name : {}".format(e))

        # decrypt public address if password is provided
        if password:
            try:
                public = self.decryptPublic(name,password)
                private = self.decryptPrivate(name,password)
            except SyntaxWarning as e:
                raise SyntaxWarning(("Invalid password provided, transaction canceled : {}").format(e))

        # check if reciever is address, or if they exist in address book
        if not algosdk.encoding.is_valid_address(rcv_address):
            try:
                rcv_address = self.getPublic(reciever)
                print("Found " + reciever + " in addressbook.")
            except KeyError as e:
                print("No valid address or contact for : " + reciever)
                return

        # format amount to Algos instead of mAlgos
        if not microAlgos:
            amount = amount*1000000


        raw_data = {
            "amt": int(amount),         # unit is microAlgos
            "fee": int(params["fee"]),                 # data["fee"] ~ 0.001 Algos
            "first": int(params["lastRound"]),        # first valid block
            "last": int(params["lastRound"]+1000),  # last valid block
            "gen": params["genesisID"],          # network
            "receiver": rcv_address,            # reciever address
            "sender": public,     # sender address
            "gh": params["genesishashb64"]          # genisis hash
        }

        tx = algosdk.encoding.transaction.PaymentTxn(**raw_data,)
        return tx.sign(private)

    # generate the string needed to generate participation keys
    def addPartKey(self,name:str,params,rounds:int,password:str = None):
        """
        Prints the line that is needed for generating participation keys on an Algorand node

        Args:
            name (str) : Name of account in wallet file to generate participation key for
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            rounds (int) : Number of rounds for participation key to be valid
            password (str) : If needed, password used to decrypt wallet.

        Returns: prints to command line
        """
         # try to convert to dictionary
        try:
            params = vars(params)
        except:
            pass

        print("To participate en consensus, you will need to generate a participation key on your node.")
        print("It may be nessecary to add 'sudo' if goal is installed in a root directory.")
        print("It may also be nessecary to add -d $ALGORAND_DATA at the end.")

        # either go online or offline to be a good faith consensus participant
        if password:
            print("===========")
            print("goal account addpartkey -a {a} --roundFirstValid={f} --roundLastValid={l} -d /var/lib/algorand".format(a=self.decryptPublic(name,password),f=params["lastRound"],l=params["lastRound"]+rounds))
            print("===========")
        else:
            print("===========")
            print("goal account addpartkey -a {a} --roundFirstValid={f} --roundLastValid={l} -d /var/lib/algorand".format(a=self.getPublic(name),f=params["lastRound"],l=params["lastRound"]+rounds))
            print("===========")

    # generate transaction data that commits an account to be online or offline for consensus
    def participateConsensus(self,name:str,params,partkeyinfo:dict = None,password:str = None):
        """
        Allows for changing participation status on Algorand, also known as "going online" or "going offline"

        Args:
            name (str) : Name of account in wallet file to change participation status of
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            partkeyinfo (dict) : Participation info gotten from personal node using 'goal account partkeyinfo'
            password (str) : If needed, password used to decrypt wallet.

        Returns: signed transaction with signature
        """
        import base64

        #if online and not partkeyinfo:
        #    raise ValueError("Participation key info has to be provided to register as online.")

         # try to convert to dictionary
        try:
            params = vars(params)
        except:
            pass

        if partkeyinfo:
            data = {
                "sender": self.getPublic(name,password),
                "votekey": algosdk.encoding.encode_address(base64.b64decode(partkeyinfo["vote"])),
                "selkey": algosdk.encoding.encode_address(base64.b64decode(partkeyinfo["sel"])),
                "votefst": partkeyinfo["first"],
                "votelst": partkeyinfo["last"],
                "votekd": partkeyinfo["voteKD"],
            }
        else:
            data = {
                "sender": self.getPublic(name,password),
                "votekey": None,
                "selkey": None,
                "votefst": None,
                "votelst": None,
                "votekd": None,
            }

        data.update(
                {"fee": 1000,
                "flat_fee": True,
                "first": params["lastRound"],
                "last": params["lastRound"]+1000,
                "gen": params["genesisID"],
                "gh": params["genesishashb64"]}
        )

        tx = algosdk.encoding.transaction.KeyregTxn(**data,)
        return tx.sign(self.getPrivate(name,password))

class generate():

    def governanceCommitNote(commit_amount:int) -> str:
        return "af/gov1:j{\"com\":" + str(commit_amount) + "}"

    def governanceVoteRaw(vote:str) -> str:
        return f"af/gov1:j[{vote}]"

    def governanceVoteNote(vote_round:int,cast_votes:list[str]) -> str:
        xvotes = ""
        if type(cast_votes) == list:
            for i in range(len(cast_votes)):
                xvotes +="\"" + str(cast_votes[i]) + "\""
                if i + 1 < len(cast_votes):
                    xvotes += ","
        else:
            xvotes = cast_votes
        return f"af/gov1:j[{vote_round}:{xvotes}]"

# Request password from user
def password(name = None):
    """
    Requests a password from the user.

    Args:
        name (str) : Name of account password belongs to

    Returns: password entered by user.
    """
    import getpass
    if name:
        print("Please provide the password for decrypting '{}'.".format(name))
    else:
        print("Please provide the password for decrypting the account.")
    return getpass.getpass()

## ==================================== ##
## PUT CODE TO RUN AT SCRIPT START HERE ##
## ==================================== ##

if __name__ == '__main__':
    print("Welcome to the Algorand Wallet written in Python.")
    print("For now, a help() function has not been implemented, please")
    print("see the example code at the bottom of the algorandWallet.py file.")

## ========= ##
## DEMO CODE ##
## ========= ##

## Creates wallet object
#wallet = algoWallet("algorandWallet")
#
## Creates a connection to the AlgoExplorer API
#import AlgoExplorerAPI as ae
#node = ae.node("mainnet")
#
## OR!
#
## Transact using a personal node
#address = "http://192.168.1.10:8080"
#token = "b742378b134679a314879c5674d67930125678b146570e189670cbe"
#node = algosdk.algod.AlgodClient(token,address) 
#
## Fetch suggested parameters from either API or node
#params = node.suggested_params()
#
## Generates an account and encrypts it using a password
#wallet.genAccount("primary_account","myPassword1234!")
#
## Adds a contact and gives it easy to type name
#wallet.addContact("Algorand8","APDO5T76FB57LNURPHTLAGLQOHUQZXYHH2ZKR4DPQRKK76FB4IAOBVBXHQ")
#
## Exports wallet to a file (in this case to "algorandWallet")
#wallet.exportWallet()
#
## Sends 0.1337 Algos to Algorand8 on testnet, and decrypts the wallet for signing
#txA = wallet.makeSendAlgoTx("primary_account","Algorand8",0.1337,params,"myPassword1234!")
#
## https://developer.algorand.org/docs/run-a-node/participate/generate_keys/
#partkeyinfo = {}
#
## Registers as online for participation in consensus
#txB = wallet.participateConsensus("primary_account",params,partkeyinfo,"myPassword1234!","online")
#
## Sends transaction and catches transaction ID
#txnoteA = node.send_transaction(txA) # Posts money transfer transaction to blockchain
#txnoteB = node.send_transaction(txB) # Posts consensus participation transaction to blockchain
#
## Prints links to AlgoExplorer transaction page 
## !!This will only work for the AlgoExplorerAPI node!!
#print( node.explorer_tx(txA) ) 
#print( node.explorer_tx(txB) )