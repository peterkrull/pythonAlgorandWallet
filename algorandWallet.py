from Cryptodome.Hash.SHA512 import new
import algosdk

from cryptography.fernet import Fernet, InvalidToken
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

    ## ========================== ##
    ## BASIC WALLET FUNCTIONALITY ##
    ## ========================== ##

    # sets the disired name of the wallet file
    def setWalletFileName(self,fileName:str):
        """
        Changes the default wallet file

        Args:
            fileName (str) : name of file to use for importing and exporting
        """
        self.walletFileName = fileName

    # import wallet from wallet file
    def importWallet(self,fileName:str = None):
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
    def exportWallet(self,fileName:str = None):
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
        newAccount = {
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
        if name in self.internalWallet:
            print("An account with this name already exists. If you want to overwrite it, type 'yes', anything else will cancel.")
            if (input().lower() == "yes"):
                self.internalWallet.update(newAccount)

    # renames an existing account.
    def renameAccount(self,oldName:str,newName:str):
        """
        Allows for renaming of accounts (and contacts) in wallet

        Args:
            oldName (str) : Name of wallet to change name of
            newName (str) : New name of wallet
        """

        account = {newName:self.internalWallet[oldName]}
        self.removeAccount(oldName,False)
        self.internalWallet.update(account)

        print("The account '{}' has been renamed to '{}'".format(oldName,newName))
    
    # delete an existing account.
    def removeAccount(self,name:str,verbose = True):
        """
        Allows for removal of accounts (and contacts) from wallet

        Args:
            name (str) : Name of wallet to remove
        """

        del self.internalWallet[name]
        if verbose:
            print("The account '{}' has been removed from wallet".format(name))

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
            return self.internalWallet[account]["contact"]["public"]

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

        # Check for address validity
        if not algosdk.encoding.is_valid_address(publicAddr):
            raise InvalidAddress(publicAddr)

        # Check if address fied is already occupied
        if contact in self.internalWallet:
            print("An account with this name already exists. If you want to overwrite it, type 'yes', anything else will cancel.")
            if (input().lower() != "yes"):
                return

        # Update contact
        self.internalWallet.update({contact:{"contact" : {"public":publicAddr}}})

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

    # add governance account
    def addGovernanceContact(self,publicAddr:str):
        self.addContact("governance",publicAddr)

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
            except InvalidToken:
                raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
        except KeyError:

            # second, try to look for a contact
            try:
                try:
                    public = fern.decrypt(bytes(self.internalWallet[name]["contact"]["public"], 'utf-8')).decode()
                except InvalidToken:
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
        except InvalidToken:
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
        except InvalidToken:
            raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
    
    ## ============================= ##
    ## TRANSACTION / SIGNATURE STUFF ##
    ## ============================= ##

    # generate a signed Algorand transaction object
    def makeSendAlgoTx(self,name:str,reciever:str,amount:int, params:algosdk.future.transaction.SuggestedParams, note:str = None, password:str = None, microAlgos:bool = False):
        """
        Simple function for creating a signed Algo transaction

        Args:
            name (str) : Account used to send Algos from
            reciever (str) : Address or name in wallet file of recipient
            amount (int) or (float) : Number of algos to send to recipient
            params (algosdk...SuggestedParams) : Suggested Algorand transaction parameters
            note (str) : Note field, used for short messages and voting on governance
            password (str) : If needed, password used to decrypt wallet.
            microAlgos (bool) : Switch to micro Algos instead of full algos (muiltiply by 1_000_000)

        Returns: signed transaction
        """    

        rcv_address = reciever
        public = self.getPublic(name,password)
        private = self.getPrivate(name,password)

        # check if reciever is address, or if they exist in address book
        if not algosdk.encoding.is_valid_address(rcv_address):
            try:
                rcv_address = self.getPublic(reciever)
                print("Found {} in addressbook.".format(reciever))
            except KeyError as e:
                raise NoValidContact(reciever)

        # format amount to Algos instead of mAlgos
        if not microAlgos:
            amount = algosdk.util.algos_to_microalgos( amount )

        if type(params) == dict:
            params = algoWallet.params_dict_to_object(params)

        tx = algosdk.future.transaction.PaymentTxn(
            public,
            params,
            rcv_address,
            int(amount),
            note = note
        )

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
        Wether the account goes online or offline depends on if the partkeyinfo parameter is supplied, or is left at None

        Args:
            name (str) : Name of account in wallet file to change participation status of
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            partkeyinfo (dict) : Participation info gotten from personal node using 'goal account partkeyinfo'
            password (str) : If needed, password used to decrypt wallet.

        Returns: signed transaction with signature
        """
        
        if type(params) == dict:
            params = algoWallet.params_dict_to_object(params)

        if partkeyinfo:
            data = {
                "sender": self.getPublic(name,password),
                "votekey": partkeyinfo["vote"],
                "selkey": partkeyinfo["sel"],
                "votefst": partkeyinfo["first"],
                "votelst": partkeyinfo["last"],
                "votekd": partkeyinfo["voteKD"],
                "sp":params
            }
        else:
            data = {
                "sender": self.getPublic(name,password),
                "votekey": None,
                "selkey": None,
                "votefst": None,
                "votelst": None,
                "votekd": None,
                "sp":params
            }

        tx = algosdk.future.transaction.KeyregTxn(**data,)
        return tx.sign(self.getPrivate(name,password))

    # generate transaction data to commit Algos to governance
    def governanceCommit(self,name:str, params, commit_amount:int, password:str = None, governance_acount:str = "governance",full_algo = False):
        """
        Generates signed transaction for participating in Algorand governance

        Args:
            name (str) : Name of account in wallet file to commit to governance
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            commit_amount (int) : number of micro Algos or Algos to commit to governance (see full_algo)
            password (str) : If needed, password used to decrypt wallet.
            governance_acount (str) : address or name in contact list of governancen account
            full_algo (bool) : Wether to use full Algos or micro Algos -> True for full Algos

        Returns: prints to command line
        """  

        if type(params) == dict:
            params = algoWallet.params_dict_to_object(params)

        if full_algo:
            gov_note = generate.governanceCommitNote( algosdk.util.algos_to_microalgos( commit_amount) )
        else:
            gov_note = generate.governanceCommitNote( commit_amount )

        if not algosdk.encoding.is_valid_address(governance_acount):
            try:
                governance_acount = self.getPublic(governance_acount)
                print("Found governance account in addressbook.")
            except KeyError as e:
                print("No valid address or contact for : " + governance_acount)
                return

        tx = algosdk.future.transaction.PaymentTxn(
            self.getPublic(name,password),
            params,
            governance_acount,
            0,
            note = gov_note
        )

        return tx.sign(self.getPrivate(name,password))

    # generate transaction data to cast a vote in governance
    def governanceVote(self,name:str,params,vote_round:int,cast_votes:str,password = None, governance_acount:str = "governance"):
        """
        Generates signed transaction for voting in Algorand governance

        Args:
            name (str) : Name of account in wallet file to generate participation key for
            params : Suggested Algorand transaction parameters ( see AlgodClient.suggested_params() )
            vote_round (int) : Round of governance voting to cast a vote in
            cast_votes list(str) : list containing strings of votes to cast
            password (str) : If needed, password used to decrypt wallet.
            governance_acount (str) : address or name in contact list of governancen account

        Returns: prints to command line
        """     

        if type(params) == dict:
            params = algoWallet.params_dict_to_object(params)

        govNote = generate.governanceVoteNote(vote_round,cast_votes)

        if not algosdk.encoding.is_valid_address(governance_acount):
            try:
                governance_acount = self.getPublic(governance_acount)
                print("Found governance account in addressbook.")
            except KeyError as e:
                print("No valid address or contact for : " + governance_acount)
                return

        tx = algosdk.future.transaction.PaymentTxn(
            self.getPublic(name,password),
            params,
            governance_acount,
            0,
            note = govNote
        )

        return tx.sign(self.getPrivate(name,password))

    # converts a suggested parameters dictionary to a SuggestedParams-object 
    def params_dict_to_object(params:dict):
        return algosdk.future.transaction.SuggestedParams(
            params["fee"],
            params["lastRound"],
            params["lastRound"] + 1000,
            params["genesishashb64"],
            params["genesisID"],
            False)

class generate():

    # generate string that commits Algos for governance
    def governanceCommitNote(commit_amount:int) -> str:
        """
        Generates a properly formatted string commiting algos for Algorand Governance proposals.

        Args:
            commit_amount (int) : Amount of micro Algos to commit for governance

        Returns: Formatted string
        """
        return "af/gov1:j{\"com\":" + str(int(commit_amount)) + "}"

    # generate string that casts votes in governance (primary method)
    def governanceVoteNote(vote_round:int,cast_votes:str) -> str:
        """
        Generates a properly formatted string for voting on Algorand Governance proposals.
        This should be added to the note field of a transaction to a specific governance address.
        Votes should be entered like this:  `governanceVoteNote(23,["b","c"])`

        Args:
            vote_round (int) : Round to vote in
            cast_votes (str) or list(str) : Votes to cast in governance proposal

        Returns: Formatted string
        """
        xvotes = ""
        if type(cast_votes) == list:
            for i in range(len(cast_votes)):
                xvotes +="\"" + str(cast_votes[i]) + "\""
                if i + 1 < len(cast_votes):
                    xvotes += ","
        else:
            xvotes = cast_votes
        return f"af/gov1:j[{vote_round},{xvotes}]"

    # generate string that casts votes in governance (secondary method)
    def governanceVoteRaw(vote:str) -> str:
        """
        Generates a properly formatted string for voting on Algorand Governance proposals.
        This should be added to the note field of a transaction to a specific governance address.
        See also `governanceVoteNote()`

        Args:
            vote (int) : Round to vote in as well as votes to cast in governance proposal

        Returns: Formatted string
        """
        return f"af/gov1:j[{vote}]"

class NoValidContact(Exception):
    """
    Exception for when a contact does not exist in the address book.
    
    Args:
        contact (str) : name of contact that could not looked up
        custom_message (str) : overwrites the defult exception message of this class
    """
    def __init__(self,contact,custom_message=None):
        message = custom_message if custom_message else "No contact named '{}' could be found in addressbook.".format(contact)
        super().__init__(message)

class NoValidAccount(Exception):
    """
    Exception for when an account does not exist in the address book / wallet.
    
    Args:
        account (str) : name of account that could not looked up
        custom_message (str) : overwrites the defult exception message of this class
    """
    def __init__(self,account,custom_message=None):
        message = custom_message if custom_message else "No account named '{}' could be found in wallet.".format(account)
        super().__init__(message)

class InvalidAddress(Exception):
    """
    Exception for if a supplied Algorand address is invalid
    
    Args:
        address (str) : Address that is invalid
        custom_message (str) : overwrites the defult exception message of this class
    """
    def __init__(self,address,custom_message=None):
        message = custom_message if custom_message else "The address '{}' is not a valid Algorand address.".format(address)
        super().__init__(message)

class IncorrectPassword(Exception):
    """
    Exception for if decryption of account failed due to incorrect password
    
    Args:
        account (str) : Account that failed to get decrypted
    """
    def __init__(self,account,custom_message=None):
        message = custom_message if custom_message else "Incorrect password for the account '{}'.".format(account)
        super().__init__(message)
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