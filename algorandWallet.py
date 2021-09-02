import base64
import algosdk

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Algorand Node class (AlgoExplorer)
class algoNode:
    
    # 'requests' library to interact with API
    req = __import__('requests')

    # class constructor, sets base url to chosen net type
    def __init__(self,net = "mainnet"):
        self.net = net.lower()
        if net.lower() == "mainnet":
            self.base_url = "https://algoexplorerapi.io/"
        elif net.lower() == "testnet":
            self.base_url = "https://testnet.algoexplorerapi.io/"
        elif net.lower() == "betanet":
            self.base_url = "https://betanet.algoexplorerapi.io/"
        else:
            print("Invalid net type : " + str(net) + " ; defaulting to testnet.")
            self.base_url = "https://testnet.algoexplorerapi.io/"
            self.net = "testnet"
    
    # returns relevant explorer URL
    def explorer(self):
        if self.net == "mainnet":
            return "https://algoexplorer.io/"
        elif self.net == "testnet":
            return "https://testnet.algoexplorer.io/"
        elif self.net == "betanet":
            return "https://betanet.algoexplorer.io/"

    # Returns true if the API is healthy    
    def getHealth(self):
        temp_url = self.base_url + "health"
        response = self.req.get(temp_url)
        return response.ok

    # Gets parameters for new transactions
    def getTxnParams(self):
        temp_url = self.base_url + "v2/transactions/params"
        response = self.req.get(temp_url)
        if response.ok:
            import ast
            return ast.literal_eval(bytes.decode(response.content)) 
        else:
            raise Exception("Can't connect to API. URL might be incorrect.")
    
    # Gets the last round/block
    def getLastRound(self):
        return self.getTxnParams()["last-round"]

    # Gets the genesis-has
    def getGenesisHash(self):
        return self.getTxnParams()["genesis-hash"]

    # Gets the genesis-has
    def getGenesisId(self):
        return self.getTxnParams()["genesis-id"]

    # Gets the genesis-has
    def getMinFee(self):
        return self.getTxnParams()["min-fee"]

    # Gets the genesis-has
    def getConsensusVer(self):
        return self.getTxnParams()["consensus-version"]

    # Gets the info related to a public address
    def getAccountInfo(self,public_addr):
        return self.getBlank("v2/accounts/" + str(public_addr))

    # Gets info from any arbitrary subdomain related to the API
    def getBlank(self,subdomain):
        temp_url = self.base_url + str(subdomain)
        response = self.req.get(temp_url)
        if response.ok:
            import ast
            return ast.literal_eval(bytes.decode(response.content))
        else:
            raise Exception("API call failed :{}".format(response.content))
    
    # make post transaction to the blockchain using API
    def makeTransaction(self,signed_txn):
        return self.req.post(self.base_url + "v2/transactions",signed_txn)

# Algorand Wallet class
class algoWallet:

    # class constructor
    def __init__(self,filename = "algoWallet",importInit = False):
        self.walletFileName = filename
        self.internalWallet = {}
        if importInit:
            self.importWallet(filename)

    ## ========================== ##
    ## BASIC WALLET FUNCTIONALITY ##
    ## ========================== ##

    # sets the disired name of the wallet file
    def setWalletFileName(self,fileName):
        self.walletFileName = fileName

    # import wallet from wallet file
    def importWallet(self,fileName = ""):
        import json
        if fileName == "":
            fileName = self.walletFileName
        self.internalWallet = json.load(open(fileName,'r'))

    # export wallet to a file
    def exportWallet(self,fileName = ""):
        import json
        if fileName == "":
            fileName = self.walletFileName
        with open(fileName,'w') as file:
            json.dump(self.internalWallet,file)

    # generates a new wallet
    def genAccount(self,name,password = False): 

        private, public = algosdk.account.generate_account()
        self.makeAccount(name,private,password)

    # accept either mnemonic or private key as input to recover account
    def importAccount(self,name,privateKey, password = False):

        # check if given key is valid private key or mnemonic
        try:
            algosdk.account.address_from_private_key(privateKey)
            private = privateKey
        except:
            try:
                private = algosdk.mnemonic.to_private_key(privateKey)
            except ValueError:
                raise ValueError("***Invalid private key/phrase. Please double check that it is correct.***")


        self.makeAccount(name,private,password)

    # make an account from private key (not for users)
    def makeAccount(self,name,private,password = False):
        # derive pubilc and mnemonic from private key
        public = algosdk.account.address_from_private_key(private)
        mnemonic = algosdk.mnemonic.from_private_key(private)

        # if password is given, encrypt all all contents
        if password:
            [public,private,mnemonic],salt = self.encryptContents([public,private,mnemonic],password)
            salt = salt.decode()
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
        self.internalWallet.update(newWallet)

    ## ================ ##
    ## GET ACCOUNT INFO ##
    ## ================ ##

    # gets the public address for an account in wallet
    def getPublic(self,account):
        try:
            return self.internalWallet[account]["account"]["public"]
        except KeyError:
            try:
                return self.internalWallet[account]["contact"]["public"]
            except KeyError:
                print("No account or contact named '" + account + "' exists.")

    # gets the private key for an account in wallet
    def getPrivate(self,account):
        try:
            return self.internalWallet[account]["account"]["private"]
        except KeyError:
            print("No account named '" + account + "' exists.")

    # gets the private mnemonic for an account in wallet
    def getMnemonic(self,account):
        try:
            return self.internalWallet[account]["account"]["mnemonic"]
        except KeyError:
            print("No account named '" + account + "' exists.")

    ## ====================== ##
    ## CONACTS / ADDRESS BOOK ##
    ## ====================== ##

    # add a contact to address book for certain account
    def addContact(self,contact,publicAddr):
        if  algosdk.encoding.is_valid_address(publicAddr):
            try:
                self.internalWallet[contact]["contact"].update({contact:publicAddr})
            except KeyError:
                self.internalWallet.update({contact:{"contact" : {"public":publicAddr}}})
        else:
            raise Exception("Invalid Algorand account address.")

    # removes contact from certain accounts addressbook
    def rmContact(self,contact):
        try:
            del self.internalWallet[contact]
        except KeyError:
            print("No contact named " + contact + " exists.")

    ## ============================== ##
    ## WALLET ENCRYPTION / DECRYPTION ##
    ## ============================== ##

    # returns the salt value for any account or contact
    def getSalt(self,name):
        try:
            return self.internalWallet[name]["fernetsalt"]
        except KeyError:
            print("No account named '" + name + "' exists.")
   
    # generate fernet key with given salt and password
    def fernetGenerator(self,salt,password):
        wallet_password_byte = password.encode()

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
    def encryptContents(self,contents,password):
        # Encryption of private information
        # creates Fernet compatible password key
        salt = os.urandom(32)
        fern = self.fernetGenerator(salt,password)
    
        # iterate and encrypt input if given as a list
        if type(contents) is list:
            output = []
            for i in range(len(contents)):
                output.append(fern.encrypt(bytes(contents[i], 'utf-8')).decode())
            return output , base64.b64encode(salt)
        else:
            return fern.encrypt(bytes(contents, 'utf-8')).decode() , base64.b64encode(salt)
    
    # encrypt the contents of an account
    def encryptAccount(self,name,password):

        # check if account does not exist or is encrypted
        try:
            if self.internalWallet[name]["fernetsalt"] != "":
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
    def decryptAccount(self,name,password):

        # check if account is even encrypted
        try:
            if self.internalWallet[name]["fernetsalt"] == "":
                print("This account is not encrypted.")
                return
        except:
            raise KeyError("This account does not have a fetnet salt")

        private = self.decryptPrivate(name,password)
        self.makeAccount(name,private)

    # TODO check if contents is even encrypted (check for salt)
    def decryptContents(self,contents,salt,password):
        fern = self.fernetGenerator(salt,password)
        return fern.decrypt(bytes(contents, 'utf-8')).decode()

    # decrypt and get the private key of an account
    def decryptPrivate(self,name,password):
        fern = self.fernetGenerator(self.getSalt(name),password)
        try:
            return fern.decrypt(bytes(self.internalWallet[name]["account"]["private"], 'utf-8')).decode()
        except cryptography.fernet.InvalidToken:
            raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
        
    # decrypt and get the private mnemonic of an account
    def decryptMnemonic(self,name,password):
        fern = self.fernetGenerator(self.getSalt(name),password)
        try:
            return fern.decrypt(bytes(self.internalWallet[name]["account"]["mnemonic"], 'utf-8')).decode()
        except cryptography.fernet.InvalidToken:
            raise SyntaxWarning("Invalid password for '{}', decryption failed.".format(name))
    
    # decrypt and get the public address of account or contact
    def decryptPublic(self,name,password):
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


    ## ============================= ##
    ## TRANSACTION / SIGNATURE STUFF ##
    ## ============================= ##

    # function to support simple Algo transactions using algoExplorer API
    def makeAlgoTxOnline(self,name,reciever,amount, algoNodeObj,password = False):

        # assume valid addresses first
        rcv_address = reciever
        public = self.getPublic(name)
        public = self.getPrivate(name)

        # check if wallet wallet is encrypted and password is provided
        try:
            if ((self.internalWallet[name]["fernetsalt"] != "") and not password):
                raise UserWarning("This wallet is encrypted, please provide a password.")
        except KeyError as e:
            raise KeyError("No account exists with that name : {}".format(e))

        # decrypt public address if password is provided
        if password:
            try:
                public = self.decryptPublic(name,password)
                private = self.decryptPrivate(name,password)
            except SyntaxWarning as e:
                raise SyntaxWarning(e)

        # validate that sender account has sufficient balance
        holdings = algoNodeObj.getAccountInfo(public)["amount"]
        if holdings - 500000 < amount*1000000:
            print("Insufficient balance. Has "+str(holdings/1000000)+" Algos, trying to send " + str(amount) + " Algos")
            print("You need to leave at least 0.5 Algos in your account at all times.")
        else:
            print("Sufficient balance, proceeding.")

        # if reciever is not an address, look in address book
        if not algosdk.encoding.is_valid_address(rcv_address):
            
            rcv_address = self.getPublic(reciever)

            if rcv_address == None:
                print("No valid address or contact for : " + reciever)
                return
            else:
                print("Found " + reciever + " in addressbook.")

        data = algoNodeObj.getTxnParams()

        raw_data = {
            "amt": int(amount*1000000),         # unit is microAlgos
            "fee": data["fee"],                 # data["fee"] ~ 0.001 Algos
            "first": data["last-round"],        # first valid block
            "last": data["last-round"] + 1000,  # last valid block
            "gen": data["genesis-id"],          # network
            "receiver": rcv_address,            # reciever address
            "sender": public,     # sender address
            "gh": data["genesis-hash"]          # genisis hash
        }

        return self.signTransaction(raw_data,private)    

    # transact algos offline (you must supply all parameters manually)
    def makeAlgoTxOffline(self,name,reciever,amount, first = "", last = "", fee = 0, microAlgos = False, gen = "", gh = "", net = "mainnet"):
        rcv_address = reciever

        if not algosdk.encoding.is_valid_address(rcv_address):
            try:
                rcv_address = self.getPublicContact(name,reciever)
                print("Found " + reciever + " in addressbook.")
            except KeyError as e:
                print("No valid address or contact for : " + reciever)
                return

        # format amount
        if not microAlgos:
            amount = amount*1000000

        # automatically add 1000 to last round
        if last == "":
            last = first + 1000

        # automatically fill in net information
        if net == "mainnet":
            if gh == "":
                gh = 'wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8='
            if gen == "":
                gen = 'mainnet-v1.0'
        elif net == "testnet":
            if gh == "":    
                gh = 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI='
            if gen == "":
                gen = 'testnet-v1.0'
        elif net == "betanet:":
            if gh == "":
                gh = 'mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0='
            if gen == "":
                gen = 'betanet-v1.0'

        raw_data = {
            "amt": int(amount),         # unit is microAlgos
            "fee": int(fee),                 # data["fee"] ~ 0.001 Algos
            "first": int(first),        # first valid block
            "last": int(last),  # last valid block
            "gen": gen,          # network
            "receiver": rcv_address,            # reciever address
            "sender": self.getPublic(name),     # sender address
            "gh": gh          # genisis hash
        }

        return self.signTransaction(raw_data,self.getPrivate(name)) 

    # signs and converts a valid transaction dictionary to a binary variable.
    def signTransaction(self,data_in,private_in):
        return self.signData(data_in,private_in,"tx")

    # sign key registration transaction
    def signKeyreg(self,data_in,private_in):
        return self.signData(data_in,private_in,"reg")

    # sign any kind of data dictionary by defining a type
    def signData(self,data_in,private_in,type = "transaction"):
        
        # Format raw data as a payment transaction
        if type.lower() == "transaction" or "transact" or "txn" or "tx" or "send" or "snd" or "pay" or "payment":
            try:
                unsigned_data = algosdk.encoding.transaction.PaymentTxn(**data_in,)
            except TypeError as e:
                print("Invalid data : " + str(e))
                return
        
        # format raw data as a key registration to go online/offline for governance
        elif type.lower() == "keyreg" or "register" or "reg" or "participate" or "consensus" or "gov" or "governance":
            try:
                unsigned_data = algosdk.encoding.transaction.KeyregTxn(**data_in,)
            except TypeError as e:
                print("Invalid data : " + str(e))
                return
        
        # format raw data as a asset transfer transaction
        elif type.lower() == "assettransfer" or "transferasset":
            try:
                unsigned_data = algosdk.encoding.transaction.AssetTransferTxn(**data_in,)
            except TypeError as e:
                print("Invalid data : " + str(e))
                return

        # format raw data as a asset config transaction
        elif type.lower() == "assetconfig" or "configasset":
            try:
                unsigned_data = algosdk.encoding.transaction.AssetConfigTxn(**data_in,)
            except TypeError as e:
                print("Invalid data : " + str(e))
                return

        # format raw data as a asset freeze transaction
        elif type.lower() == "assetfreeze" or "freezeasset":
            try:
                unsigned_data = algosdk.encoding.transaction.AssetFreezeTxn(**data_in,)
            except TypeError as e:
                print("Invalid data : " + str(e))
                return


        # accept either mnemonic or private key as input
        private = ""
        try:
            algosdk.account.address_from_private_key(private_in)
            private = private_in
        except:
            pass
            try:
                private = algosdk.mnemonic.to_private_key(private_in)
            except ValueError:
                raise ValueError("***Invalid private key/phrase. Please double check that it is correct.***")

        # Sign transaction using private key
        signed_data = unsigned_data.sign(private)

        # turn that shit into a pile of binary garbage
        signed_data = base64.b64decode(algosdk.encoding.msgpack_encode(signed_data))

        return signed_data

    ## ================ ##
    ## USER LAYER STUFF ##
    ## ================ ##

    # quick function for sending algos using node object
    def sendAlgo(self,name,reciever,amount,algoNodeObj,password = False):
        try:
            signed_txn = self.makeAlgoTxOnline(name,reciever,amount,algoNodeObj,password)
            return algoNodeObj.makeTransaction(signed_txn)
        except UserWarning as e:
            print("This wallet is encrypted, please provide a password")
            return False
        except SyntaxWarning as e:
            print("Invalid password provided, transaction canceled.")
            return False
        
        #except:
        #    print("Unknown error during transaction")
        #    return False  

# Request password from user
def password(name = None):
    if name != None:
        print("Please provide the password for decrypting '{}'.".format(name))
    else:
        print("Please provide the password for decrypting the account.")
    return input()

# Prints transaction response
def txnMessage(response,node):
    if response:
        if response.status_code == 200:
            import ast
            print("Transaction successful, transaction overview URL can be found below:")
            print(node.explorer()+ "tx/" + ast.literal_eval(bytes.decode(response.content))["txId"])
        else:
            print("Got status code : {}".format(str(response.status_code)))
            print(bytes.decode(response.content))

## ==================================== ##
## PUT CODE TO RUN AT SCRIPT START HERE ##
## ==================================== ##

print("Welcome to the Algorand Wallet written in Python.")
print("A help() function has not yet been implemented.")
print("Please see the example code in the algorandWallet.py file.")

## ========= ##
## DEMO CODE ##
## ========= ##

## Creates wallet object
#wallet = algoWallet("algorandWallet",True)
#
## Creates a connection to the AlgoExplorer API on testnet
#node = algoNode("testnet")
#
## Generates an account and encrypts it using a password
#wallet.genAccount("primary_account","myPassword1234!")
#
## Adds a contact and gives it easy to type name
#wallet.addContact("Algorand8","APDO5T76FB57LNURPHTLAGLQOHUQZXYHH2ZKR4DPQRKK76FB4IAOBVBXHQ")
#
## Exports wallet to a file
#wallet.exportWallet()
#
## Sends 0.1337 Algos to Algorand6 on testnet, and decrypts the wallet for signing
#wallet.sendAlgo("primary_account","Algorand8",0.1337,node,"myPassword1234!")