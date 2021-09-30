import algosdk
from algosdk.v2client.algod import AlgodClient

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    def importAccount(self,name,private, password = False):

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
    def makeAccount(self,name,private,password = False):
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
        print("Functionality not yet implemented")
    
    # TODO (func) delete an existing account.
    def removeAccount(self,name):
        print("Functionality not yet implemented")

    ## ================ ##
    ## GET ACCOUNT INFO ##
    ## ================ ##

    # gets the public address for an account in wallet
    def getPublic(self,account):
        try:
            if self.getSalt(account) != "":
                return self.internalWallet[account]["account"]["public"]
            else:
                return self.decryptPublic(account,password(account))
        except KeyError:

            # also try contact
            try:
                return self.internalWallet[account]["contact"]["public"]
            except KeyError:
                print("No account or contact named '" + account + "' exists.")

    # gets the private key for an account in wallet
    def getPrivate(self,account):
        try:
            if self.getSalt(account) != "":
                return self.internalWallet[account]["account"]["private"]
            else:
                return self.decryptPrivate(account,password(account))
        except KeyError:
            print("No account named '" + account + "' exists.")

    # gets the private mnemonic for an account in wallet
    def getMnemonic(self,account):
        try:
            if self.getSalt(account) != "":
                return self.internalWallet[account]["account"]["mnemonic"]
            else:
                return self.decryptMnemonic(account,password(account))
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
    def removeContact(self,contact):
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
            raise KeyError
   
    # generate fernet key with given salt and password
    def fernetGenerator(self,salt,password):
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
    def encryptContents(self,contents,password):
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
    def encryptAccount(self,name,password):

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
    def decryptAccount(self,name,password):

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
    
    ## ============================= ##
    ## TRANSACTION / SIGNATURE STUFF ##
    ## ============================= ##

    # TODO algosdk.encoding.transaction.xxxxxx is outdated and it should be using algosdk.future.transaction.xxxxxx instead

    # transact algos offline (you must supply all parameters manually)
    def makeSendAlgoTx(self,name,reciever,amount, params, password = None, microAlgos = False):
        
        # try to convert to dictionary
        try:
            params = vars(params)
        except:
            pass

        rcv_address = reciever
        public = self.getPrivate(name)
        private = self.getPrivate(name)

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
            "first": int(params["first"]),        # first valid block
            "last": int(params["last"]),  # last valid block
            "gen": params["gen"],          # network
            "receiver": rcv_address,            # reciever address
            "sender": public,     # sender address
            "gh": params["gh"]          # genisis hash
        }

        return self.signData(raw_data,private,"tx")

    # sign any kind of data dictionary by defining a type
    def signData(self,data_in,private_in,type = "transaction"):

        # Format raw data as a payment transaction
        if any(x in type.lower() for x in ['transaction','transact','txn','tx','send',"snd","pay","payment"]):
            try:
                unsigned_data = algosdk.encoding.transaction.PaymentTxn(**data_in,)
            except TypeError as e:
                print("Invalid PaymentTxn data : " + str(e))
                return
        
        # format raw data as a key registration to go online/offline for governance
        elif any(x in type.lower() for x in ['keyreg','register','reg','participate','consensus',"gov","governance"]):
            try:
                unsigned_data = algosdk.encoding.transaction.KeyregTxn(**data_in,)
            except TypeError as e:
                print("Invalid KeyregTxn data : " + str(e))
                return
        
        # format raw data as a asset transfer transaction
        elif any(x in type.lower() for x in ['assettransfer','transferasset']):
            try:
                unsigned_data = algosdk.encoding.transaction.AssetTransferTxn(**data_in,)
            except TypeError as e:
                print("Invalid AssetTransferTxn data : " + str(e))
                return

        # format raw data as a asset config transaction
        elif any(x in type.lower() for x in ['assetconfig','configasset']):
            try:
                unsigned_data = algosdk.encoding.transaction.AssetConfigTxn(**data_in,)
            except TypeError as e:
                print("Invalid AssetConfigTxn data : " + str(e))
                return

        # format raw data as a asset freeze transaction
        elif any(x in type.lower() for x in ['assetfreeze','freezeasset']):
            try:
                unsigned_data = algosdk.encoding.transaction.AssetFreezeTxn(**data_in,)
            except TypeError as e:
                print("Invalid AssetFreezeTxn data : " + str(e))
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

        return signed_data

    # generate the string needed to generate participation keys
    def addPartKey(self,name,params,rounds,password = None):

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
            print("goal account addpartkey -a {a} --roundFirstValid={f} --roundLastValid={l} -d /var/lib/algorand".format(a=self.decryptPublic(name,password),f=params["first"],l=params["first"]+rounds))
            print("===========")
        else:
            print("===========")
            print("goal account addpartkey -a {a} --roundFirstValid={f} --roundLastValid={l} -d /var/lib/algorand".format(a=self.getPublic(name),f=params["first"],l=params["first"]+rounds))
            print("===========")

    # generate transaction data that commits an account to be online or offline for consensus
    def participateConsensus(self,name,params,partkeyinfo,password = None,status = "Online"):
        import base64

         # try to convert to dictionary
        try:
            params = vars(params)
        except:
            pass

        status = status.lower()

        # Data for going offline
        data = {
            "sender": partkeyinfo["acct"],
            "votekey": algosdk.encoding.encode_address(base64.b64decode(partkeyinfo["vote"])) if status == "online" else None,
            "selkey": algosdk.encoding.encode_address(base64.b64decode(partkeyinfo["sel"])) if status == "online" else None,
            "votefst": partkeyinfo["first"] if status == "online" else None
            "votelst": partkeyinfo["last"] if status == "online" else None,
            "votekd": partkeyinfo["voteKD"] if status == "online" else None,
            "fee": 1500,
            "flat_fee": True,
            "first": params["first"],
            "last": params["last"],
            "gen": params["gen"],
            "gh": params["gh"]
        }

        return self.signData(data,self.decryptPrivate(name,password),type = "reg")


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
#node = ae.algoNode("mainnet")
#
## OR!
#
## Transact using a personal node
#address = "http://192.168.1.10:8080"
#token = "b742378b134679a314879c5674d67930125678b146570e189670cbe"
#node = AlgodClient(token,address) 
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