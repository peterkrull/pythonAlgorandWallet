import base64
from typing import Type
import algosdk

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
            raise Exception("Can't connect to API. URL might be incorrect.")
    
    # make send transaction to the blockchain using API
    def makeTransaction(self,signed_txn):
        return self.req.post(self.base_url + "v2/transactions",signed_txn)

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
    def genWallet(self,name,password = False): 

        private, public = algosdk.account.generate_account()

        encrypted = False
        if password:
            encrypted = True
            # TODO encrypt
            private = self.encryptPrivates(private,password)

        newWallet = {
            str(name) : {
                "public" : public,
                "private" : private,
                "mnemonic" : algosdk.mnemonic.from_private_key(private),
                "encrypted" : encrypted
            }
        }
        self.internalWallet.update(newWallet)

    # accept either mnemonic or private key as input to recover account
    def importAccountFromPrivate(self,name,private_key, password = False):

        private = ""
        try:
            algosdk.account.address_from_private_key(private_key)
            private = private_key
        except:
            pass
            try:
                private = algosdk.mnemonic.to_private_key(private_key)
            except ValueError:
                raise ValueError("***Invalid private key/phrase. Please double check that it is correct.***")

        encrypted = False
        if password:
            encrypted = True
            # TODO encrypt
            private = self.encryptPrivates(private,password)


        newWallet = {
            str(name) : {
                "public" : algosdk.account.address_from_private_key(private),
                "private" : private,
                "mnemonic" : algosdk.mnemonic.from_private_key(private),
                "encrypted" : encrypted
            }
        }
        self.internalWallet.update(newWallet)

    ## ================ ##
    ## GET ACCOUNT INFO ##
    ## ================ ##

    # gets the public address for an account in wallet
    def getPublic(self,account):
        try:
            return self.internalWallet[account]["public"]
        except KeyError:
            print("No account named '" + account + "' exists.")

    # gets the private key for an account in wallet
    def getPrivate(self,account):
        try:
            return self.internalWallet[account]["private"]
        except KeyError:
            print("No account named '" + account + "' exists.")

    # gets the private mnemonic for an account in wallet
    def getMnemonic(self,account):
        try:
            return self.internalWallet[account]["mnemonic"]
        except KeyError:
            print("No account named '" + account + "' exists.")

    ## ====================== ##
    ## CONACTS / ADDRESS BOOK ##
    ## ====================== ##

    # gets the public address for a contact
    def getPublicContact(self,account,contact):
        try:
            return self.internalWallet[account]["addressbook"][contact]
        except KeyError as e:
            
            if str(e) == "'"+account+"'":
                print("No account named '" + account + "' exists.")
            elif str(e) == "'addressbook'":
                print("No addressbook available for " + account + ".")
            elif str(e) == "'"+contact+"'":
                print("No contact named '" + contact + "' exists.")
            else:
                print("Unknown error : " + str(e))
            raise KeyError("No contact named '" + contact + "' exists for '"+ account +"'.")

    # add a contact to address book for certain account
    def addContact(self,name,contact,public_addr):
        if  algosdk.encoding.is_valid_address(public_addr):
            try:
                self.internalWallet[name]["addressbook"].update({contact:public_addr})
            except KeyError:
                self.internalWallet[name].update({"addressbook" : {}})
                self.internalWallet[name]["addressbook"].update({contact:public_addr})
        else:
            raise Exception("Invalid Algorand account address.")

    # removes contact from certain accounts addressbook
    def rmContact(self,name,contact):
        try:
            del self.internalWallet[name]["addressbook"][contact]
        except KeyError:
            print("No contact named " + contact + " exists for " + name + ".")

    ## ============================== ##
    ## WALLET ENCRYPTION / DECRYPTION ##
    ## ============================== ##

    # TODO enable encryption
    # encrypts the private key using a specific password
    def encryptPrivates(self,private,password):
        pass

    ## ============================= ##
    ## TRANSACTION / SIGNATURE STUFF ##
    ## ============================= ##

    # function to support simple Algo transactions
    def makeAlgoTx(self,name,reciever,amount, algoNodeObj, offline = False, fee = "", first = "", last = "", gen = "", gh = ""):
        rcv_address = reciever

        holdings = algoNodeObj.getAccountInfo(self.getPublic(name))["amount"]
        if holdings - 500000 < amount*1000000:
            print("Insufficient balance. Has "+str(holdings/1000000)+" Algos, trying to send " + str(amount) + " Algos")
            print("You need to leave at least 0.5 Algos in your account at all times.")
        else:
            print("Sufficient balance, proceeding.")

        if not algosdk.encoding.is_valid_address(rcv_address):
            try:
                rcv_address = self.getPublicContact(name,reciever)
                print("Found " + reciever + " in addressbook.")
            except KeyError as e:
                print("No valid address or contact for : " + reciever)
                return
        
        # TODO fetch most current block from AlgoExplorer (or personal node)
        data = algoNodeObj.getTxnParams()

        raw_data = {
            "amt": int(amount*1000000),         # unit is microAlgos
            "fee": data["fee"],                 # data["fee"] ~ 0.001 Algos
            "first": data["last-round"],        # first valid block
            "last": data["last-round"] + 1000,  # last valid block
            "gen": data["genesis-id"],          # network
            "receiver": rcv_address,            # reciever address
            "sender": self.getPublic(name),     # sender address
            "gh": data["genesis-hash"]          # genisis hash
        }

        return self.signTransaction(raw_data,self.getPrivate(name))    

    # TODO make general (any) offline transaction func
    # transact algos offline
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

    # signs and converts a valid dictionary to a binary variable.
    def signTransaction(self,data_in,private_in):
        return self.signData(data_in,private_in,"tx")

    # sign key registration transaction
    def signKeyreg(self,data_in,private_in):
        return self.signData(data_in,private_in,"tx")

    # quick function for sending algos using node object
    def sendAlgo(self,name,reciever,amount,algoNodeObj):
        signed_txn = self.makeAlgoTx(name,reciever,amount,algoNodeObj)
        return algoNodeObj.makeTransaction(signed_txn)

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

## ==================================== ##
## PUT CODE TO RUN AT SCRIPT START HERE ##
## ==================================== ##



## ========= ##
## DEMO CODE ##
## ========= ##

## Creates wallet object and imports known wallet file
#wallet = algoWallet("testWallet",True)
#
## Creates a connection to the AlgoExplorer API
#testNode = algoNode("testnet")
#
## Sends 5 algos from 'pk-testnet' account to 'bobby' on testnet
#
#answer = wallet.sendAlgo("pk-testnet","bobby",5,testNode)
#
## check API response
#if answer.status_code == 200:
#    import ast
#    print("Transaction successful, transaction overview URL can be found below:")
#    print(testNode.explorer()+ "tx/" + ast.literal_eval(bytes.decode(answer.content))["txId"])