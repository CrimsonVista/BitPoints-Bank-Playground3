'''
Created on Mar 27, 2014

@author: sethjn
'''

import sys, os, getpass, shelve, time, traceback, stat
import datetime, asyncio, argparse, configparser, shutil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
# from contextlib import closing

from BankMessages import *
from Exchange import BitPoint

from BankCore import LedgerOperationSuccess, Ledger, LedgerLine # For unshelving
from AsyncIODeferred import Deferred

from BankServerProtocol import BankServerProtocol
from PrintingPress import PrintingPress, DefaultSerializer

# TODO: Change to match actual playground layout (gotta push these too)
from CipherUtil import SHA, loadCertFromFile, loadPrivateKeyFromPemFile, RSA_SIGNATURE_MAC
from ErrorHandler import ErrorHandler
from PacketHandler import SimplePacketHandler

import playground
from playground import Configure
from playground.network.common.Protocol import StackingProtocol
from playground.network.common.PlaygroundAddress import PlaygroundAddress
from playground.network.packet.PacketType import FIELD_NOT_SET
from playground.common.io.ui import CLIShell

import logging
logger = logging.getLogger(__file__)

RANDOM_u64 = lambda: int.from_bytes(os.urandom(8), "big")

PasswordBytesHash = lambda pw: SHA(pw).digest()
PasswordHash = lambda pw: PasswordBytesHash(bytes(pw, "utf-8"))

# TODO: Configurations
DEBUG = True

ADMIN_ZONE = 1

def callLater(delay, func):
    asyncio.get_event_loop().call_later(delay, func)


class SafeRotatingFileStream(object):
    def __init__(self, basename):
        self.__basename = basename

    def write(self, msg):
        filename = self.__basename + "." + datetime.date.fromtimestamp(time.time()).isoformat() + ".log"
        mode = "a"
        if not os.path.exists(filename):
            mode = "w+"
        with open(filename,mode) as file:
            file.write(msg)
        return len(msg)

    def flush(self):
        return


def enableSecurityLogging(bankpath):
    logpath = os.path.join(bankpath, "securitylog")
    loghandler = logging.StreamHandler(SafeRotatingFileStream(logpath))
    logging.getLogger('').addHandler(loghandler)
    loghandler.setLevel("CRITICAL")


def logSecure(msg):
    logging.critical(msg)

"""
Protocol
[c] -> [ob (server)] :: C sends openSession(login_name, password)
[c] <- [ob (server)] :: ob either closes connection or sends "OK"
[c] -> [ob (server)] :: C sends request
[c] <- [ob (server)] :: ob sends response + receipt
"""


class DummyFile(object):
    def close(self): pass

InvalidPwFile = DummyFile()



        
        
class BankClientProtocol(SimplePacketHandler, StackingProtocol):
    STATE_UNINIT = "Uninitialized"
    STATE_WAIT_FOR_LOGIN = "Waiting for login to server"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    def __init__(self, cert, loginName, password):
        debugPrint("client protocol init")
        SimplePacketHandler.__init__(self)
        StackingProtocol.__init__(self)
        self.__loginName = loginName
        self.__passwordHash = PasswordHash(password)
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0}
        self.__deferred = {"CONNECTION":Deferred(),
                           "TERMINATION":Deferred()}
        self.__state = self.STATE_UNINIT
        self.__account = None
        self.__verifier = RSA_SIGNATURE_MAC(cert.public_key())
        self.registerPacketHandler(SessionOpen, self.__handleSessionOpen)
        self.registerPacketHandler(BalanceResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(Receipt, self.__handleStdSessionResponse)
        self.registerPacketHandler(CurrentAccountResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(CurAccessResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(WithdrawalResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(LoginFailure, self.__handleLoginFailure)
        self.registerPacketHandler(RequestFailure, self.__handleRequestFailure)
        self.registerPacketHandler(AdminBalanceResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(RequestSucceeded, self.__handleStdSessionResponse)
        self.registerPacketHandler(PermissionDenied, self.__handleRequestFailure)
        self.registerPacketHandler(ListAccountsResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(ListUsersResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(LedgerResponse, self.__handleStdSessionResponse)
        self.registerPacketHandler(ServerError, self.__handleServerError)
        debugPrint("Client protocol built.")

    def __errorCallbackWrapper(self, e, d):
        self.__error(e)
        d.errback(e)
        
    def __error(self, errMsg):
        if self.__state != self.STATE_ERROR:
            self.__state = self.STATE_ERROR
            #self.reportError(errMsg)
            self.transport.close()
            
    def __reportExceptionAsDeferred(self, e):
        d = Deferred()
        # we need a call later so the client code has enough time to set the errback handler
        callLater(.1,lambda: self.__errorCallbackWrapper(e, d))
        return d
    
    def __nextRequestData(self):
        rId = RANDOM_u64()
        d = Deferred()
        self.__deferred[rId] = d
        return rId, d
    
    def verify(self, msg, sig):
        return self.__verifier.verify(msg, sig)
    
    def state(self): return self.__state
    
    def account(self): return self.__account
    
    def connection_made(self, transport):
        #SimplePacketHandler.connection_made(self)
        debugPrint("Client connection made with transport %s" % transport)
        StackingProtocol.connection_made(self, transport)
        self.transport = transport
        d = self.__deferred.get("CONNECTION", None)
        if d:
            del self.__deferred["CONNECTION"]
            d.callback(True)
        else:
            debugPrint("CONNECTION deferred not found")

    def sendPacket(self, packet):
        self.transport.write(packet.__serialize__())
        debugPrint("Sent", packet.DEFINITION_IDENTIFIER)

    def data_received(self, packet):
        debugPrint("client proto data_received")
        try:
            debugPrint("Received", PacketType.Deserialize(packet).DEFINITION_IDENTIFIER)
            self.handlePacket(None, packet)
        except Exception as e:
            print(traceback.format_exc())

    def connection_lost(self, reason):
        #SimplePacketHandler.connection_lost(self, reason)
        StackingProtocol.connection_lost(self, reason) # Needs to be an exception??
        d = self.__deferred.get("CONNECTION", None)
        if d:
            del self.__deferred["CONNECTION"]
            d.errback(Exception("Connection lost before connection made: " + str(reason)))
        d = self.__deferred.get("TERMINATION", None)
        if d:
            del self.__deferred["TERMINATION"]
            d.callback(True)

    def waitForTermination(self):
        d = self.__deferred["TERMINATION"]
        return d

    def waitForConnection(self):
        debugPrint("Client waitForConnection called")
        d =  self.__deferred.get("CONNECTION",None)
        if not d:
            # we've already executed. For this to run nearly immediately
            d = Deferred()
            callLater(.1, lambda: d.callback(True))
        return d

    def loginToServer(self):
        debugPrint("client proto loginToServer")
        if "CONNECTION" in self.__deferred:
            # we haven't connected yet!
            raise Exception("Can't login. Connection not yet made.")
        if self.__state != self.STATE_UNINIT:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        openMsg = OpenSession()
        self.__connData["ClientNonce"] = RANDOM_u64()
        openMsg.ClientNonce = self.__connData["ClientNonce"]
        openMsg.Login = self.__loginName
        openMsg.PasswordHash = self.__passwordHash
        self.__state = self.STATE_WAIT_FOR_LOGIN
        d = Deferred()
        self.__deferred["LOGIN"] = d
        self.sendPacket(openMsg)
        return d

    def __handleSessionOpen(self, protocol, msg):
        debugPrint("client proto __handleSessionOpen")
        if self.__state != self.STATE_WAIT_FOR_LOGIN:
            return self.__error("Unexpected Session Open Message. State is (%s)" % self.__state)
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error("Invalid internal state. No LOGIN deferred")
        del self.__deferred["LOGIN"]

        msgObj = msg
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            return d.errback(Exception("Invalid Connection Data"))
        self.__connData["ServerNonce"] = msgObj.ServerNonce
        self.__account = msgObj.Account
        self.__state = self.STATE_OPEN
        d.callback(True)

    def __handleLoginFailure(self, protocol, msg):
        debugPrint("client __handleLoginFailure in state", self.__state)
        msgObj = msg
        if self.__state != self.STATE_WAIT_FOR_LOGIN:
            return self.__error("Error logging in: %s" % msgObj.ErrorMessage)
        d = self.__deferred.get("LOGIN", None)
        if not d:
            return self.__error("Invalid internal state. No LOGIN deferred")
        del self.__deferred["LOGIN"]

        msgObj = msg
        d.errback(Exception(msgObj.ErrorMessage))

    def __createStdSessionRequest(self, requestType, noRequestId=False):

        msg = requestType()
        msg.ClientNonce = self.__connData["ClientNonce"]
        msg.ServerNonce = self.__connData["ServerNonce"]
        if not noRequestId:
            requestId, d = self.__nextRequestData()
            msg.RequestId = requestId
        else: d = None
        return msg, d

    def __validateStdSessionResponse(self, msgObj):
        debugPrint("client __validateStdSessionResponse", type(msgObj))
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            debugPrint("d is None")
            d.errback(Exception("Invalid internal state. No deferred for request %d" % msgObj.RequestId))
            return None
        if msgObj.ClientNonce != self.__connData["ClientNonce"]:
            debugPrint("Got ClientNonce:", msgObj.ClientNonce, "Expected ClientNonce:", self.__connData["ClientNonce"])
            d.errback(Exception("Invalid Connection Data (ClientNonce)"))
            return None
        if msgObj.ServerNonce != self.__connData["ServerNonce"]:
            debugPrint("Got ServerNonce:", msgObj.ServerNonce, "Expected ServerNonce:", self.__connData["ServerNonce"])
            d.errback(Exception("Invalid Connection Data (ServerNonce"))
            return None
        del self.__deferred[msgObj.RequestId]
        return d

    # list response, swith account response, balance response
    # receipt response,
    def __handleStdSessionResponse(self, protocol, msg):
        debugPrint("Current state:", self.__state, "(looking for %s)" % self.STATE_OPEN)
        if self.__state != self.STATE_OPEN:
            debugPrint("State not Open!")
            return self.__error("Unexpected Request Response")
        msgObj = msg
        d = self.__validateStdSessionResponse(msgObj)
        if d: d.callback(msgObj)

    def __handleServerError(self, protocol, msg):
        msgObj = msg
        #self.reportError("Server Error: " + msgObj.ErrorMessage + "\nWill terminate")
        callLater(1,self.transport.close)

    def listAccounts(self, userName=None):
        debugPrint("client listAccounts username:", userName)
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        listMsg, d = self.__createStdSessionRequest(ListAccounts)
        if userName:
            listMsg.User = userName
        self.sendPacket(listMsg)
        return d

    def listUsers(self, account=None):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        listMsg, d = self.__createStdSessionRequest(ListUsers)
        if account:
            listMsg.Account = account
        self.sendPacket(listMsg)
        return d

    def switchAccount(self, accountName):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        switchMsg, d = self.__createStdSessionRequest(SwitchAccount)
        switchMsg.Account = accountName
        self.sendPacket(switchMsg)
        return d

    def currentAccount(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        currentMsg, d = self.__createStdSessionRequest(CurrentAccount)
        self.sendPacket(currentMsg)
        return d

    def currentAccess(self, userName=None, accountName=None):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        curAccessMsg, d = self.__createStdSessionRequest(CurAccessRequest)
        if userName:
            curAccessMsg.UserName = userName
        if accountName:
            curAccessMsg.AccountName = accountName
        self.sendPacket(curAccessMsg)
        return d

    def getBalance(self):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        balanceMsg, d = self.__createStdSessionRequest(BalanceRequest)
        self.sendPacket(balanceMsg)
        return d

    def transfer(self, dstAccount, amount, memo):
        if self.__state != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        transferMsg, d = self.__createStdSessionRequest(TransferRequest)
        transferMsg.DstAccount = dstAccount
        transferMsg.Amount = amount
        transferMsg.Memo = memo
        self.sendPacket(transferMsg)
        return d

    def close(self):
        debugPrint("client close (current state: %s)" % self.__state)
        if self.__state != self.STATE_OPEN:
            return # silently ignore closing a non-open connection
        self.__state = self.STATE_UNINIT
        if self.transport:
            closeMsg, d = self.__createStdSessionRequest(Close, noRequestId=True)
            self.sendPacket(closeMsg)
            callLater(.1, self.transport.close)

    def __handleRequestFailure(self, protocol, msg):
        msgObj = msg
        if self.__state != self.STATE_OPEN:
            return self.__error("Unexpected Request Failure. Should be state %s but state %s. Failure Message: %s" % (self.STATE_OPEN, self.__state, msgObj.ErrorMessage))
        d = self.__deferred.get(msgObj.RequestId, None)
        if not d:
            return self.__error("Invalid internal state. No deferred for request %d. Error msg: %s" % (msgObj.RequestId, msgObj.ErrorMessage))
        del self.__deferred[msgObj.RequestId]

        d.errback(Exception(msgObj.ErrorMessage))

    def adminGetBalances(self):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        balanceMsg, d = self.__createStdSessionRequest(AdminBalanceRequest)
        self.sendPacket(balanceMsg)
        return d

    def deposit(self, serializedBp):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        depositMsg, d = self.__createStdSessionRequest(DepositRequest)
        depositMsg.bpData = serializedBp
        # debugPrint(depositMsg.bpData[:15], "...", depositMsg.bpData[-15:], len(depositMsg.bpData), type(depositMsg.bpData))
        self.sendPacket(depositMsg)
        return d

    def withdraw(self, amount):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        withdrawalMsg, d = self.__createStdSessionRequest(WithdrawalRequest)
        withdrawalMsg.Amount = amount
        self.sendPacket(withdrawalMsg)
        return d

    def adminCreateUser(self, loginName, password):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        createMsg, d = self.__createStdSessionRequest(SetUserPasswordRequest)
        createMsg.loginName = loginName
        createMsg.oldPwHash = ''
        createMsg.newPwHash = PasswordHash(password)
        createMsg.NewUser = True
        self.sendPacket(createMsg)
        return d

    def adminCreateAccount(self, accountName):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        createMsg, d = self.__createStdSessionRequest(CreateAccountRequest)
        createMsg.AccountName = accountName
        self.sendPacket(createMsg)
        return d

    def changePassword(self, newPassword, oldPassword=None, loginName=None):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        changeMsg, d = self.__createStdSessionRequest(SetUserPasswordRequest)
        if loginName:
            changeMsg.loginName = loginName
        else: changeMsg.loginName = ""
        if oldPassword:
            changeMsg.oldPwHash = PasswordHash(oldPassword)
        else: changeMsg.oldPwHash = ""
        changeMsg.newPwHash = PasswordHash(newPassword)
        changeMsg.NewUser = False
        self.sendPacket(changeMsg)
        return d

    def changeAccess(self, username, access, account=None):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        changeMsg, d = self.__createStdSessionRequest(ChangeAccessRequest)
        changeMsg.UserName = username
        changeMsg.AccessString = access
        if account:
            changeMsg.Account = account
        self.sendPacket(changeMsg)
        return d

    def exportLedger(self, account):
        if self.state() != self.STATE_OPEN:
            return self.__reportExceptionAsDeferred(Exception("Cannot login. State: %s" % self.__state))
        ledgerMsg, d = self.__createStdSessionRequest(LedgerRequest)
        if account:
            ledgerMsg.Account = account
        self.sendPacket(ledgerMsg)
        return d


class PlaygroundOnlineBank:

    def __init__(self, passwordFile, bank):
        #super(PlaygroundOnlineBank, self).__init__(self)
        self.__bank = bank
        self.__passwordData = PasswordData(passwordFile)

    def buildProtocol(self):
        p = BankServerProtocol(self.__passwordData, self.__bank)
        return p


class PlaygroundOnlineBankClient:
    def __init__(self, cert, loginName, pw):
        #super(PlaygroundOnlineBankClientTest, self).__init__(self)
        self._cert = cert
        self._loginName = loginName
        self._pw = pw

    def buildProtocol(self):
        debugPrint("Building client protocol...")
        return BankClientProtocol(self._cert, self._loginName, self._pw)


class AdminBankCLIClient(CLIShell.CLIShell, ErrorHandler):
    NON_ADMIN_PROMPT = "Bank Client> "
    ADMIN_PROMPT = "Bank Client [Admin]> "

    def __init__(self, clientBase, bankClientFactory, bankAddr, bankPort):
        CLIShell.CLIShell.__init__(self, prompt=self.NON_ADMIN_PROMPT)
        self.__d = None
        self.__backlog = []
        self.__bankClient = None
        self.__bankAddr = bankAddr
        self.__bankPort = bankPort
        self.__bankClientFactory = bankClientFactory
        # self.__clientBase = clientBase
        self.__connected = False
        self.__admin = False
        self.__quitCalled = False
        self.__asyncLoop = asyncio.get_event_loop()

    def __loginToServer(self, success):
        if not success:
            return self.__noLogin(Exception("Failed to login"))
        self.__d = self.__bankClient.loginToServer()
        self.__d.addCallback(self.__login)
        self.__d.addErrback(self.__noLogin)
        return self.__d

    def __login(self, success):
        self.__connected = True
        self.reset()
        self.__loadCommands()
        self.transport.write("Logged in to bank\n")

    def __noLogin(self, e):
        self.transport.write("Failed to login to bank: %s\n" % str(e))
        self.transport.write("Quiting")
        callLater(.1, self.quit)

    def __listAccountsResponse(self, msgObj):
        responseTxt = "  CurrentAccounts\n"
        for account in msgObj.Accounts:
            responseTxt += "    "+account+"\n"
        self.transport.write(responseTxt+"\n")
        self.reset()

    def __listUsersResponse(self, msgObj):
        responseTxt = "  CurrentUsers\n"
        for user in msgObj.Users:
            responseTxt += "    "+user+"\n"
        self.transport.write(responseTxt+"\n")
        self.reset()

    def __currentAccount(self, msgObj):
        if msgObj.Account:
            self.transport.write("  You are currently logged into account " + msgObj.Account)
        else:
            self.transport.write("  You are not logged into an account. Use 'account switch [accountName]'")
        self.transport.write("\n")
        self.reset()

    def __switchAccount(self, msgObj):
        self.transport.write("  Successfully logged into account.")
        self.transport.write("\n")
        self.reset()

    def __balances(self, msgObj):
        accounts, balances = msgObj.Accounts, msgObj.Balances
        if len(accounts) != len(balances):
            self.transport.write("Inernal Error. Got %d accounts but %d balances\n" % (len(accounts), len(balances)))
            return
        responseTxt = ""
        responseTxt += "  Current Balances:\n"
        for i in range(len(accounts)):
            responseTxt += "    %s: %d\n" % (accounts[i],balances[i])
        self.transport.write(responseTxt + "\n")
        self.reset()

    def __curAccess(self, msgObj):
        accounts, access = msgObj.Accounts, msgObj.Access
        if len(accounts) != len(access):
            self.transport.write("  Inernal Error. Got %d accounts but %d access\n" % (len(accounts), len(access)))
            return
        responseTxt = "  Current Access:\n"
        for i in range(len(accounts)):
            responseTxt += "    %s: %s\n" % (accounts[i], access[i])
        self.transport.write(responseTxt + "\n")
        self.reset()

    def __accountBalanceResponse(self, msgObj):
        result = msgObj.Balance
        self.transport.write("Current account balance: %d\n" % result)
        self.reset()

    def __withdrawl(self, msgObj):
        debugPrint("client __withdrawl")
        result = eval(msgObj.bpData)
        filename = "bp"+str(time.time())
        open(filename,"wb").write(result)
        self.transport.write("  Withdrew bitpoints into file %s" % filename)
        self.transport.write("\n")
        self.reset()

    def __receipt(self, msgObj):
        try:
            receiptFile = "bank_receipt."+str(time.time())
            sigFile = receiptFile + ".signature"
            self.transport.write("Receipt and signature received. Saving as %s and %s\n" % (receiptFile, sigFile))
            receiptBytes = eval(msgObj.Receipt)
            sigBytes = eval(msgObj.ReceiptSignature)
            with open(receiptFile, "wb") as f:
                f.write(receiptBytes)
            with open(sigFile, "wb") as f:
                f.write(sigBytes)
            if not self.__bankClient.verify(receiptBytes, sigBytes):
                responseTxt = "Received a receipt with mismatching signature\n"
                responseTxt += "Please report this to the bank administrator\n"
                responseTxt += "Quitting\n"
                self.transport.write(responseTxt)
                self.quit()
            else:
                self.transport.write("Valid receipt received. Transaction complete.")
                self.transport.write("\n")
                self.reset()
        except Exception as e:
            print(traceback.format_exc())

    def __createAccount(self, result):
        self.transport.write("  Account created.")
        self.transport.write("\n")
        self.reset()

    def __createUser(self, result):
        self.transport.write("  User created.")
        self.transport.write("\n")
        self.reset()

    def __changePassword(self, result):
        self.transport.write("  Password changed successfully.")
        self.transport.write("\n")
        self.reset()

    def __changeAccess(self, result):
        self.transport.write("  Access changed successfully.")
        self.transport.write("\n")
        self.reset()

    def __exportLedgerResponse(self, msgObj):
        filename = "ledger_%f" % time.time()
        self.transport.write("  Exported ledger downloaded.\n")
        self.transport.write("  Saving to file %s\n" % filename)
        with open(filename,"w+") as file:
            for line in msgObj.Lines:
                file.write(line+"\n")
        self.transport.write("  Done.\n")
        self.reset()

    def __failed(self, e):
        self.transport.write("\033[91m  Operation failed. Reason: %s\033[0m\n" % str(e))
        self.reset()
        return Exception(e)

    def handleError(self, message, reporter=None, stackHack=0):
        self.transport.write("\033[91mClient Error: %s\033[0m\n" % message)

    def quit(self, writer=None, *args):
        self.__bankClient.close()
        if self.__quitCalled: return
        self.__quitCalled = True
        self.transport.write("Exiting bank client.\n")
        callLater(0, self.transport.close)
        #callLater(.1, self.__clientBase.disconnectFromPlaygroundServer)
        callLater(.1, lambda: self.higherProtocol() and self.higherProtocol().close)
        return Deferred()

    def handleException(self, e, reporter=None, stackHack=0, fatal=False):
        debugPrint("CLI handleException")
        errMsg = traceback.format_exc()
        self.handleError(errMsg)
        if fatal:
            self.quit()

    def reset(self):
        self.__d = None

    def connection_made(self, transport):
        print("connection_made")
        try:
            CLIShell.CLIShell.connection_made(self, transport)

            loop = self.__asyncLoop
            debugPrint("CLI Making a client connection...")
            coro = playground.getConnector(self.__bankClientFactory.stack).create_playground_connection(self.__bankClientFactory.buildProtocol, self.__bankAddr, self.__bankPort)
            debugPrint("CLI Running client protocol coroutine...")
            fut = asyncio.run_coroutine_threadsafe(coro, self.__asyncLoop)
            fut.add_done_callback(self.__handleClientConnection)
            debugPrint("CLI connection_made done")
        except Exception as e:
            print(traceback.format_exc())
            self.transport.close()

    def __handleClientConnection(self, fut):
        debugPrint("CLI __handleClientConnection")
        debugPrint("Future result:", fut.exception())
        transport, protocol = fut.result()
        debugPrint("Bank connected. Running startup routines with protocol %s" % protocol)
        self.__bankConnected(protocol)
        print("Admin CLI client Connected. Starting UI t:{}. p:{}".format(transport, protocol))

    def __bankConnected(self, result):
        try:
            self.__bankClient = result
            # self.__bankClient.setLocalErrorHandler(self)
            self.__d = self.__bankClient.waitForConnection() # self.__bankClient.loginToServer()
            self.__bankClient.waitForTermination().addCallback(lambda *args: self.quit())
            self.__d.addCallback(self.__loginToServer)
            self.__d.addErrback(self.__noLogin)
            self.transport.write("Logging in to bank. Waiting for server\n")
            return self.__d
        except:
            print(traceback.format_exc())
            self.transport.close()

    def line_received(self, line):
        if self.__d:
            if line.strip().lower() == "__break__":
                self.__d = None
                self.transport.write("Operation cancelled on client. Unknown server state.\n")
            elif not self.__connected:
                self.transport.write("Still waiting for bank to login. Retry command later.\n")
            else:
                self.transport.write("Cannot execute [%s]. Waiting for previous command to complete\n"%line)
                self.transport.write("Type: __break__ to return to shell (undefined behavior).\n")
            return (False, None)
        try:
            return self.lineReceivedImpl(line)
            # return (True, self.__d)
        except Exception as e:
            self.handleException(e)
            return (False, None)
            
    def __toggleAdmin(self, writer):
        self.__admin = not self.__admin
        if self.__admin:
            self.prompt = self.ADMIN_PROMPT
        else: self.prompt = self.NON_ADMIN_PROMPT
        
    def __accessCurrent(self, writer, arg1=None, arg2=None):
        user = None
        account = None
        if arg1 and not arg2:
            if self.__admin:
                # in admin mode, one arg is the user (get all account access)
                user = arg1
                account = None
            elif not self.__admin:
                # in non-admin, one arg is the account (get my access in account)
                user = None
                account = arg1
        else:
            user = arg1
            account = arg2

        self.__d = self.__bankClient.currentAccess(user, account)
        self.__d.addCallback(self.__curAccess)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accessSet(self, writer, user, access, account=None):
        if access == "*":
            access = PasswordData.ACCOUNT_PRIVILEGES
        if access == "__none__":
            access = ''
        self.__d = self.__bankClient.changeAccess(user, access, account)
        self.__d.addCallback(self.__changeAccess)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __listAccounts(self, writer, user=None):
        if user and not self.__admin:
            writer("Not in admin mode\n")
            return
        self.__d = self.__bankClient.listAccounts(user)
        self.__d.addCallback(self.__listAccountsResponse)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __listUsers(self, writer, account=None):
        self.__d = self.__bankClient.listUsers(account)
        self.__d.addCallback(self.__listUsersResponse)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accountCurrent(self, writer):
        self.__d = self.__bankClient.currentAccount()
        self.__d.addCallback(self.__currentAccount)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accountSwitch(self, writer, switchToAccount):
        if switchToAccount == "__none__":
            switchToAccount = ''
        self.__d = self.__bankClient.switchAccount(switchToAccount)
        self.__d.addCallback(self.__switchAccount)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accountBalance(self, writer, all=False):
        if not all:
            self.__d = self.__bankClient.getBalance()
            self.__d.addCallback(self.__accountBalanceResponse)
            self.__d.addErrback(self.__failed)
        else:
            if not self.__admin:
                writer("Not in admin mode\n")
                return
            self.__d = self.__bankClient.adminGetBalances()
            self.__d.addCallback(self.__balances)
            self.__d.addErrback(self.__failed)
        return self.__d
            
    def __accountDeposit(self, writer, bpFile):
        if not os.path.exists(bpFile):
            writer("NO such file\n")
            return
        with open(bpFile,"rb") as f:
            bpData = f.read()
            self.__d = self.__bankClient.deposit(bpData)
            self.__d.addCallback(self.__receipt)
            self.__d.addErrback(self.__failed)
        return self.__d
            
    def __accountWithdrawArgsHandler(self, writer, amountStr):
        try:
            amount = int(amountStr)
        except:
            writer("Not a valid amount %s\n" % amountStr)
            return None
        if amount < 1:
            writer("Amount cannot be less than 1\n")
            return None
        return (amount,)
            
    def __accountWithdraw(self, writer, amount):
        self.__d = self.__bankClient.withdraw(amount)
        self.__d.addCallback(self.__withdrawl)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accountTransferArgsHandler(self, writer, dst, amountStr, memo):
        try:
            amount = int(amountStr)
        except:
            writer("Invalid amount %s" % amountStr)
            return None
        if amount < 1:
            writer("Amount cannot be less than 1\n")
            return None
        return (dst, amount, memo)
        
    def __accountTransfer(self, writer, dstAcct, amount, memo):
        self.__d = self.__bankClient.transfer(dstAcct, amount, memo)
        self.__d.addCallback(self.__receipt)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __accountCreate(self, writer, accountName):
        if not self.__admin:
            writer("Not in admin mode\n")
            return
        self.__d = self.__bankClient.adminCreateAccount(accountName)
        self.__d.addCallback(self.__createAccount)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __userCreate(self, writer, userName):
        if not self.__admin:
            writer("Not in admin mode\n")
            return
        password = getpass.getpass("Enter account password for [%s]: " % userName)
        password2 = getpass.getpass("Re-enter account password for [%s]: " % userName)
        if password != password2:
            self.transport.write("Mismatching passwords\n")
            return
        self.__d = self.__bankClient.adminCreateUser(userName, password)
        self.__d.addCallback(self.__createAccount)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __userPasswd(self, writer, userName=None):
        if not userName:
            oldPassword = getpass.getpass("Enter current account password: ")
        else:
            if not self.__admin:
                writer("Not in admin mode\n")
                return 
            writer("Login name specified as [%s]. This requires Admin access\n"%userName)
            oldPassword = None
        password2 = getpass.getpass("Enter new account password: ")
        password3 = getpass.getpass("Re-enter new account password: ")
        if password2 != password3:
            writer("Mismatching passwords\n")
            return
        self.__d = self.__bankClient.changePassword(password2, loginName=userName, oldPassword=oldPassword)
        self.__d.addCallback(self.__changePassword)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __exportLedger(self, writer, account=None):
        if not account and not self.__admin:
            writer("Not in admin mode.\n")
            return
        self.__d = self.__bankClient.exportLedger(account)
        self.__d.addCallback(self.__exportLedgerResponse)
        self.__d.addErrback(self.__failed)
        return self.__d
        
    def __loadCommands(self):
        cscc = CLIShell.CLICommand

        # Admin
        adminCommandHandler = cscc("admin",
                                   "Toggle admin mode",
                                   self.__toggleAdmin)

        # Access
        accessCommandHandler = cscc("access",
                                    "Configure access right",
                                    mode=cscc.SUBCMD_MODE)

        # Access - Current
        accessCurrentHandler = cscc("current",
                                    "Get the current access for a user/account",
                                    mode=cscc.STANDARD_MODE,
                                    defaultCb=self.__accessCurrent)
        accessCurrentHandler.configure(1,
                                       self.__accessCurrent,
                                       usage="[user/account]",
                                       helpTxt="Get the access of the user or account depending on admin mode.")
        accessCurrentHandler.configure(2,
                                       self.__accessCurrent,
                                       usage="[user] [account]",
                                       helpTxt="Get the access of the user/account pair")
        accessCommandHandler.configureSubcommand(accessCurrentHandler)

        # Access - Set
        accessSetHandler = cscc("set",
                                helpTxt="Set access for a user",
                                mode=cscc.STANDARD_MODE)
        accessSetHandler.configure(2,
                                   self.__accessSet,
                                   usage="[username] [access]",
                                   helpTxt="Set the access for username on current account")
        accessSetHandler.configure(3,
                                   self.__accessSet,
                                   usage="[username] [access] [account]",
                                   helpTxt="Set the access for username on account")
        accessCommandHandler.configureSubcommand(accessSetHandler)

        # Account
        accountHandler = cscc("account",
                              helpTxt="Commands related to an account",
                              mode=cscc.SUBCMD_MODE)

        # Account - List
        accountListHandler = cscc("list",
                                  helpTxt="List accounts for current user",
                                  defaultCb=self.__listAccounts,
                                  mode=cscc.STANDARD_MODE)
        accountListHandler.configure(1,
                                     self.__listAccounts,
                                     helpTxt="Admin: List accounts for a specific user",
                                     usage="[user]")
        accountHandler.configureSubcommand(accountListHandler)

        # Account - Current
        accountCurrentHandler = cscc("current",
                                     helpTxt="Get the current account name",
                                     defaultCb=self.__accountCurrent)
        accountHandler.configureSubcommand(accountCurrentHandler)

        # Account - Switch
        accountSwitchHandler = cscc("switch",
                                    helpTxt="Switch the current account",
                                    mode=cscc.STANDARD_MODE)
        accountSwitchHandler.configure(1,
                                       self.__accountSwitch,
                                       "Switch to [account name]",
                                       usage="[account name]")
        accountHandler.configureSubcommand(accountSwitchHandler)

        # Account - Balance
        accountBalanceHandler = cscc("balance",
                                     helpTxt="Get the current account balance",
                                     defaultCb=self.__accountBalance,
                                     mode=cscc.SUBCMD_MODE)
        accountBalanceAllHandler = cscc("all",
                                        helpTxt="Admin: Get ALL balances",
                                        defaultCb=lambda writer: self.__accountBalance(writer, True),
                                        mode=cscc.STANDARD_MODE)
        accountBalanceHandler.configureSubcommand(accountBalanceAllHandler)
        accountHandler.configureSubcommand(accountBalanceHandler)

        # Account - Deposit
        accountDepositHandler = cscc("deposit",
                                     helpTxt="Deposit bitpoints",
                                     mode=cscc.STANDARD_MODE)
        accountDepositHandler.configure(1,
                                        self.__accountDeposit,
                                        "Deposit a file of bitpoints",
                                        usage="[bp file]")
        accountHandler.configureSubcommand(accountDepositHandler)

        # Account - Withdraw
        accountWithdrawHandler = cscc("withdraw",
                                      helpTxt="Withdraw bitpoints",
                                      mode=cscc.STANDARD_MODE)
        accountWithdrawHandler.configure(1,
                                         self.__accountWithdraw,
                                         "Withdraw an amount of bitpoints",
                                         argHandler=self.__accountWithdrawArgsHandler,
                                         usage="[amount]")
        accountHandler.configureSubcommand(accountWithdrawHandler)

        # Account - Transfer
        accountTransferHandler = cscc("transfer",
                                      helpTxt="Transfer funds to another account",
                                      mode=CLIShell.CLICommand.STANDARD_MODE)
        accountTransferHandler.configure(3,
                                         self.__accountTransfer,
                                         "Transfer amount to dst with memo",
                                         argHandler=self.__accountTransferArgsHandler,
                                         usage="[dst] [amount] [memo]")
        accountHandler.configureSubcommand(accountTransferHandler)

        # Account - Create
        accountCreateHandler = cscc("create",
                                    helpTxt="Admin: create new account",
                                    mode=cscc.STANDARD_MODE)
        accountCreateHandler.configure(1,
                                       self.__accountCreate,
                                       "Create account named [account name]",
                                       usage="[account name]")
        accountHandler.configureSubcommand(accountCreateHandler)

        # User
        userHandler = cscc("user",
                           helpTxt="Manage user(s)",
                           mode = cscc.SUBCMD_MODE)

        # User - List
        userListHandler = cscc("list",
                               helpTxt="List all users for the current account",
                               defaultCb=self.__listUsers,
                               mode=cscc.STANDARD_MODE)
        userListHandler.configure(1,
                                  self.__listUsers,
                                  helpTxt="List the users with access to [account]",
                                  usage="[account]")
        userHandler.configureSubcommand(userListHandler)

        # User - Create
        userCreateHandler = cscc("create",
                                 helpTxt="Admin: create a new user",
                                 mode=cscc.STANDARD_MODE)
        userCreateHandler.configure(1,
                                    self.__userCreate,
                                    helpTxt="Admin: create user [username]",
                                    usage="[username]")
        userHandler.configureSubcommand(userCreateHandler)

        # User - Passwd
        userPasswdHandler = cscc("passwd",
                                 helpTxt="Set password",
                                 defaultCb=self.__userPasswd,
                                 mode=CLIShell.CLICommand.STANDARD_MODE)
        userPasswdHandler.configure(1,
                                    self.__userPasswd,
                                    helpTxt="Admin: Set the password for user",
                                    usage="[user]")
        userHandler.configureSubcommand(userPasswdHandler)

        # Export
        exportCommandHandler = cscc("export",
                                    helpTxt="[Admin] Export the entire ledger",
                                    defaultCb=self.__exportLedger,
                                    mode=cscc.STANDARD_MODE)
        exportCommandHandler.configure(1,
                                       self.__exportLedger,
                                       helpTxt="Export ledger for a specific acocunt",
                                       usage="[account]")

        # Register the main 5 commands
        self.registerCommand(adminCommandHandler)
        self.registerCommand(accessCommandHandler)
        self.registerCommand(accountHandler)
        self.registerCommand(userHandler)
        self.registerCommand(exportCommandHandler)
           
    
class PasswordData(object):
    # NOTE. Uses shelve.
    #  Originally used "sync" but wouldn't sync!
    #  So, now, I use close to force it to sync
    
    PASSWORD_TABLE = "pw"
    ACCOUNT_TABLE = "act"
    USER_ACCESS_TABLE = "acc"
    
    ACCOUNT_PRIVILEGES = "btdwa" # balance, transfer, deposit, withdraw, administer
    ADMIN_PRIVILEGES = "BSAFC" # balance (all users), switch (to admin accounts)
                                # administer, freeze, confiscate
                                
    ADMIN_ACCOUNT = "__admin__"
    
    def __init__(self, filename):
        self.__filename = filename
        if not os.path.exists(self.__filename):
            #print("File %s not found. Creating a new DB..." % self.__filename)
            self.__createDB(self.__filename)
        else: self.__loadDB(self.__filename)
            
    def __createDB(self, filename):
        #if filename.endswith(".db"):
        #    filename = filename[:-3]
        # this open is soley to create the file
        db = shelve.open(filename)
        db.close()
        self.__tmpPwTable = {}
        self.__tmpAccountTable = {self.ADMIN_ACCOUNT:0}
        self.__tmpUserTable = {}
        for tableName in Ledger.INITIAL_ACCOUNTS:
            self.__tmpAccountTable[tableName]=0
        self.sync()
        
    def __loadDB(self, filename):
        #if filename.endswith(".db"):
        #    filename = filename[:-3]
        with shelve.open(filename) as db: # closing(...)
            # this is all currently loaded into memory. Find something better?
            self.__tmpUserTable = db[self.USER_ACCESS_TABLE]
            self.__tmpAccountTable = db[self.ACCOUNT_TABLE]
            self.__tmpPwTable = db[self.PASSWORD_TABLE]
        
    def sync(self):
        with shelve.open(self.__filename) as db: # closing(...)
            db[self.USER_ACCESS_TABLE] = self.__tmpUserTable
            db[self.ACCOUNT_TABLE] = self.__tmpAccountTable
            db[self.PASSWORD_TABLE] = self.__tmpPwTable
            db.sync()
        
    def __setUser(self, username, passwordHash):
        self.__tmpPwTable[username] = passwordHash
        
    def __delUser(self, userName):
        del self.__tmpPwTable[userName]
        if userName in self.__tmpUserTable:
            del self.__tmpUserTable[userName]
            
    def __addAccount(self, accountName):
        self.__tmpAccountTable[accountName] = 1
        
    def hasUser(self, userName):
        return userName in self.__tmpPwTable
    
    def hasAccount(self, accountName):
        return accountName in self.__tmpAccountTable
    
    def iterateAccounts(self):
        return list(self.__tmpAccountTable.keys())
    
    def iterateUsers(self, account=None):
        if not account:
            return list(self.__tmpPwTable.keys())
        else:
            return [username for username in list(self.__tmpUserTable.keys())
                    if account in self.__tmpUserTable[username]]
    
    def __getUserPw(self, userName):
        return self.__tmpPwTable[userName]
    
    def currentAccess(self, userName, accountName=None):
        debugPrint("pwD currentAccess un:", userName,"acc:", accountName)
        access = self.__tmpUserTable.get(userName, {})
        if accountName:
            return access.get(accountName, '')
        else: return access
    
    def __setUserAccess(self, userName, accountName, privilegeData):
        if userName not in self.__tmpUserTable:
            self.__tmpUserTable[userName] = {}
        self.__tmpUserTable[userName][accountName] = privilegeData
        
    def isValidAccessSpec(self, access, accountName):
        if accountName == self.ADMIN_ACCOUNT:
            allAccess = self.ADMIN_PRIVILEGES
        else:
            allAccess = self.ACCOUNT_PRIVILEGES
        for accessLetter in access:
            if accessLetter not in allAccess:
                return False
        return True
            
    def createUser(self, userName, passwordHash, modify=False):
        if self.hasUser(userName) and not modify:
            raise Exception("User  %s already exists" % userName)
        self.__setUser(userName, passwordHash)
        
    def currentUserPassword(self, userName):
        if not self.hasUser(userName):
            raise Exception("User  %s does not already exist" % userName)
        return self.__getUserPw(userName)
                
    def createAccount(self, accountName):
        if self.hasAccount(accountName):
            raise Exception("Account %s already exists" % accountName)
        self.__addAccount(accountName)
        
    def configureAccess(self, userName, accountName, access):
        if not self.hasUser(userName):
            raise Exception("No such user %s to assign to account" % userName)
        if not self.hasAccount(accountName):
            raise Exception("No such account %s for user privileges" % accountName)
        if not self.isValidAccessSpec(access, accountName):
            raise Exception("Unknown access %s" % (access, )) 
        self.__setUserAccess(userName, accountName, access)
        
    def removeUser(self, userName):
        if not self.hasUser(userName):
            raise Exception("No such user %s to remove" % userName)
        self.__delUser(userName)       


# TODO: Update the usage
USAGE = """
OnlineBank.py pw <passwordFile> user [add <username>] [del <username>] [change <username>]
OnlineBank.py pw <passwordFile> account [add <accountname]
OnlineBank.py pw <passwordFile> chmod <username> [<accountname> [<privileges>]]
\tPrivileges must be one of %s or %s
OnlineBank.py server <passwordFile> <bankpath> <cert> [<mintcertpath>]
OnlineBank.py client <bank Playground addr> <cert> <user name>
""" % (PasswordData.ACCOUNT_PRIVILEGES, PasswordData.ADMIN_PRIVILEGES)


def getPasswordHashRoutine(currentPw=None):
    newPw = None
    oldPw = None
    while currentPw != oldPw:
        oldPw = getpass.getpass("ENTER CURRENT PASSWORD:")
        oldPw = PasswordHash(oldPw)
    while newPw is None:
        newPw = getpass.getpass("Enter new password:")
        newPw2 = getpass.getpass("Re-enter new password:")
        if newPw != newPw2:
            print("Passwords did not match")
            newPw = None
    return PasswordHash(newPw)

def debugPrint(*s):
    if DEBUG: print("\033[93m[%s]" % round(time.time() % 1e4, 4), *s, "\033[0m")
    
class OnlineBankInterface:
    def __init__(self):
        self.init_argument_handling()
        playgroundPath = Configure.CurrentPath()
        self._bankconfigPath = os.path.join(playgroundPath, "bank")
        if not os.path.exists(self._bankconfigPath):
            os.mkdir(self._bankconfigPath)
        
        self._pwfile = os.path.join(self._bankconfigPath, "login_data.db")
        self._bankPath = os.path.join(self._bankconfigPath, "bankdata")
        self._certPath = os.path.join(self._bankconfigPath, "bank.cert")
        self._keyPath  = os.path.join(self._bankconfigPath, "bank.key")
        self._mintCertPath = os.path.join(self._bankconfigPath, "mint.cert")
        self._mintKeyPath = os.path.join(self._bankconfigPath, "mint.key")
        self._mintPath = os.path.join(self._bankconfigPath, "mint")
        
        self._printedBpDir = os.path.join(self._bankconfigPath, "printed_bitpoints")
        if not os.path.exists(self._printedBpDir):
            os.mkdir(self._printedBpDir)
        if not os.path.exists(self._bankPath):
            os.mkdir(self._bankPath)
            
        self._verbose = False
            
    def info(self, msg):
        self._verbose and print(msg)
        
    def generate_key_and_cert(self, common_name, key_path, cert_path):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maryland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Baltimore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EN 601.644"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=90)
        ).sign(key, hashes.SHA256(), default_backend())

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))        
        
    def initialize_bank(self, args):
        if not os.path.exists(self._bankconfigPath):
            os.mkdir(self._bankconfigPath)
        if args.initialize_cmd == "client":
            shutil.copy2(args.bank_cert, self._certPath)
        elif args.initialize_cmd == "mint":
            self.info("== Initialize Mint ==")
            passwd = getpass.getpass("Create mint password: ")
            passwd2 = getpass.getpass("Re-enter mint password: ")
            if passwd != passwd2:
                sys.exit("Passwords do not match")
                
            if args.mint_key == "generate":
                self.info("... Generating mint key and certificate.")
                common_name = args.mint_cert
                self.generate_key_and_cert(common_name, self._mintKeyPath, self._mintCertPath)
            else:
                shutil.copy2(args.mint_cert, self._mintCertPath)
                shutil.copy2(args.mint_key, self._mintKeyPath)
            os.chmod(self._mintKeyPath, stat.S_IREAD)

            cert = loadCertFromFile(self._mintCertPath)
            key = loadPrivateKeyFromPemFile(self._mintKeyPath)
            
            self.info("... Creating printing press vault.")
            PrintingPress.CreateBankVault(self._mintPath, cert, key, passwd)
            
            serializer = DefaultSerializer(self._printedBpDir)
            mint = PrintingPress(cert, passwd, self._mintPath)
            denomination_letter = args.initial_bitpoints[-1]
            if denomination_letter.isnumeric():
                denominations = int(args.initial_bitpoints)
                count = 1
            elif denomination_letter == 'k':
                denominations = 1000
                count = int(args.initial_bitpoints[:-1])
            elif denomination_letter == 'm':
                denominations = 1000000
                count = int(args.initial_bitpoints[:-1])
            else:
                raise Exception("Unknown bp identifier {}".format(denomination_letter))
            self.info("... Printing a total of {}x{} bitpoints.".format(count, denominations))
            for i in range(count):
                mint.mintBitPoints(denominations, serializer)
                self.info("\tPrinted {}x{}".format(i+1, denominations))
            self.info("== END MINT INIT ==")

        elif args.initialize_cmd == "server":
            self.info("== Initialize Bank Server ==")
            passwd = getpass.getpass("Create bank password: ")
            passwd2 = getpass.getpass("Re-enter bank password: ")
            if passwd != passwd2:
                raise Exception("Mismatching bank passwords")
                
            if args.bank_key == "generate":
                self.info("... Generating bank key and certificate.")
                common_name = args.bank_cert
                self.generate_key_and_cert(common_name, self._keyPath, self._certPath)
                
                # if we're generating a bank key and cert, also generate a mint if needed
                if not os.path.exists(self._mintKeyPath):
                    self.info("... Mint does not yet exist. Generate.")
                    args.initialize_cmd = "mint"
                    args.mint_key = "generate"
                    args.mint_cert = common_name + " mint"
                    args.initial_bitpoints = "100k"
                    self.initialize_bank(args)
            else:
                if not os.path.exists(self._mintKeyPath):
                    raise Exception("Cannot initialize a bank without a mint")
                shutil.copy2(args.bank_cert, self._certPath)
                shutil.copy2(args.bank_key, self._keyPath)
            os.chmod(self._keyPath, stat.S_IREAD)
                
            cert = loadCertFromFile(self._certPath)
            key = loadPrivateKeyFromPemFile(self._keyPath)
            
            self.info("... Create bank ledger")
            Ledger.InitializeDb(self._bankPath, cert, key, passwd)
            bank = Ledger(self._bankPath, cert, passwd)
            
            self.info("... register mint certificate.")
            result = bank.registerMintCert(self._mintCertPath)
            if not isinstance(result, LedgerOperationSuccess):
                raise Exception("Could not load certificate: {}".format(result.msg()))

            for rootdir, dirs, files in os.walk(self._printedBpDir):
                if rootdir != self._printedBpDir: continue
                for bp_file in files:
                    self.info("... Uploading bit point file {} to bank.".format(bp_file))
                    bp_file_path = os.path.join(rootdir, bp_file)
                    with open(bp_file_path, "rb") as f: 
                        bps = BitPoint.deserializeAll(f)
                        result = bank.depositCash("VAULT", bps)
                        if not isinstance(result, LedgerOperationSuccess):
                            raise Exception("Could not load bitpoints. Bank in unknown state.")
            
            self.info("... Create administrator {}.".format(args.bank_administrator))
            # create the administrator
            admin_pw = 1
            admin_pw2 = 2
            while admin_pw != admin_pw2:
                admin_pw = getpass.getpass("Create bank administrator password: ")
                admin_pw2 = getpass.getpass("Verify bank administrator password: ")
            
            pwDB = PasswordData(self._pwfile)
            pwDB.createUser(args.bank_administrator, PasswordHash(admin_pw), modify=False)
            
            # admin accounts are already created
            pwDB.configureAccess(
                args.bank_administrator, 
                PasswordData.ADMIN_ACCOUNT, 
                PasswordData.ADMIN_PRIVILEGES)
                
            pwDB.sync()
            self.info("== END INIT BANK SERVER ==")
        
    def init_argument_handling(self):

        parser = argparse.ArgumentParser()
        parser.add_argument("-v","--verbose",action="store_true",default=False)
        subparsers = parser.add_subparsers(dest='cmd')
        
        initialize_parser = subparsers.add_parser("initialize")
        
        initialize_parser_parsers = initialize_parser.add_subparsers(dest='initialize_cmd')
        init_client_parser = initialize_parser_parsers.add_parser("client")
        init_client_parser.add_argument('bank_cert')
        init_client_parser.add_argument("-v","--verbose",action="store_true",default=False)
        
        init_mint_parser = initialize_parser_parsers.add_parser('mint')
        init_mint_parser.add_argument('mint_key')
        init_mint_parser.add_argument('mint_cert')
        init_mint_parser.add_argument("initial_bitpoints")
        init_mint_parser.add_argument("-v","--verbose",action="store_true",default=False)
        
        init_server_parser = initialize_parser_parsers.add_parser('server')
        init_server_parser.add_argument("bank_key")
        init_server_parser.add_argument("bank_cert")
        init_server_parser.add_argument('bank_administrator')
        init_server_parser.add_argument("-v","--verbose",action="store_true",default=False)
        
        config_parser = subparsers.add_parser('config')
        config_parser.add_argument('setting')
        config_parser.add_argument('setting_args',nargs="*")
        
        db_parser = subparsers.add_parser('db')
        db_subparsers = db_parser.add_subparsers(dest='db_cmd')
        
        user_parser = db_subparsers.add_parser("user")
        user_subparsers = user_parser.add_subparsers(dest='user_cmd')
        
        adduser_parser = user_subparsers.add_parser("add")
        adduser_parser.add_argument('user_name')
        
        deluser_parser = user_subparsers.add_parser('del')
        deluser_parser.add_argument('user_name')
        
        pw_parser = user_subparsers.add_parser('pwd')
        pw_parser.add_argument('user_name')
        
        chmoduser_parser = user_subparsers.add_parser('chmod')
        chmoduser_parser.add_argument('user_name')
        chmoduser_parser.add_argument('account_name',nargs="?")
        chmoduser_parser.add_argument('privileges',nargs="?")
        
        account_parser = db_subparsers.add_parser('account')
        account_parser.add_argument('account_cmd',choices=['add','del'])
        account_parser.add_argument('account_name')
        
        verify_parser = subparsers.add_parser('verify')
        verify_parser.add_argument('receipt_file')
        verify_parser.add_argument('receipt_sig_file')
        
        server_parser = subparsers.add_parser('server')
        client_parser = subparsers.add_parser('client')
        client_parser.add_argument('--override', '-x', action='append', nargs=2)
        
        self._parser = parser
        
    def handle_db_cmd(self, args):
        pwDB = PasswordData(self._pwfile)
        
        if args.db_cmd == "user":
            userName = args.user_name
            
            if args.user_cmd == "add":
                if pwDB.hasUser(userName):
                    sys.exit("User %s already exists" % userName)
                newPw = getPasswordHashRoutine()
                pwDB.createUser(userName, newPw, modify=False)
                
            elif args.user_cmd == "del":
                if not pwDB.hasUser(userName):
                    sys.exit("No such user login name: " + userName)
                pwDB.removeUser(userName)
                
            elif args.user_cmd == "pwd":
                if not pwDB.hasUser(userName):
                    sys.exit("User %s does not already exist" % userName)
                oldPwHash = pwDB.currentUserPassword(userName)
                newPw = getPasswordHashRoutine(oldPwHash)
                pwDB.createUser(userName, newPw, modify=True)
                
            elif args.user_cmd == "chmod":
                accountName = args.account_name
                accessString = args.privileges
                
                if not pwDB.hasUser(userName):
                    sys.exit("User %s does not already exist" % userName)
                
                if accountName and not pwDB.hasAccount(accountName):
                    sys.exit("Account %s does not exist" % accountName)
                    
                if accountName and accessString:
                    if not pwDB.isValidAccessSpec(accessString, accountName):
                        sys.exit("Invalid access spec")
                    pwDB.configureAccess(userName, accountName, accessString)
                else:
                    print("current privileges", pwDB.currentAccess(userName, accountName))
                
            else:
                print("Unhandled command {}".format(args.user_cmd))
                
        elif args.db_cmd == "account":
            # Unfortunately, the password database and the
            # bank ledger database have to be kept in sync. 
            # Both have to have the same set of accounts.
            # TODO: Fix this.
            passwd = getpass.getpass("Bank password required for changing account: ")
            accountName = args.account_name
            if args.account_cmd == "add":
                if pwDB.hasAccount(accountName):
                    sys.exit("Account %s already exists" % accountName)
                
                bank = Ledger(self._bankPath, self._certPath, passwd)
                bank.createAccount(accountName)
                pwDB.createAccount(accountName)
            elif args.account_cmd == "del":
                sys.exit("Account del not yet implemented")
            else:
                print ("Unhandled command {}".format(args.account_cmd))
                
        pwDB.sync()
        sys.exit("Finished.")
        
    def handle_server(self):
        if "SERVER" not in self._bankConfig:
            raise Exception("Server has not yet been configured.")
        required_config = "port",
        for k in required_config:
            if k not in self._bankConfig["SERVER"]:
                raise Exception("Client not yet configured. Requires {}".format(k))
                
        enableSecurityLogging(self._bankPath)
        logSecure("Security Logging Enabled, creating bank server from path %s" % self._bankPath)
        
        cert = loadCertFromFile(self._certPath)
        ledgerPassword = getpass.getpass("Enter bank password:")
        
        bank = Ledger(self._bankPath, cert, ledgerPassword)
        bankServer = PlaygroundOnlineBank(self._pwfile, bank)
        if self._mintCertPath:
            result = bank.registerMintCert(self._mintCertPath)
            if not result.succeeded():
                sys.exit("Could not load mint certificate", result.msg())
                
        bankPort = int(self._bankConfig["SERVER"]["port"])
        stack = self._bankConfig["SERVER"].get("stack","default")

        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        coro = playground.getConnector(stack).create_playground_server(
            bankServer.buildProtocol, 
            bankPort)
        server = loop.run_until_complete(coro)
        localhost_name = server.sockets[0].gethostname()
        print("Bank Server Started at {}".format(localhost_name))
        print("To access start a bank client protocol to {}".format(localhost_name))
        loop.run_forever()
        loop.close()
        
    def handle_client(self):
        if "CLIENT" not in self._bankConfig:
            raise Exception("Client has not yet been configured.")
        required_config = "bank_addr", "bank_port", "username"
        for k in required_config:
            if k not in self._bankConfig["CLIENT"]:
                raise Exception("Client not yet configured. Requires {}".format(k))
        
        bank_addr =     self._bankConfig["CLIENT"]["bank_addr"]
        bank_port = int(self._bankConfig["CLIENT"]["bank_port"])
        stack     =     self._bankConfig["CLIENT"].get("stack","default")
        username  =     self._bankConfig["CLIENT"]["username"]
        
        
        cert = loadCertFromFile(self._certPath)
        passwd = getpass.getpass("Enter bank account password for {}: ".format(username))

        clientFactory = PlaygroundOnlineBankClient(cert, username, passwd)
        clientFactory.stack = self._bankConfig["SERVER"].get("stack","default") # UGLY HACK TO FIX LATER

        loop = asyncio.get_event_loop()

        def initShell():
            print("start init")
            uiFactory = AdminBankCLIClient(None, clientFactory, bank_addr, bank_port)
            uiFactory.registerExitListener(lambda reason: loop.call_later(2.0, loop.stop))
            a = CLIShell.AdvancedStdio(uiFactory)

        # loop.set_debug(enabled=True)
        loop.call_soon(initShell)
        loop.run_forever()
            
    def reloadConfig(self):
        
        bankconfigFile = os.path.join(self._bankconfigPath, "config.ini")
        self._bankConfig = configparser.ConfigParser()
        self._bankConfig.read(bankconfigFile)
        
    def saveConfig(self):
        bankconfigFile = os.path.join(self._bankconfigPath, "config.ini")
        with open(bankconfigFile, 'w') as configfile:
            self._bankConfig.write(configfile)
        
    def handle_config(self, args):
        self.reloadConfig()
        section,param = args.setting.split(":")
        section = section.upper()
        
        if section == "SERVER":
        
            if section not in self._bankConfig:
                self._bankConfig[section] = {}
            
            if param == "port":
                port, = args.setting_args
                int(port)
                self._bankConfig[section][param] = port
                
            elif param == "stack":
                self._bankConfig[section][param] = port
                
            else:
                print("Unknown settiong {}".format(args.setting))
                
        elif section == "CLIENT":
            if section not in self._bankConfig:
                self._bankConfig[section] = {}
                
            if param in ["username", "bank_addr", "bank_stack"]:
                value, = args.setting_args
                self._bankConfig[section][param] = value
            elif param == "bank_port":
                port, = args.setting_args
                int(port)
                self._bankConfig[section][param] = port
                
            else:
                print("Unknown settiong {}".format(args.setting))
        self.saveConfig()
            
        
    def handle(self, args):
        
        args = self._parser.parse_args(args)
        self._verbose = args.verbose
        
        if args.cmd == "initialize":
            self.initialize_bank(args)
            
        self.reloadConfig()
    
        if args.cmd == "config":
            self.handle_config(args)
            
        if args.cmd == "db":
            self.handle_db_cmd(args)

        elif args.cmd == "verify":
            receipt, receiptSig = args.receipt_file, args.receipt_sig_file
            cert = loadCertFromFile(certpath)
            verifier = RSA_SIGNATURE_MAC(cert.public_key())
            with open(receipt,"rb") as f:
                receiptData = f.read()
            with open(receiptSig,"rb") as f:
                receiptSigData = f.read()
            print("Verification result = ",
                  verifier.verify(receiptData, receiptSigData))

        elif args.cmd == "server":
            self.handle_server()

        elif args.cmd == "client":
            overrides = {}
            if args.override:
                if "CLIENT" not in self._bankConfig:
                    self._bankConfig["CLIENT"] = {}
                for key, value in args.override:
                    self._bankConfig["CLIENT"][key] = value
            self.handle_client()

if __name__ == "__main__":
    interface = OnlineBankInterface()
    interface.handle(sys.argv[1:])
