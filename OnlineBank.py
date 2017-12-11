'''
Created on Mar 27, 2014

@author: sethjn
'''

import sys, os, getpass, shelve, time, traceback, datetime, asyncio
# from contextlib import closing

from BankMessages import *
from Exchange import BitPoint

from BankCore import Ledger, LedgerLine # For unshelving
from AsyncIODeferred import Deferred

# TODO: Change to match actual playground layout (gotta push these too)
from CipherUtil import SHA, loadCertFromFile, RSA_SIGNATURE_MAC
from ui import CLIShell
from network.common import ErrorHandler
from network.common.PacketHandler import SimplePacketHandler

import playground
from playground.network.common.Protocol import StackingProtocol
from playground.network.common.PlaygroundAddress import PlaygroundAddress
from playground.network.packet.PacketType import FIELD_NOT_SET

import logging
logger = logging.getLogger(__file__)

RANDOM_u64 = lambda: int.from_bytes(os.urandom(8), "big")

PasswordBytesHash = lambda pw: SHA(pw).digest()
PasswordHash = lambda pw: PasswordBytesHash(bytes(pw, "utf-8"))

# TODO: Configurations
DEBUG = True
BANK_FIXED_PLAYGROUND_ADDR = PlaygroundAddress(20174, 1, 1337, 1)
BANK_FIXED_PLAYGROUND_PORT = 700
# The playground address network (XXXX.___.XXXX.XXXX) allowed
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


class BankServerProtocol(StackingProtocol, SimplePacketHandler, ErrorHandler):

    STATE_UNINIT = "Uninitialized"
    STATE_OPEN = "Open"
    STATE_ERROR = "Error"
    
    ADMIN_PW_ACCOUNT = "__admin__"
    ADMIN_ACCOUNTS = ["VAULT"]
    
    WITHDRAWAL_LIMIT = 1000
    WITHDRAWAL_WINDOW = 6*3600 # 6 hours in seconds
    
    def __logSecure(self, msg):
        fullMsg = "SERVER SECURITY (Session %(ClientNonce)d-%(ServerNonce)d"
        fullMsg += " User [%(LoginName)s] Account [%(AccountName)s] "
        fullMsg = fullMsg % self.__connData
        peer = self.transport and self.transport.get_extra_info("peername") or "<NOT CONNECTED>"
        fullMsg += " Peer [%s]): " % (peer,)
        fullMsg += msg
        logSecure(fullMsg)
    
    def __init__(self, pwDb, bank):
        debugPrint("server proto init")
        SimplePacketHandler.__init__(self)
        #self.setHandler(self)
        self.__pwDb = pwDb
        self.__connData = {"ClientNonce":0,
                           "ServerNonce":0,
                           "AccountName":None,
                           "LoginName":None}
        self.__state = self.STATE_UNINIT
        self.__bank = bank
        self.__withdrawlTracking = {}
        self.registerPacketHandler(OpenSession, self.__handleOpenSession)
        self.registerPacketHandler(ListAccounts, self.__handleListAccounts)
        self.registerPacketHandler(ListUsers, self.__handleListUsers)
        self.registerPacketHandler(CurrentAccount, self.__handleCurrentAccount)
        self.registerPacketHandler(SwitchAccount, self.__handleSwitchAccount)
        self.registerPacketHandler(BalanceRequest, self.__handleBalanceRequest)
        self.registerPacketHandler(TransferRequest, self.__handleTransferRequest)
        self.registerPacketHandler(DepositRequest, self.__handleDeposit)
        self.registerPacketHandler(WithdrawalRequest, self.__handleWithdrawal)
        self.registerPacketHandler(AdminBalanceRequest, self.__handleAdminBalanceRequest)
        self.registerPacketHandler(CreateAccountRequest, self.__handleCreateAccount)
        self.registerPacketHandler(SetUserPasswordRequest, self.__handleSetUserPassword)
        self.registerPacketHandler(ChangeAccessRequest, self.__handleChangeAccess)
        self.registerPacketHandler(CurAccessRequest, self.__handleCurAccess)
        self.registerPacketHandler(LedgerRequest, self.__handleLedgerRequest)
        self.registerPacketHandler(Close, self.__handleClose)

    def connection_made(self, transport):
        debugPrint("server proto connection made", transport)
        StackingProtocol.connection_made(self, transport)
        self.transport = transport

    def sendPacket(self, packet):
        self.transport.write(packet.__serialize__())
        debugPrint("Sent", packet.DEFINITION_IDENTIFIER)

    def data_received(self, packet):
        debugPrint("server proto data_received")
        self.__logSecure("Received packet %s" % packet)
        try:
            self.handlePacket(None, packet)
        except Exception as e:
            print(traceback.format_exc())
        
    def __clearWithdrawlLimit(self, account):
        if account in self.__withdrawlTracking:
            del self.__withdrawlTracking[account]
    
    # def handleError(self, message, reporter=None, stackHack=0):
    #     self.__logSecure("Error Reported %s" % message )
    #     # handleError handles error messages reported in the framework
    #     # this is different from __error, which is designed to handle
    #     # errors in the protocol
    #     self.g_ErrorHandler.handleError(message, reporter, stackHack)
    
    # def handleException(self, e, reporter=None, stackHack=0, fatal=False):
    #     # handle if it's reported by us, or by one of our methods
    #     localHandler = (reporter == self or (hasattr(reporter,"im_self") and reporter.im_self==self))
    #     if not localHandler:
    #         self.g_ErrorHandler.handleException(e, reporter, stackHack, fatal)
    #         return
    #
    #     # this is an exception handler for exceptions raised by the framework
    #     errMsg = "Error reported in handler %s\n" % str(reporter)
    #     errMsg += traceback.format_exc()
    #     # we will treat exceptions as fatal. Try to shut down
    #     try:
    #         networkErrorMessage = ServerError()
    #         networkErrorMessage.ErrorMessage = errMsg
    #         self.transport.write(networkErrorMessage)
    #         self.handleError(errMsg)
    #     except Exception:
    #         self.handleError("Failed to transmit message: " + errMsg)
    #         self.handleError(traceback.format_exc())
    #     try:
    #         callLater(0, self.transport.close)
    #     except:
    #         pass
    
    def __error(self, errMsg, requestId = 0, fatal=True):
        debugPrint("server proto error ", errMsg)
        self.__logSecure(errMsg)
        if self.__state == self.STATE_ERROR:
            return None
        if self.__state == self.STATE_UNINIT:
            response = LoginFailure()
            response.ClientNonce = self.__connData["ClientNonce"]
        else:
            response = RequestFailure()
            response.ClientNonce = self.__connData["ClientNonce"]
            response.ServerNonce = self.__connData["ServerNonce"]
            response.RequestId = requestId
        response.ErrorMessage = errMsg
        self.sendPacket(response)
        if fatal:
            debugPrint("server proto error Closing connection!")
            self.__state = self.STATE_ERROR
            callLater(1, self.transport.close)
        return None
    
    def __sendPermissionDenied(self, errMsg, requestId=0):
        if self.__state == self.STATE_ERROR:
            return None
        self.__logSecure("Permission denied, %s" % errMsg)
        response = PermissionDenied()
        response.ClientNonce = self.__connData.get("ClientNonce",0)
        response.ServerNonce = self.__connData.get("ServerNonce",0)
        response.RequestId = requestId
        response.ErrorMessage = errMsg
        self.sendPacket(response)
        return None
    
    def __getSessionAccount(self, msgObj):
        if self.__state != self.STATE_OPEN:
            self.__error("Session not logged-in", msgObj.RequestId)
            return None, None
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            self.__error("Invalid connection data", msgObj.RequestId)
            return None, None
        account = self.__connData["AccountName"]
        userName = self.__connData["LoginName"]
        if account and self.__pwDb.hasAccount(account):
            access = self.__pwDb.currentAccess(userName, account)
        else: access = ''
        debugPrint("server __getSessionAccount acc:", account, "access:", access)
        return (account, access)
    
    def __validateAdminPeerConnection(self):
        peer = self.transport.get_extra_info("peername")
        debugPrint("Server's Peer:", peer)
        if not peer: return False
        addr = PlaygroundAddress.FromString(peer[0])
        # Uhhh this is a weird check...
        #if addr[1] != ADMIN_ZONE: return False
        return True

    def __getAdminPermissions(self, requestId=0, fatal=True):
        if not self.__validateAdminPeerConnection():
            if fatal: self.__error("Unauthorized connection location. Will be logged", requestId)
            return None
        userName = self.__connData.get("LoginName",None)
        if not userName:
            if fatal: self.__error("Attempt for admin without logging in. Will be logged", requestId)
            return None
        if not self.__pwDb.hasUser(userName):
            if fatal: self.__error("Attempt for admin from not user. Will be logged", requestId)
            return None
        access = self.__pwDb.currentAccess(userName, self.ADMIN_PW_ACCOUNT)
        if not access:
            if fatal: self.__error("Attempt for admin without any admin permissions. Will be logged", requestId)
            return None
        return access
    
    """def __getAdminAccount(self, msgObj):
        if not self.__validateAdminPeerConnection():
            self.__error("Unauthorized connection location. Will be logged", msgObj.RequestId)
            return None
        account = self.__getSessionAccount(msgObj)
        if account != self.ADMIN_PW_ACCOUNT:
            self.__error("Unauthorized account", msgObj.RequestId)
            return None
        return account"""
    
    def __createResponse(self, msgObj, responseType):
        response = responseType()
        response.ClientNonce = msgObj.ClientNonce
        response.ServerNonce = msgObj.ServerNonce
        return response
    
    def __handleOpenSession(self, protocol, msg):
        # permissions: None
        if self.__state != self.STATE_UNINIT:
            return self.__error("Session not uninitialized. State %s" % self.__state)
        msgObj = msg
        self.__connData["ClientNonce"] = msgObj.ClientNonce
        if not self.__pwDb.hasUser(msgObj.Login):
            debugPrint("server proto __handleOpenSession pw not equal")
            return self.__error("Invalid Login. User does not exist or password is wrong")
        passwordHash = self.__pwDb.currentUserPassword(msgObj.Login)
        # debugPrint(passwordHash, len(passwordHash), type(passwordHash), "VS", msgObj.PasswordHash, len(msgObj.PasswordHash), type(msgObj.PasswordHash))
        if passwordHash != eval(msgObj.PasswordHash):
            debugPrint("server proto __handleOpenSession pw not equal")
            return self.__error("Invalid Login. User does not exist or password is wrong")
        """if not  accountName in self.__bank.getAccounts():
            return self.__error("Invalid Login")"""
        self.__connData["ServerNonce"] = RANDOM_u64()
        self.__connData["AccountName"] = ""
        self.__connData["LoginName"] = msgObj.Login
        self.__state = self.STATE_OPEN
        response = SessionOpen()
        response.ClientNonce = msgObj.ClientNonce
        response.ServerNonce = self.__connData["ServerNonce"]
        response.Account = ""
        self.__logSecure("Request for open with nonce %d, sending back %d" % (msgObj.ClientNonce,
                                                                              self.__connData["ServerNonce"]))
        self.sendPacket(response)
        
    def __handleCurrentAccount(self, protocol, msg):
        # permissions: None
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if account is None: # require
            return 
        response = self.__createResponse(msgObj, CurrentAccountResponse)
        response.Account = account
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
        
    def __handleListAccounts(self, protocol, msg):
        # permissions: regular - None, for a specific user, Admin(B)
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if account is None:
            return
        if msgObj.User != FIELD_NOT_SET:
            adminAccessData = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccessData is None:
                # error already reported.
                return None
            if "B" not in adminAccessData:
                self.__logSecure("Trying to list accounts for %s requires 'B' access, but has %s" % (msgObj.User, adminAccessData))
                return self.__sendPermissionDenied("Requires 'B' access", msgObj.RequestId)
            userName = msgObj.User
        else:
            userName = self.__connData["LoginName"]
        accountAccessData = self.__pwDb.currentAccess(userName)
        accountNames = list(accountAccessData.keys())
        response = self.__createResponse(msgObj, ListAccountsResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = accountNames
        self.sendPacket(response)
        
    def __handleListUsers(self, protocol, msg):
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        users = []
        if account is None:
            return
        if msgObj.Account == FIELD_NOT_SET:
            # use current account, unless account is not set, in which case
            # it has to be administrator
            accountToList = account
        else:
            accountToList = msgObj.Account
        self.__logSecure("list users requested for account %s" % accountToList)
            
        if accountToList == '':
            adminAccessData = self.__getAdminPermissions(msgObj.RequestId)
            self.__logSecure("List of all users required admin access")
            if adminAccessData is None:
                # error already reported
                return None
            accountToList = None
        else:
            accountToListAccess = self.__pwDb.currentAccess(self.__connData["LoginName"], accountToList)
            if 'a' not in accountToListAccess:
                self.__logSecure("List of users for account %s required 'a', but access is %s" % (accountToList, accountToListAccess))
                return self.__sendPermissionDenied("Requires 'a' access", msgObj.RequestId)

        for name in self.__pwDb.iterateUsers(accountToList):
            users.append(name)
        response = self.__createResponse(msgObj, ListUsersResponse)
        response.RequestId = msgObj.RequestId
        response.Users = users
        self.__logSecure("sending list of %d users" % len(users))
        self.sendPacket(response)
        
    def __handleSwitchAccount(self, protocol, msg):
        # permissions: some permissions on account, if an admin account, 'S'
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if account is None:
            return
        desiredAccount = msgObj.Account
        
        result = True
        if desiredAccount.startswith("__"):
            self.__logSecure("ATTEMPT TO ACCESS SPECIAL ACCOUNT %s" % desiredAccount)
            result = False
        elif desiredAccount in self.ADMIN_ACCOUNTS:
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess is None:
                self.__logSecure("ATTEMPT TO ACCESS ADMIN ACCOUNT %s" % desiredAccount)
                return
            if 'S' not in adminAccess:
                self.__logSecure("ATTEMPT TO ACCESS ADMIN ACCOUNT %s WITHOUT 'S' in %s" % (desiredAccount, adminAccess))
                return self.__sendPermissionDenied("Requires 'S' permissions", msgObj.RequestId)
        elif desiredAccount:
            access = self.__pwDb.currentAccess(self.__connData["LoginName"], desiredAccount)
            if not access:
                self.__logSecure("Attempt to switch to %s, but no access" % desiredAccount) 
                result = False
        if result:
            self.__connData["AccountName"] = desiredAccount
            self.__logSecure("Account Switched")
        if result:
            response = self.__createResponse(msgObj, RequestSucceeded)
        else:
            response = self.__createResponse(msgObj, RequestFailure)
            response.ErrorMessage = "Could not switch accounts"
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
    
    def __handleBalanceRequest(self, protocol, msg):
        # permissions: regular(b)
        debugPrint("server __handleBalanceRequest requestID:", msg.RequestId, type(msg.RequestId))
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            self.__logSecure("Cannot get balance when no account selected")
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected"
            self.sendPacket(response)
            return None
        if 'b' not in access:
            self.__logSecure("Required 'b' access for account %s, but had %s" % (account, access))
            return self.__sendPermissionDenied("No Permission to check Balances", 
                                               msgObj.RequestId)
        balance = self.__bank.getBalance(account) or 0
        debugPrint("Balance for account", account, ":", balance)
        response = self.__createResponse(msgObj, BalanceResponse)
        response.RequestId = msgObj.RequestId
        response.Balance = balance
        self.__logSecure("Sending back balance")
        self.sendPacket(response)
        
    def __handleAdminBalanceRequest(self, protocol, msg):
        # permissions: Admin(B)
        msgObj = msg
        adminAccess = self.__getAdminPermissions(msgObj.RequestId)
        if adminAccess is None:
            self.__logSecure("No admin access to get admin balances")
            return
        if "B" not in adminAccess:
            self.__logSecure("Requires 'B' access for balances, but have %s" % adminAccess)
            return self.__sendPermissionDenied("Requires 'B' access", msgObj.RequestId)
        accountList = self.__bank.getAccounts()
        balancesList = []
        for account in accountList:
            balancesList.append(self.__bank.getBalance(account))
        response = self.__createResponse(msgObj, AdminBalanceResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = list(accountList)
        response.Balances = balancesList
        self.__logSecure("Sending back %d balances" % len(balancesList))
        self.sendPacket(response)
        
    def __handleTransferRequest(self, protocol, msg):
        # permissions: regular(t)
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            self.__logSecure("Cannot get transfer when no account selected")
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected"
            self.sendPacket(response)
        if not 't' in access:
            self.__logSecure("Requires 't' access to transfer from %s, but have %s" % (account, access))
            return self.__sendPermissionDenied("Requires 't' access", msgObj.RequestId)
        dstAccount = msgObj.DstAccount
        if not dstAccount in self.__bank.getAccounts():
            return self.__error("Invalid destination account %s" % dstAccount, msgObj.RequestId,
                                fatal=False)
        amount = msgObj.Amount
        if amount < 0: 
            return self.__error("Invalid (negative) amount %d" % amount, msgObj.RequestId,
                                fatal=False)
        if amount > self.__bank.getBalance(account):
            return self.__error("Insufficient Funds to pay %d" % amount, msgObj.RequestId,
                                fatal=False)
        result = self.__bank.transfer(account,dstAccount, amount, msgObj.Memo)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        # Assume single threaded. The last transaction will still be the one we care about
        result = self.__bank.generateReceipt(dstAccount)
        if not result.succeeded():
            return self.__error("Bank transfer failed: " + result.msg(), msgObj.RequestId,
                                fatal=True)
        receipt, signature = result.value()
        response = self.__createResponse(msgObj, Receipt)
        response.RequestId = msgObj.RequestId
        response.Receipt = receipt
        response.ReceiptSignature = signature
        self.__logSecure("Transfer succeeded, sending receipt")
        self.sendPacket(response)
        
    def __handleDeposit(self, protocol, msg):
        # requires: regular(d)
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            self.__logSecure("Cannot get deposit when no account selected")
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected"
            self.sendPacket(response)
        if 'd' not in access:
            self.__logSecure("Requires 'd' access to deposit in %s, but have %s" % (account, access))
            return self.__sendPermissionDenied("Requires 'd' access", msgObj.RequestId)
        bps = []
        bpData = eval(msgObj.bpData)
        # debugPrint(bpData[:15], "...", bpData[-15:], len(bpData), type(bpData))
        while bpData:
            newBitPoint, offset = BitPoint.deserialize(bpData)
            bpData = bpData[offset:]
            bps.append(newBitPoint)
        result = self.__bank.depositCash(account,bps)
        if not result.succeeded():
            self.__logSecure("Deposit failed, %s" % result.msg())
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = result.msg()
        else:
            result = self.__bank.generateReceipt(account)
            if not result.succeeded():
                self.__logSecure("Could not generate receipt? %s" % result.msg())
                response = self.__createResponse(msgObj, RequestFailure)
                response.RequestId = msgObj.RequestId
                response.ErrorMessage = result.msg()
            else:
                self.__logSecure("Deposit complete. Sending Signed Receipt")
                receipt, signature = result.value()
                response = self.__createResponse(msgObj, Receipt)
                response.RequestId = msgObj.RequestId
                response.Receipt = receipt
                response.ReceiptSignature = signature
        self.sendPacket(response)
        
    def __handleWithdrawal(self, protocol, msg):
        # requires: regular(d)
        msgObj = msg
        account, access = self.__getSessionAccount(msgObj)
        if not account:
            self.__logSecure("Cannot withdraw when no account selected")
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected"
            self.sendPacket(response)
        if 'd' not in access:
            self.__logSecure("Requires 'd' access to withdraw from %s but have %s" % (account, access))
            return self.__sendPermissionDenied("Requires 'd' access", msgObj.RequestId)
        if self.__withdrawlTracking.get(account,0)+msgObj.Amount > self.WITHDRAWAL_LIMIT:
            self.__logSecure("Attempt to withdraw over the limit. Current: %d, requested: %d, limit: %d" % 
                             (self.__withdrawlTracking.get(account, 0), msgObj.Amount, self.WITHDRAWAL_LIMIT))
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Over Limit"
            self.sendPacket(response)
            return
        result = self.__bank.withdrawCash(account,msgObj.Amount)
        if not result.succeeded():
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = result.msg()
        else:
            if account not in self.__withdrawlTracking:
                self.__withdrawlTracking[account] = 0
                callLater(self.WITHDRAWAL_WINDOW, lambda: self.__clearWithdrawlLimit(account))
            self.__withdrawlTracking[account] += msgObj.Amount
            bitPoints = result.value()
            bpData = b""
            for bitPoint in bitPoints:
                bpData += bitPoint.serialize()
            response = self.__createResponse(msgObj, WithdrawalResponse)
            response.RequestId = msgObj.RequestId
            response.bpData = bpData
        self.sendPacket(response)
        
    def __isValidUsername(self, name):
        for letter in name:
            if not letter.isalnum() and not letter == "_":
                return False
        return True
        
    def __handleSetUserPassword(self, protocol, msg):
        # requires that the user is changing his own password, or Admin('A') access
        msgObj = msg
        userName = msgObj.loginName
        newUser = msgObj.NewUser
        self.__logSecure("Received change password request. Current user %s, user to change [%s]" % 
                    (self.__connData["LoginName"], userName))
        errorResponse = self.__createResponse(msgObj, RequestFailure)
        errorResponse.RequestId = msgObj.RequestId
        okResponse = self.__createResponse(msgObj, RequestSucceeded)
        okResponse.RequestId = msgObj.RequestId
        if not userName:
            userName = self.__connData["LoginName"]
        
        if (newUser or userName != self.__connData["LoginName"]):
            # if this is a new user, must be admin because couldn't login
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess is None:
                self.__logSecure("Failed. Admin access required to create user, or change other user")
                return
            if "A" not in adminAccess:
                self.__logSecure("Failed. Requires 'A' access, but only have %s" % adminAccess)
                return self.__sendPermissionDenied("Requires 'A' access", msgObj.RequestId)
            
            if newUser and self.__pwDb.hasUser(userName):
                self.__logSecure("Tried to create user %s that already exists" % userName)
                errorResponse.ErrorMessage = "User %s already exists" % userName
                self.sendPacket(errorResponse)
                return
            elif newUser and not self.__isValidUsername(userName):
                self.__logSecure("Attempt to create user with invalid name [%s]" % userName)
                errorResponse.ErrorMessage = "Username invalid. Only letters, numbers, and underscores."
                self.sendPacket(errorResponse)
                return
            elif not newUser and not self.__pwDb.hasUser(userName):
                self.__logSecure("Attempt to change password for non-existent user [%s]" % userName)
                errorResponse.ErrorMessage = "User %s does not exist" % userName
                self.sendPacket(errorResponse)
                return
        elif msgObj.oldPwHash == '':
            # Cannot allow this.
            self.__logSecure("Attempt to change username %s without previous hash" % userName)
            errorResponse.ErrorMessage = "No password hash specified"
            self.sendPacket(errorResponse)
            return
        elif self.__pwDb.currentUserPassword(userName) != eval(msgObj.oldPwHash):
                self.__logSecure("Incorrect previous password for %s password change" % userName)
                errorResponse.ErrorMessage = "Invalid Password"
                self.sendPacket(errorResponse)
                return
            
        pwHash = eval(msgObj.newPwHash)
        self.__pwDb.createUser(userName, pwHash, modify=True)
        self.__pwDb.sync()
        self.__logSecure("Password changed")
        self.sendPacket(okResponse)
        
    def __handleCreateAccount(self, protocol, msg):
        # requires Admin(A)
        msgObj = msg
        adminAccess = self.__getAdminPermissions(msgObj.RequestId)
        if adminAccess is None:
            self.__logSecure("Creating an account requires administrator access")
            return
        if "A" not in adminAccess:
            self.__logSecure("Creating an account requires 'A' access. Only have %s" % adminAccess)
            return self.__sendPermissionDenied("Requires 'A' access", msgObj.RequestId)
        
        response = self.__createResponse(msgObj, RequestSucceeded)
        newAccountName = msgObj.AccountName
        if self.__pwDb.hasAccount(newAccountName):
            self.__logSecure("Attempt to create account that already exists")
            response = self.__createResponse(msgObj, RequestFailure)
            response.ErrorMessage = "That account already exists"
        result = self.__bank.createAccount(newAccountName)
        if result.succeeded():
            self.__logSecure("New account %s created" % newAccountName)
            if not self.__pwDb.hasUser(newAccountName):
            # should only happen if we manually added a user to pwDB
                self.__pwDb.createAccount(newAccountName)
            self.__pwDb.sync()
        else:
            self.__logSecure("Internal Failure in creating account %s" % newAccountName)
            response = self.__createResponse(msgObj, RequestFailure)
            response.ErrorMessage = "Could not create account. Internal error"
        response.RequestId = msgObj.RequestId
        self.sendPacket(response)
        
    def __handleCurAccess(self, protocol, msg):
        msgObj = msg
        userName = self.__connData["LoginName"]
        if msgObj.UserName != FIELD_NOT_SET:
            checkUserName = msgObj.UserName
        else:
            checkUserName = userName
        if msgObj.AccountName != FIELD_NOT_SET:
            accountName = msgObj.AccountName
        else: accountName = None
        self.__logSecure("Attempt to check access of %s on account %s" % (checkUserName, accountName))
        
        if userName != checkUserName and not accountName:
            # requires admin access to get general permissions for other user
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess is None:
                self.__logSecure("Checking this access requires administrative access")
                return
            if 'A' not in adminAccess:
                self.__logSecure("Checking this access requires 'A' access, but have %s" % adminAccess)
                return self.__sendPermissionDenied("Requires admin access 'A'", 
                                                   msgObj.RequestId)
        elif userName != checkUserName:
            # requires 'a' to check other user's permissions on an account
            access = self.__pwDb.currentAccess(userName, accountName) 
            if 'a' not in access:
                self.__logSecure("Checking this access requires 'a' access but have %s" % access)
                return self.__sendPermissionDenied("Requires access 'a'", 
                                                   msgObj.RequestId)
        
        accounts = []
        accountsAccess = []
        if accountName:
            accounts.append(accountName)
            accountsAccess.append(self.__pwDb.currentAccess(checkUserName, accountName))
        else:
            accessMulti = self.__pwDb.currentAccess(checkUserName)
            for accountName, accountAccessString in accessMulti.items():
                accounts.append(accountName)
                accountsAccess.append(accountAccessString)
        response = self.__createResponse(msgObj, CurAccessResponse)
        response.RequestId = msgObj.RequestId
        response.Accounts = accounts
        response.Access = accountsAccess
        self.__logSecure("Sending back access information for %s on %d accounts" % (checkUserName, len(accountsAccess)))
        self.sendPacket(response)
        
    def __handleChangeAccess(self, protocol, msg):
        # if no account is specified, it must be for the current account with 'a' access
        # if an account is specified, it must belong to the current user with 'a' access
        # if an account is specified that doesn't belong to the current user, Admin('A')
        msgObj = msg
        userName = self.__connData["LoginName"]
        changeUserName = msgObj.UserName
        account, access = self.__getSessionAccount(msgObj)
        if account is None:
            self.__logSecure("Cannot change access. There was an error in state")
            return None # this was an actual error
        if not account and msgObj.Account == FIELD_NOT_SET:
            self.__logSecure("Cannot change access, no account specified, and no current account selected")
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Account must be selected or specified"
            self.sendPacket(response)
            return
        if msgObj.Account != FIELD_NOT_SET:
            account = msgObj.Account
            self.__logSecure("Trying to change access for %s in account %s" % (userName, account))
            access = self.__pwDb.currentAccess(userName, account)
        if not access:
            # doesn't own the account. Check admin 
            # 
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess is None:
                self.__logSecure("Access change request requires an administrator")
                return
            if 'A' not in adminAccess:
                self.__logSecure("Access change request requires 'A' access, but have %s" % adminAccess)
                return self.__sendPermissionDenied("Requires admin access or regular 'a'", 
                                                   msgObj.RequestId)
        elif 'a' not in access:
            # do a non-fatal admin access check
            adminAccess = self.__getAdminPermissions(msgObj.RequestId, fatal=False)
            if not adminAccess or 'A' not in adminAccess:
                self.__logSecure("Access change request requires 'a' or 'A' but got %s and %s" % (access, adminAccess))
                return self.__sendPermissionDenied("Requires 'a' access or admin", msgObj.RequestId)
        
        if not self.__pwDb.isValidAccessSpec(msgObj.AccessString, account):
            response = self.__createResponse(msgObj, RequestFailure)
            response.RequestId = msgObj.RequestId
            response.ErrorMessage = "Invalid access string %s" % msgObj.AccessString
            self.__logSecure("Tried to change access to invalid %s" % msgObj.AccessString)
            self.sendPacket(response)
            return
        self.__pwDb.configureAccess(changeUserName, account, msgObj.AccessString)
        self.__pwDb.sync()
        response = self.__createResponse(msgObj, RequestSucceeded)
        response.RequestId = msgObj.RequestId
        self.__logSecure("User %s access to %s changed to %s" % (changeUserName, account, msgObj.AccessString))
        self.sendPacket(response)

    def __handleLedgerRequest(self, protocol, msg):
        msgObj = msg
        #account, access = self.__getSessionAccount(msgObj)
        userName = self.__connData["LoginName"]
        accountToGet = msgObj.Account != FIELD_NOT_SET and msgObj.Account or None
        self.__logSecure("Request ledger for user %s and account %s" % (userName, accountToGet))
        if not accountToGet:
            # No account specified. Get the entire bank ledger.
            # this is administrative access only.
            adminAccess = self.__getAdminPermissions(msgObj.RequestId)
            if adminAccess is None:
                self.__logSecure("Requesting an all-accounts ledger requires admin access")
                return
            if 'A' not in adminAccess:
                self.__logSecure("Requesting an all-accounts ledger requires 'A' access, but have %s" % adminAccess)
                return self.__sendPermissionDenied("Requires admin access", 
                                                   msgObj.RequestId)
            # return all lines
            lFilter = lambda lline: True
        else:
            accountToGetAccess = self.__pwDb.currentAccess(userName, accountToGet) 
            if 'a' not in accountToGetAccess:
                # don't kill the connection if we don't have admin. Just tell them.
                adminAccess = self.__getAdminPermissions(msgObj.RequestId, fatal=False)
                if adminAccess is None or 'A' not in adminAccess:
                    self.__logSecure("User %s attempting to get ledger for %s requires 'a' or 'A', but have %s and %s" %
                                     (userName, accountToGet, accountToGetAccess, adminAccess))
                    return self.__sendPermissionDenied("Requires admin access or regular 'a'", 
                                                       msgObj.RequestId)
            lFilter = lambda lline: lline.partOfTransaction(accountToGet)
        lineNums = self.__bank.searchLedger(lFilter)
        lines = []
        for lineNum in lineNums:
            line = self.__bank.getLedgerLine(lineNum)
            lines.append(line.toHumanReadableString(accountToGet))
        response = self.__createResponse(msgObj, LedgerResponse)
        response.RequestId = msgObj.RequestId
        response.Lines = lines
        self.__logSecure("User %s getting ledger for %s (%d lines" % (userName, accountToGet, len(lines)))
        self.sendPacket(response)
            
    def __handleClose(self, protocol, msg):
        debugPrint("server __handleClose", msg.DEFINITION_IDENTIFIER)
        msgObj = msg
        self.__logSecure("Close Connection")
        if self.__state != self.STATE_OPEN:
            return # silently ignore close messages on unopen connections
        if self.__connData["ClientNonce"] != msgObj.ClientNonce:
            return # silently ignore close messages on wrong client nonce
        if self.__connData["ServerNonce"] != msgObj.ServerNonce:
            return # silently ignore close messages on wrong server nonce
        self.__state = self.STATE_UNINIT
        if self.transport: self.transport.close()
        
        
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

    def __init__(self, clientBase, bankClientFactory, bankAddr):
        CLIShell.CLIShell.__init__(self, prompt=self.NON_ADMIN_PROMPT)
        self.__d = None
        self.__backlog = []
        self.__bankClient = None
        self.__bankAddr = bankAddr
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
        try:
            CLIShell.CLIShell.connection_made(self, transport)

            loop = self.__asyncLoop
            debugPrint("CLI Making a client connection...")
            coro = playground.getConnector(self.__bankClientFactory.stack).create_playground_connection(self.__bankClientFactory.buildProtocol, self.__bankAddr, BANK_FIXED_PLAYGROUND_PORT)
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
            
class PlaygroundNodeControl(object):
    Name = "OnlineBank"
    def __init__(self):
        self.__mode = None
        self.__stdioUI = None
    
    def processServer(self, serverArgs):
        self.__mode = "server"
        if len(serverArgs) not in [3,4]:
            return (False, "Bank server requires " +
                            "passwordFile, bankPath, certPath, (optional: mintCert)")

        stack, passwordFile, bankPath, certPath = serverArgs[0:4]

        if not os.path.exists(passwordFile):
            return (False, "Could not locate passwordFile " + passwordFile)
        if not os.path.exists(certPath):
            return (False, "Could not locate cert file " + certPath)
        cert = loadCertFromFile(certPath)
        ledgerPassword = getpass.getpass("Enter bank password:")
        enableSecurityLogging(bankPath)
        logSecure("Security Logging Enabled, creating bank server from path %s" % bankPath)
        bank = Ledger(bankPath, cert, ledgerPassword)
        self.bankServer = PlaygroundOnlineBank(passwordFile, bank)
        if len(serverArgs) == 4:
            mintCertFile = serverArgs[3]
            result = bank.registerMintCert(mintCertFile)
            if not result.succeeded():
                print("Could not load certificate", result.msg())

        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        coro = playground.getConnector(stack).create_playground_server(self.bankServer.buildProtocol, BANK_FIXED_PLAYGROUND_PORT)
        server = loop.run_until_complete(coro)
        print("Bank Server Started at {}".format(server.sockets[0].gethostname()))
        print("To access start a bank client protocol to %s:%s" % (BANK_FIXED_PLAYGROUND_ADDR,BANK_FIXED_PLAYGROUND_PORT)) # TODO: change address to display the correct host Playground address
        loop.run_forever()
        loop.close()
        return (True,"")
    
    def processClient(self, clientArgs):
        self.__mode = "client"
        if len(clientArgs) == 4:
            stack, remoteAddress, certPath, loginName= clientArgs[0:4]
        else:
            return (False, "Bank client CLI requires remote, address, certPath, and user loginName")
        if not os.path.exists(certPath):
            return (False, "Could not locate cert file " + certPath)

        # remove this to accept the provided address instead
        # remoteAddress = BANK_FIXED_PLAYGROUND_ADDR

        cert = loadCertFromFile(certPath)
        passwd = getpass.getpass("Enter bank account password for %s: "%loginName)

        clientFactory = PlaygroundOnlineBankClient(cert, loginName, passwd)
        clientFactory.stack = stack # UGLY HACK TO FIX LATER

        loop = asyncio.get_event_loop()

        def initShell():
            uiFactory = AdminBankCLIClient(None, clientFactory, remoteAddress)
            uiFactory.registerExitListener(lambda reason: loop.call_later(2.0, loop.stop))
            a = CLIShell.AdvancedStdio(uiFactory)

        # loop.set_debug(enabled=True)
        loop.call_soon(initShell)
        loop.run_forever()
        return (True, "")
    
    def getStdioProtocol(self):
        return self.__stdioUI
    
    def start(self, args):
        if len(args) == 0 or args[0] not in ['server', 'client']:
            return (False, "OnlineBank requires either 'server' or 'client' not %s" % args[0])
        if args[0] == 'server':
            return self.processServer(args[1:])
        if args[0] == 'client':
            return self.processClient(args[1:])
        return (False, "Internal inconsistency. Should not get here")
    
    def stop(self):
        # not yet implemented
        return (True,"")
    
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
            print("File %s not found. Creating a new DB..." % self.__filename)
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
            return access.get(accountName, {})
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

def main(args):
    if len(args) < 2 or args[1] in ["help","--help","-h"]:
        sys.exit(USAGE)
    if args[1] == "pw":
        if len(args) < 4:
            sys.exit(USAGE)
        pwfile, cmd = args[2:4]
        pwDB = PasswordData(pwfile)
        if cmd == "user":
            if len(args) != 6:
                sys.exit(USAGE)
            subcmd, userName = args[4:6]
            if subcmd == "add":
                if pwDB.hasUser(userName):
                    sys.exit("User %s already exists" % userName)
                newPw = getPasswordHashRoutine()
                pwDB.createUser(userName, newPw, modify=False)
            elif subcmd == "del":
                if not pwDB.hasUser(userName):
                    sys.exit("No such user login name: " + userName)
                pwDB.removeUser(userName)
            elif subcmd == "change":
                if not pwDB.hasUser(userName):
                    sys.exit("User %s does not already exist" % userName)
                oldPwHash = pwDB.currentUserPassword(userName)
                newPw = getPasswordHashRoutine(oldPwHash)
                pwDB.createUser(userName, newPw, modify=True)
            else:
                sys.exit(USAGE)
        elif cmd == "account":
            if len(args) != 6:
                sys.exit(USAGE)
            subcmd, accountName = args[4:6]
            if subcmd == "add":
                if pwDB.hasAccount(accountName):
                    sys.exit("Account %s already exists" % accountName)
                pwDB.createAccount(accountName)
            else:
                sys.exit(USAGE)
        elif cmd == "chmod":
            if len(args) == 5:
                userName = args[4]
                accountName, accessString = None, None
            elif len(args) == 6:
                userName, accountName = args[4:6]
                accessString = None
            elif len(args) == 7:
                userName, accountName, accessString = args[4:7]
            else:
                sys.exit(USAGE)
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
        pwDB.sync()
        sys.exit("Finished.")

    elif args[1] == "verify_receipt":
        certfile, receipt, receiptSig = args[2:5]
        cert = loadCertFromFile(certfile)
        verifier = RSA_SIGNATURE_MAC(cert.public_key())
        with open(receipt,"rb") as f:
            receiptData = f.read()
        with open(receiptSig,"rb") as f:
            receiptSigData = f.read()
        print("Verification result = ",
              verifier.verify(receiptData, receiptSigData))

    elif args[1] == "server":
        control = PlaygroundNodeControl()
        args = args[1:]
        success, reason = control.start(args)
        if not success:
            print(reason)

    elif args[1] == "client":
        control = PlaygroundNodeControl()
        args = args[1:]
        success, reason = control.start(args)
        if not success:
            print(reason)

    else:
        sys.exit(USAGE)

if __name__ == "__main__":
    main(args=sys.argv)
