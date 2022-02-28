#!/usr/bin/python3

import argparse
import csv
import ctypes
import fnmatch
import logging
import sys
import os
import json
import sqlite3
import ctypes
import re
import itertools
import requests
import lz4.block as lz4
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import matplotlib.dates as mdates
import xml.etree.cElementTree as ET
from urllib import parse
from asn1crypto import pem, x509
from base64 import b64decode, b64encode
from datetime import datetime


class Addon:
    """
    Stores data relating to a Firefox addon.
    """

    def __init__(
        self,
        name,
        version,
        URL,
        storeURL,
        downloads,
        screenshots,
        rating,
    ):
        """
        Parameters
        ----------
        name : str
        Name of the addon.

        version : float
        Version number for the addon.

        url : str
        URL where the addon can be downloaded.

        storeURL : str
        URL of the store page for the addon.

        downloads : int
        Number of weekly downloads of the addon.

        screenshots : [str]
        List of URLs to screenshots of the addon.

        rating : float
        Average rating of the addon.
        """
        self.name = name
        self.version = version
        self.URL = URL
        self.storeURL = storeURL
        self.downloads = downloads
        self.screenshots = screenshots
        self.rating = rating


class Extension:
    """
    Stores data relating to a Firefox extension.
    """

    def __init__(
        self,
        name,
        URL,
        permissions,
    ):
        """
        Parameters
        ----------
        name : str
        Name of the extension.

        url : str
        URL where the extension can be downloaded.

        permissions : [str]
        List of user-granted permissions the extension holds.
        """
        self.name = name
        self.URL = URL
        self.permissions = permissions


class Certificate:
    """
    Stores data relating to a trusted imported X509 certificate.
    """

    def __init__(
        self,
        version,
        serial,
        hashAlgo,
        issuer,
        validFrom,
        validUntil,
        subject,
        subjectKeyAlgorithm,
        subjectKeyBitSize,
        extensions,
        cert,
    ):
        """
        Parameters
        ----------
        version : int
        Version number.

        serial : str
        Serial number.

        hashAlgo : str
        Hashing algorithm used for certificate.

        issuer : str
        Issuing authority.

        validFrom : str (date)
        Date certificate is valid from.

        validUntil : str (date)
        Date certificate is valid until.

        subject : str
        Certificate subject.

        subjectKeyAlgorithm : str
        Public key algorithm.

        subjectKeyBitSize : int
        Public key bit size.

        extensions : [str]
        X509 extensions related to certificate.

        cert : bytes
        The certificate.
        """
        self.version = version
        self.serial = serial
        self.hashAlgo = hashAlgo
        self.issuer = issuer
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.subject = subject
        self.subjectKeyAlgorithm = subjectKeyAlgorithm
        self.subjectKeyBitSize = subjectKeyBitSize
        self.extensions = extensions
        self.cert = cert

        self.calculateCertificatePath()

    def calculateCertificatePath(self):
        self.path = "certificates/{}-{}.pem".format(
            self.subject.split(": ")[1].split(",")[0].replace(" ", "-"), self.serial
        )


class Cookie:
    """
    Stores data relating to a Firefox cookie.
    """

    def __init__(
        self,
        host,
        name,
        value,
        expiry,
        lastAccessed,
        creationTime,
        secure,
        httpOnly,
        sameSite,
    ):
        """
        Parameters
        ----------
        host : str
        Site on which cookie is valid.

        name : str
        Cookie name.

        value : str
        Data stored in cookie.

        expiry : str (date)
        Date and time describing the expiry of the cookie.

        lastAccessed : str (date)
        Date and time describing when the cookie was last accessed.

        creationTime : str (date)
        Date and time describing when the cookie was created.

        secure : bool
        Set if 'Secure' flag is on cookie.

        httpOnly : bool
        Set if 'HTTPOnly' flag is on cookie.

        sameSite : bool
        Set if 'SameSite' flag is on cookie.
        """
        self.host = host
        self.name = name
        self.value = value
        self.expiry = expiry
        self.lastAccessed = lastAccessed
        self.creationTime = creationTime
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite


class FormField:
    """
    Stores data relating to an autocomplete item remembered from a HTTP form.
    """

    def __init__(
        self,
        name,
        value,
        useCount,
    ):
        """
        Parameters
        ----------
        name : str
        Name of the HTTP field.

        value : str
        The autocomplete value stored for the specified field.

        useCount : int
        Number of times user has entered the item into the field.
        """
        self.name = name
        self.value = value
        self.useCount = useCount


class HistorySearch:
    """
    Stores data relating to a browsing history search.
    """

    def __init__(
        self,
        query,
        useFrequency,
    ):
        """
        Parameters
        ----------
        query : str
        The query string to search for within browsing history.

        useFrequency : str
        The frequency that the user has searched for this query in browsing history.
        """
        self.query = query
        self.useFrequency = useFrequency


class Download:
    """
    Stores data relating to a download within Firefox.
    """

    def __init__(
        self,
        date,
        downloadPath,
        URL,
    ):
        """
        Parameters
        ----------
        date : str (date)
        Date of download.

        downloadPath : str
        Chosen download path for the file.

        URL : str
        URL that the file is retrieved from.
        """
        self.date = date
        self.downloadPath = downloadPath
        self.URL = URL


class Browse:
    """
    Stores data relating to a browsing history item.
    """

    def __init__(
        self,
        date,
        URL,
        title,
        visitType,
        visitCount,
    ):
        """
        Parameters
        ----------
        date : str (date)
        Date of browse to site.

        URL : str
        URL the user browsed to.

        title : str
        Title of the page user browsed to.

        visitType : int
        How the user accessed the page:
            1: User followed a link
            2: User typed URL
            3: User followed a bookmark
            4: Loaded from Iframe
            5: Loaded via HTTP redirect 301
            6: Loaded via HTTP redirect 302
            7: Loaded via a Download
            8: User followed a link inside an Iframe
            9: Page was reloaded

        visitCount : int
        Number of times the user browsed to the page in this visitType manner.
        """
        self.date = date
        self.URL = URL
        self.title = title
        self.visitType = visitType
        self.visitCount = visitCount


class Bookmark:
    """
    Stores data relating to a Firefox bookmark.
    """

    def __init__(
        self,
        dateAdded,
        URL,
        title,
        active,
    ):
        """
        Parameters
        ----------
        dateAdded : str (date)
        Date bookmark was added.

        URL : str
        URL to the bookmarked page.

        title : str
        Title of the bookmarked page.

        active : bool
        Set if the page is actively bookmarked. Unset if bookmark has been deleted.
        """
        self.dateAdded = dateAdded
        self.URL = URL
        self.title = title
        self.active = active


class LoginDecrypter:
    """
    Acts as a proxy for the NSS library to decrypt Firefox logins.
    """

    class SECItem(ctypes.Structure):
        """
        Structure representing SECItem type for NSS decryption
        """

        _fields_ = [
            ("type", ctypes.c_uint),
            ("data", ctypes.c_char_p),
            ("len", ctypes.c_uint),
        ]

    class PK11SlotInfo(ctypes.Structure):
        """
        Structure representing a PKCS slot
        """

    def __init__(self):
        # Load the LibNSS library.
        self.NSS = None
        self._decryptionAvailable = True
        self.loadLibNSS()

        # Create the pointers to required structures.
        pointerSlot = ctypes.POINTER(self.PK11SlotInfo)
        pointerSECItem = ctypes.POINTER(self.SECItem)

        # Set input and output types for LibNSS C functions so automatic type casting happens.
        self.setCTypes("NSS_Init", ctypes.c_int, ctypes.c_char_p)
        self.setCTypes("NSS_Shutdown", ctypes.c_int)
        self.setCTypes("PK11_GetInternalKeySlot", pointerSlot)
        self.setCTypes("PK11_FreeSlot", None, pointerSlot)
        self.setCTypes(
            "PK11_CheckUserPassword", ctypes.c_int, pointerSlot, ctypes.c_char_p
        )
        self.setCTypes(
            "PK11SDR_Decrypt",
            ctypes.c_int,
            pointerSECItem,
            pointerSECItem,
            ctypes.c_void_p,
        )
        self.setCTypes("SECITEM_ZfreeItem", None, pointerSECItem, ctypes.c_int)

    def setDecryptionStatus(self, status):
        """Sets the decryptionAvailiable attribute to the status argument."""
        self._decryptionAvailable = status

    def getDecryptionStatus(self):
        """Returns the decryptionAvailable attribute of the LoginDecrypter."""
        return self._decryptionAvailable

    def setCTypes(self, name, returnType, *inputTypes):
        """
        Sets the input and output types for NSS functions.

        Parameters
        ----------
        name : str
        Name of the function.

        returnType : ctype
        Return value type of the function.

        *inputTypes : ctype
        Argument types of the function.
        """
        # Set the input/output types for NSS functions.
        result = getattr(self.NSS, name)
        result.restype = returnType
        result.argtypes = inputTypes
        setattr(self, name, result)

    def loadLibNSS(self):
        """Searches for the LibNSS library on the user's system, and loads it into memory."""
        # Search for LibNSS on the system.
        nssLibraryName = "libnss3.so"
        locations = (
            "",
            "/usr/lib",
            "/usr/lib/nss",
            "/usr/lib64",
            "/usr/lib64/nss",
            "/usr/local/lib",
            "/usr/local/lib/nss",
            "/opt/local/lib",
            "/opt/local/lib/nss",
        )
        for location in locations:
            nssPath = os.path.join(location, nssLibraryName)
            # Attempt to load LibNSS.
            try:
                nss: ctypes.CDLL = ctypes.CDLL(nssPath)
            except OSError:
                continue
            else:
                self.NSS = nss

        # Set decryptionAvailable to False if NSS library is not on the system.
        if self.NSS == None:
            logging.error("[!] Couldn't find NSS Library on System. Exiting...")
            self._decryptionAvailable = False

    def decode(self, base64Data):
        """
        Attempts to decode NSS encrypted input data.

        Parameters
        ----------
        base64Data : str
        Data to decrypt, encoded in Base64.

        Return Values
        -------------
        decryptedData : str/None
        Successfully decrypted data, or None.
        """
        if self._decryptionAvailable:
            # Base64 decode the password.
            decodedData = b64decode(base64Data)

            # Create the structures for encryption and decryption.
            encryptedData = self.SECItem(0, decodedData, len(decodedData))
            decryptedData = self.SECItem(0, None, 0)

            # Decrypt the data, and check whether it succeeded.
            errorCode = self.PK11SDR_Decrypt(encryptedData, decryptedData, None)
            try:
                if errorCode == -1:
                    logging.error(
                        "[!] Password decryption failed. Passwords protected by a Master Password!"
                    )
                    sys.exit(1)

                finalData = ctypes.string_at(
                    decryptedData.data, decryptedData.len
                ).decode("utf-8")

            finally:
                # Free the decryption object.
                self.SECITEM_ZfreeItem(decryptedData, 0)

            return finalData

        # Return none if decryption not available.
        else:
            return None


class LoginData:
    """
    Stores and decrypts Firefox logins at mass.
    """

    def __init__(self, profile):
        """
        Parameters
        ----------
        profile : str
        Path to the Firefox profile.
        """
        self.logins = []
        self.profile = profile

        # Create the NSS decrypter.
        self.decrypter = LoginDecrypter()

    def initialiseProfile(self):
        """Initialises the NSS decrypter with the specified user profile."""
        # UTF-8 encode the firefox profile folder in case of foreign characters.
        profile = self.profile.encode("utf-8")

        # Initialise NSS with the profile.
        errorCode = self.decrypter.NSS_Init(b"sql:" + profile)

        # Check for error on initialisation.
        if errorCode != 0:
            logging.error("[!] Couldn't Initialise NSS Profile...")
            self.decrypter.setDecryptionStatus(False)

    def attemptBlankAuthentication(self):
        """
        Attempt to decrypt the 'password_check' value with a blank password.

        Return Values
        -------------
        status : bool
        Set if blank password authentication succeeded. Unset if master password is needed.
        """
        # Get a keyslot from the decrypter and call the CheckUserPassword function with a blank password.
        keySlot = self.decrypter.PK11_GetInternalKeySlot()

        if not keySlot:
            logging.error("[!] Couldn't retrieve keyslot...")
            return None

        errorCode = self.decrypter.PK11_CheckUserPassword(keySlot, "".encode("utf-8"))

        # Check the result of authentication and return as necessary.
        if errorCode != 0:
            self.decrypter.PK11_FreeSlot(keySlot)
            return False
        else:
            self.decrypter.PK11_FreeSlot(keySlot)
            return True

    def attemptPasswordAuthentication(self, password):
        """
        Attempt to decrypt the 'password_check' value with a known specified password.

        Parameters
        ----------
        password : str
        The password to check.

        Return Values
        -------------
        status : bool
        Set if password authentication succeeded. Unset if master password is not the password entered.
        """
        # Get a keyslot from the decrypter and call the CheckUserPassword function with a blank password.
        keySlot = self.decrypter.PK11_GetInternalKeySlot()

        if not keySlot:
            logging.error("[!] Couldn't retrieve keyslot...")
            return None

        errorCode = self.decrypter.PK11_CheckUserPassword(
            keySlot, password.encode("utf-8")
        )

        # Check the result of authentication and return as necessary.
        if errorCode != 0:
            self.decrypter.PK11_FreeSlot(keySlot)
            return False
        else:
            self.decrypter.PK11_FreeSlot(keySlot)
            return True

    def attemptBruteForceAuthentication(self, wordlist):
        """
        Attempt to decrypt the 'password_check' value via a dictionary (wordlist attack).

        Parameters
        ----------
        wordlist : str
        Path to a dictionary/wordlist.

        Return Values
        -------------
        password : str/None
        The yielded password, or None if correct password is not in dictionary.

        error : bool
        True if error occurred when gathering keyslot.
        """
        # Open the wordlist and go through line by line.
        with open(wordlist) as wordlistFile:
            for line in wordlistFile:
                guess = line.rstrip()

                # Skip comments or blank lines.
                if guess == "" or guess[0] == "#":
                    continue

                # Obtain a keyslot and attempt to check the password.
                keySlot = self.decrypter.PK11_GetInternalKeySlot()

                if not keySlot:
                    logging.error("[!] Couldn't retrieve keyslot...")
                    return True

                errorCode = self.decrypter.PK11_CheckUserPassword(
                    keySlot, guess.encode("utf-8")
                )

                # If the error code is zero, password authentication has succeeded, return the current guess.
                if errorCode == 0:
                    return guess

        # If correct password is not in wordlist, return None.
        return None

    def authenticate(self, correctPassword):
        """
        Authenticate to NSS with the correct password for the profile.

        Parameters
        ----------
        correctPassword : str
        The correct password to unlock the profile.

        Return Values
        -------------
        authenticated : bool
        True if authentication successful.
        """

        # Create a keyslot
        keySlot = self.decrypter.PK11_GetInternalKeySlot()

        if not keySlot:
            logging.error("[!] Couldn't retrieve keyslot...")
            return False

        # Authenticate to the NSS library using the correct password.
        errorCode = self.decrypter.PK11_CheckUserPassword(
            keySlot, correctPassword.encode("utf-8")
        )

        # Free the keyslot once finished.
        self.decrypter.PK11_FreeSlot(keySlot)

        return True

    def decryptLogins(self):
        """Decrypt all logins using the authenticated NSS decrypter."""
        for login in self.logins:
            # Set the decrypted usernames and passwords in the login objects.
            login.username = self.decrypter.decode(login.encryptedUsername)
            login.password = self.decrypter.decode(login.encryptedPassword)

    def deactivateProfile(self):
        """Deactivate the NSS profile and library once finished."""
        _ = self.decrypter.NSS_Shutdown()


class Login:
    """
    Stores data relating to a saved login.
    """

    def __init__(
        self,
        host,
        encryptedUsername,
        encryptedPassword,
    ):
        """
        Parameters
        ----------
        host : str
        Host that login applies to.

        encryptedUsername : str
        Encrypted login username.

        encryptedPassword : str
        Encrrypted login password.
        """
        self.host = host
        self.encryptedUsername = encryptedUsername
        self.encryptedPassword = encryptedPassword
        # Set the decrypted usernames and passwords to none until decrypted.
        self.username = None
        self.password = None


class FoxHunter:
    """
    Allows analysis of collected Firefox data.
    """

    def __init__(
        self,
        addons,
        extensions,
        certificates,
        cookies,
        formHistory,
        historySearches,
        downloadHistory,
        browsingHistory,
        bookmarks,
        logins,
    ):
        """
        Parameters
        ----------
        addons : [Addon]
        List of installed addons.

        extensions : [Extension]
        List of installed extensions.

        certificates : [Certificate]
        List of installed certificates.

        cookies : [Cookie]
        List of stored cookies.

        formHistory : [FormField]
        List of autocomplete form history fields.

        historySearches : [HistorySearch]
        List of history searches.

        downloadHistory : [Download]
        List of downloads.

        browsingHistory : [Browse]
        List of browsing history items.

        bookmarks : [Bookmark]
        List of bookmarks.

        logins : [Login]
        List of logins.
        """

        self.addons = addons
        self.extensions = extensions
        self.certificates = certificates
        self.cookies = cookies
        self.formHistory = formHistory
        self.historySearches = historySearches
        self.downloadHistory = downloadHistory
        self.browsingHistory = browsingHistory
        self.bookmarks = bookmarks
        self.logins = logins

        # Set the available items.
        arguments = locals()
        self.available = [
            [attribute, value]
            for attribute, value in arguments.items()
            if value != [] and attribute != "self"
        ]

        self.analysedAvailable = []
        self.generatedGraphs = []
        self.diagramDirectories = []

    def findAvailable(self):
        """Returns the list of set attributes."""
        return self.available

    def findAnalysedAvailable(self):
        """Returns the list of set analysed extensions."""
        return self.analysedAvailable

    def convertedVersion(self, version):
        """Converts a version to tuple."""
        return tuple(map(int, (version.split("."))))

    def analyseAddons(self):
        """
        Performs analysis on gathered addons.

        1. Finds addons not installed through Mozilla store.
        2. Finds addons with low download rates and/or ratings.
        3. Finds out-of-date addons - potential security risks.
        """

        self.analysedAddons = {
            "Non Mozilla Install": [],
            "Low User Ratings": [],
            "Out Of Date": [],
        }

        internetCheck = True
        for addon in self.addons:
            # Check for addons not installed through Mozilla.
            if addon.URL != None:
                if "addons.mozilla" not in addon.URL:
                    self.analysedAddons["Non Mozilla Install"].append(addon)

            # Check for addons with low download rates/ratings.
            if addon.rating < 2.5 or addon.downloads < 1000:
                self.analysedAddons["Low User Ratings"].append(addon)

            # Check for out of date addons.
            try:
                if internetCheck:
                    html = requests.get(addon.storeURL).text
                    storeVersion = re.findall(r"\"version\":\"([0-9,.]*)", html)[0]
                    if self.convertedVersion(addon.version) < self.convertedVersion(
                        storeVersion
                    ):
                        self.analysedAddons["Out Of Date"].append(addon)
            except:
                logging.error(
                    "[!] No Internet Connection. Skipping Addon Version Checks..."
                )
                internetCheck = False

        self.analysedAvailable.append(["analysedAddons", self.analysedAddons])

    def analyseExtensions(self):
        """
        Performs analysis on gathered extensions.

        1. Finds extensions not installed through Mozilla store.
        2. Finds extensions with dangerous/abnormal permissions.
        """

        # Define interesting permissions
        self.analysedExtensions = {"Non Mozilla Install": [], "Interesting Permissions": []}
        permissions = [
            "background",
            "browserSettings",
            "cookies",
            "geolocation",
            "pageCapture",
            "downloads.open",
            "geolocation",
            "pageCapture",
            "privacy",
            "proxy",
        ]

        
        for extension in self.extensions:
            # Identify non mozilla installs.
            if extension.URL != None:
                if all([substring not in extension.URL for substring in ["addons.mozilla", "addons.cdn.mozilla"]]):
                    self.analysedExtensions["Non Mozilla Install"].append(extension)

            # Identify extensions with said permissions and mark them.
            for permission in permissions:
                if permission in extension.permissions:
                    self.analysedExtensions["Interesting Permissions"].append(extension)
                    break

        self.analysedAvailable.append(["analysedExtensions", self.analysedExtensions])

    def analyseCertificates(self):
        """
        Performs analysis on gathered certificates.

        1. Finds certificates from relatively unknown issuers.
        2. Finds certificates with weak encryption standards.
        """

        self.analysedCertificates = {"Uncommon Issuer": [], "Weak Encryption": []}

        # Define common issuers.
        commonIssuers = [
            "CN=ACCVRAIZ1,OU=PKIACCV,O=ACCV,C=ES",
            "OU=AC RAIZ FNMT-RCM,O=FNMT-RCM,C=ES",
            "CN=Actalis Authentication Root CA,O=Actalis S.p.A./03358520967,L=Milan,C=IT",
            "CN=AffirmTrust Commercial,O=AffirmTrust,C=US",
            "CN=AffirmTrust Networking,O=AffirmTrust,C=US",
            "CN=AffirmTrust Premium,O=AffirmTrust,C=US",
            "CN=AffirmTrust Premium ECC,O=AffirmTrust,C=US",
            "CN=Amazon Root CA 1,O=Amazon,C=US",
            "CN=Amazon Root CA 2,O=Amazon,C=US",
            "CN=Amazon Root CA 3,O=Amazon,C=US",
            "CN=Amazon Root CA 4,O=Amazon,C=US",
            "CN=Atos TrustedRoot 2011,O=Atos,C=DE",
            "CN=Autoridad de Certificacion Firmaprofesional CIF A62634068,C=ES",
            "CN=Baltimore CyberTrust Root,OU=CyberTrust,O=Baltimore,C=IE",
            "CN=Buypass Class 2 Root CA,O=Buypass AS-983163327,C=NO",
            "CN=Buypass Class 3 Root CA,O=Buypass AS-983163327,C=NO",
            "CN=CA Disig Root R2,O=Disig a.s.,L=Bratislava,C=SK",
            "CN=CFCA EV ROOT,O=China Financial Certification Authority,C=CN",
            "CN=COMODO Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB",
            "CN=COMODO ECC Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB",
            "CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB",
            "CN=Chambers of Commerce Root,OU=http://www.chambersign.org,O=AC Camerfirma SA CIF A82743287,C=EU",
            "CN=Global Chambersign Root,OU=http://www.chambersign.org,O=AC Camerfirma SA CIF A82743287,C=EU",
            "CN=Certigna,O=Dhimyotis,C=FR",
            "CN=Certigna Root CA,OU=0002 48146308100036,O=Dhimyotis,C=FR",
            "CN=Certum CA,O=Unizeto Sp. z o.o.,C=PL",
            "CN=Certum Trusted Network CA,OU=Certum Certification Authority,O=Unizeto Technologies S.A.,C=PL",
            "CN=Certum Trusted Network CA 2,OU=Certum Certification Authority,O=Unizeto Technologies S.A.,C=PL",
            "CN=Chambers of Commerce Root - 2008,O=AC Camerfirma S.A.,serialNumber=A82743287,L=Madrid (see current address at www.camerfirma.com/address),C=EU",
            "CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB",
            "CN=Cybertrust Global Root,O=Cybertrust\, Inc",
            "CN=D-TRUST Root CA 3 2013,O=D-Trust GmbH,C=DE",
            "CN=D-TRUST Root Class 3 CA 2 2009,O=D-Trust GmbH,C=DE",
            "CN=D-TRUST Root Class 3 CA 2 EV 2009,O=D-Trust GmbH,C=DE",
            "CN=DST Root CA X3,O=Digital Signature Trust Co.",
            "CN=DigiCert Assured ID Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Assured ID Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Assured ID Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US",
            "CN=E-Tugra Certification Authority,OU=E-Tugra Sertifikasyon Merkezi,O=E-Tu\C4\9Fra EBG Bili\C5\9Fim Teknolojileri ve Hizmetleri A.\C5\9E.,L=Ankara,C=TR",
            "CN=EC-ACC,OU=Jerarquia Entitats de Certificacio Catalanes,OU=Vegeu https://www.catcert.net/verarrel (c)03,OU=Serveis Publics de Certificacio,O=Agencia Catalana de Certificacio (NIF Q-0801176-I),C=ES",
            "emailAddress=pki@sk.ee,CN=EE Certification Centre Root CA,O=AS Sertifitseerimiskeskus,C=EE",
            "CN=Entrust.net Certification Authority (2048),OU=(c) 1999 Entrust.net Limited,OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.),O=Entrust.net",
            "CN=Entrust Root Certification Authority,OU=(c) 2006 Entrust\, Inc.,OU=www.entrust.net/CPS is incorporated by reference,O=Entrust\, Inc.,C=US",
            "CN=Entrust Root Certification Authority - EC1,OU=(c) 2012 Entrust\, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust\, Inc.,C=US",
            "CN=Entrust Root Certification Authority - G2,OU=(c) 2009 Entrust\, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust\, Inc.,C=US",
            "CN=Entrust Root Certification Authority - G4,OU=(c) 2015 Entrust\, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust\, Inc.,C=US",
            "emailAddress=info@diginotar.nl,CN=DigiNotar Root CA,O=DigiNotar,C=NL",
            "CN=DigiNotar PKIoverheid CA Organisatie - G2,O=DigiNotar B.V.,C=NL",
            "CN=GDCA TrustAUTH R5 ROOT,O=GUANG DONG CERTIFICATE AUTHORITY CO.\,LTD.,C=CN",
            "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
            "CN=GTS Root R2,O=Google Trust Services LLC,C=US",
            "CN=GTS Root R3,O=Google Trust Services LLC,C=US",
            "CN=GTS Root R4,O=Google Trust Services LLC,C=US",
            "CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US",
            "CN=GeoTrust Primary Certification Authority,O=GeoTrust Inc.,C=US",
            "CN=GeoTrust Primary Certification Authority - G2,OU=(c) 2007 GeoTrust Inc. - For authorized use only,O=GeoTrust Inc.,C=US",
            "CN=GeoTrust Primary Certification Authority - G3,OU=(c) 2008 GeoTrust Inc. - For authorized use only,O=GeoTrust Inc.,C=US",
            "CN=GeoTrust Universal CA,O=GeoTrust Inc.,C=US",
            "CN=GeoTrust Universal CA 2,O=GeoTrust Inc.,C=US",
            "CN=GlobalSign,O=GlobalSign,OU=GlobalSign ECC Root CA - R4",
            "CN=GlobalSign,O=GlobalSign,OU=GlobalSign ECC Root CA - R5",
            "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE",
            "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R2",
            "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R3",
            "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R6",
            "CN=Global Chambersign Root - 2008,O=AC Camerfirma S.A.,serialNumber=A82743287,L=Madrid (see current address at www.camerfirma.com/address),C=EU",
            "OU=Go Daddy Class 2 Certification Authority,O=The Go Daddy Group\, Inc.,C=US",
            "CN=Go Daddy Root Certificate Authority - G2,O=GoDaddy.com\, Inc.,L=Scottsdale,ST=Arizona,C=US",
            "CN=Hellenic Academic and Research Institutions ECC RootCA 2015,O=Hellenic Academic and Research Institutions Cert. Authority,L=Athens,C=GR",
            "CN=Hellenic Academic and Research Institutions RootCA 2011,O=Hellenic Academic and Research Institutions Cert. Authority,C=GR",
            "CN=Hellenic Academic and Research Institutions RootCA 2015,O=Hellenic Academic and Research Institutions Cert. Authority,L=Athens,C=GR",
            "CN=Hongkong Post Root CA 1,O=Hongkong Post,C=HK",
            "CN=Hongkong Post Root CA 3,O=Hongkong Post,L=Hong Kong,ST=Hong Kong,C=HK",
            "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
            "CN=ISRG Root X2,O=Internet Security Research Group,C=US",
            "CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US",
            "CN=IdenTrust Public Sector Root CA 1,O=IdenTrust,C=US",
            "CN=Izenpe.com,O=IZENPE S.A.,C=ES",
            "CN=LuxTrust Global Root 2,O=LuxTrust S.A.,C=LU",
            "emailAddress=info@e-szigno.hu,CN=Microsec e-Szigno Root CA 2009,O=Microsec Ltd.,L=Budapest,C=HU",
            "CN=NetLock Arany (Class Gold) F\C5\91tan\C3\BAs\C3\ADtv\C3\A1ny,OU=Tan\C3\BAs\C3\ADtv\C3\A1nykiad\C3\B3k (Certification Services),O=NetLock Kft.,L=Budapest,C=HU",
            "CN=Network Solutions Certificate Authority,O=Network Solutions L.L.C.,C=US",
            "CN=OISTE WISeKey Global Root GA CA,OU=OISTE Foundation Endorsed,OU=Copyright (c) 2005,O=WISeKey,C=CH",
            "CN=OISTE WISeKey Global Root GB CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH",
            "CN=OISTE WISeKey Global Root GC CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH",
            "CN=QuoVadis Root Certification Authority,OU=Root Certification Authority,O=QuoVadis Limited,C=BM",
            "CN=QuoVadis Root CA 1 G3,O=QuoVadis Limited,C=BM",
            "CN=QuoVadis Root CA 2,O=QuoVadis Limited,C=BM",
            "CN=QuoVadis Root CA 2 G3,O=QuoVadis Limited,C=BM",
            "CN=QuoVadis Root CA 3,O=QuoVadis Limited,C=BM",
            "CN=QuoVadis Root CA 3 G3,O=QuoVadis Limited,C=BM",
            "CN=SSL.com EV Root Certification Authority ECC,O=SSL Corporation,L=Houston,ST=Texas,C=US",
            "CN=SSL.com EV Root Certification Authority RSA R2,O=SSL Corporation,L=Houston,ST=Texas,C=US",
            "CN=SSL.com Root Certification Authority ECC,O=SSL Corporation,L=Houston,ST=Texas,C=US",
            "CN=SSL.com Root Certification Authority RSA,O=SSL Corporation,L=Houston,ST=Texas,C=US",
            "CN=SZAFIR ROOT CA2,O=Krajowa Izba Rozliczeniowa S.A.,C=PL",
            "CN=SecureSign RootCA11,O=Japan Certification Services\, Inc.,C=JP",
            "CN=SecureTrust CA,O=SecureTrust Corporation,C=US",
            "CN=Secure Global CA,O=SecureTrust Corporation,C=US",
            "OU=Security Communication RootCA2,O=SECOM Trust Systems CO.\,LTD.,C=JP",
            "OU=Security Communication RootCA1,O=SECOM Trust.net,C=JP",
            "CN=Sonera Class2 CA,O=Sonera,C=FI",
            "CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL",
            "CN=Staat der Nederlanden Root CA - G3,O=Staat der Nederlanden,C=NL",
            "OU=Starfield Class 2 Certification Authority,O=Starfield Technologies\, Inc.,C=US",
            "CN=Starfield Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US",
            "CN=Starfield Services Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US",
            "CN=SwissSign Gold CA - G2,O=SwissSign AG,C=CH",
            "CN=SwissSign Platinum CA - G2,O=SwissSign AG,C=CH",
            "CN=SwissSign Silver CA - G2,O=SwissSign AG,C=CH",
            "CN=Symantec Class 1 Public Primary Certification Authority - G4,OU=Symantec Trust Network,O=Symantec Corporation,C=US",
            "CN=Symantec Class 1 Public Primary Certification Authority - G6,OU=Symantec Trust Network,O=Symantec Corporation,C=US",
            "CN=Symantec Class 2 Public Primary Certification Authority - G4,OU=Symantec Trust Network,O=Symantec Corporation,C=US",
            "CN=Symantec Class 2 Public Primary Certification Authority - G6,OU=Symantec Trust Network,O=Symantec Corporation,C=US",
            "CN=T-TeleSec GlobalRoot Class 2,OU=T-Systems Trust Center,O=T-Systems Enterprise Services GmbH,C=DE",
            "CN=T-TeleSec GlobalRoot Class 3,OU=T-Systems Trust Center,O=T-Systems Enterprise Services GmbH,C=DE",
            "CN=TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1,OU=Kamu Sertifikasyon Merkezi - Kamu SM,O=Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK,L=Gebze - Kocaeli,C=TR",
            "CN=TWCA Global Root CA,OU=Root CA,O=TAIWAN-CA,C=TW",
            "CN=TWCA Root Certification Authority,OU=Root CA,O=TAIWAN-CA,C=TW",
            "O=Government Root Certification Authority,C=TW",
            "CN=TeliaSonera Root CA v1,O=TeliaSonera",
            "CN=TrustCor ECA-1,OU=TrustCor Certificate Authority,O=TrustCor Systems S. de R.L.,L=Panama City,ST=Panama,C=PA",
            "CN=TrustCor RootCert CA-1,OU=TrustCor Certificate Authority,O=TrustCor Systems S. de R.L.,L=Panama City,ST=Panama,C=PA",
            "CN=TrustCor RootCert CA-2,OU=TrustCor Certificate Authority,O=TrustCor Systems S. de R.L.,L=Panama City,ST=Panama,C=PA",
            "OU=Trustis FPS Root CA,O=Trustis Limited,C=GB",
            "CN=UCA Extended Validation Root,O=UniTrust,C=CN",
            "CN=UCA Global G2 Root,O=UniTrust,C=CN",
            "CN=USERTrust ECC Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US",
            "CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US",
            "CN=VeriSign Class 3 Public Primary Certification Authority - G4,OU=(c) 2007 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=VeriSign Class 3 Public Primary Certification Authority - G5,OU=(c) 2006 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=VeriSign Universal Root Certification Authority,OU=(c) 2008 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=VeriSign Class 1 Public Primary Certification Authority - G3,OU=(c) 1999 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=VeriSign Class 2 Public Primary Certification Authority - G3,OU=(c) 1999 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=VeriSign Class 3 Public Primary Certification Authority - G3,OU=(c) 1999 VeriSign\, Inc. - For authorized use only,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US",
            "CN=XRamp Global Certification Authority,O=XRamp Security Services Inc,OU=www.xrampsecurity.com,C=US",
            "OU=certSIGN ROOT CA,O=certSIGN,C=RO",
            "OU=ePKI Root Certification Authority,O=Chunghwa Telecom Co.\, Ltd.,C=TW",
            "CN=emSign ECC Root CA - C3,O=eMudhra Inc,OU=emSign PKI,C=US",
            "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
            "CN=emSign Root CA - C1,O=eMudhra Inc,OU=emSign PKI,C=US",
            "CN=emSign Root CA - G1,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
            "CN=thawte Primary Root CA,OU=(c) 2006 thawte\, Inc. - For authorized use only,OU=Certification Services Division,O=thawte\, Inc.,C=US",
            "CN=thawte Primary Root CA - G2,OU=(c) 2007 thawte\, Inc. - For authorized use only,O=thawte\, Inc.,C=US",
            "CN=thawte Primary Root CA - G3,OU=(c) 2008 thawte\, Inc. - For authorized use only,OU=Certification Services Division,O=thawte\, Inc.,C=US",
        ]

        # Define DN replacements to make.
        replacements = [
            ["Common Name: ", "CN="],
            ["Organizational Unit: ", "OU="],
            ["Organization: ", "O="],
            ["Locality: ", "L="],
            ["State: ", "ST="],
            ["Country: ", "C="],
        ]

        #  Identify unknown issuers.
        for certificate in self.certificates:
            # Make DN replacements where necessary.
            issuer = certificate.issuer
            for replacement in replacements:
                issuer = issuer.replace(replacement[0], replacement[1])
            issuer = issuer.replace(", ", ",")

            # Check if issuer is in common issuer list.
            if issuer not in commonIssuers:
                self.analysedCertificates["Uncommon Issuer"].append(certificate)

            # Check for RSA less than 2048.
            if (
                certificate.subjectKeyAlgorithm == "rsa"
                and certificate.subjectKeyBitSize < 2048
            ):
                self.analysedCertificates["Weak Encryption"].append(certificate)

            # Check for SHA1, MD5 or MD2 hashes.
            if certificate.hashAlgo in ["md2", "md5", "sha1"]:
                self.analysedCertificates["Weak Encryption"].append(certificate)

        self.analysedAvailable.append(
            ["analysedCertificates", self.analysedCertificates]
        )

    def analyseBookmarks(self):
        """
        Performs analysis on gathered bookmarks.

        1. Finds deleted bookmarks.
        """

        self.analysedBookmarks = {"Deleted": []}

        # Sort bookmarks according to date.
        self.bookmarks.sort(
            key=lambda x: datetime.strptime(x.dateAdded, "%Y-%m-%d %H:%M:%S")
        )

        # Identify deleted bookmarks
        for bookmark in self.bookmarks:
            if not bookmark.active:
                self.analysedBookmarks["Deleted"].append(bookmark)

        self.analysedAvailable.append(["analysedBookmarks", self.analysedBookmarks])

    def analyseDownloads(self):
        """
        Performs analysis on gathered downloads.

        1. Finds possible malware by file names.
        2. Categorises downloads by file type for further analysis.
        3. Finds websites that content is commonly downloaded from.
        4. Produces user download graphs.
        """

        self.analysedDownloads = {"Possible Malware": []}

        # Attempt to download the malware list
        try:
            response = requests.get("https://fsrm.experiant.ca/api/v1/combined")
            malwareList = json.loads(response.text)
            for filter in malwareList["filters"]:
                regex = r"^{}$".format(
                    filter.translate(
                        str.maketrans(
                            {
                                "[": "\[",
                                "]": "\]",
                                "+": "\+",
                                "?": "\?",
                                ".": "\.",
                                "*": ".*",
                            }
                        )
                    )
                )
                self.analysedDownloads["Possible Malware"] = self.analysedDownloads[
                    "Possible Malware"
                ] + [
                    x
                    for x in self.downloadHistory
                    if re.match(regex, os.path.basename(x.downloadPath))
                ]
        except:
            logging.error("[!] No Internet Connection. Skipping Malware Checks...")

        # Categorise downloads by file type.
        for download in self.downloadHistory:
            # Sort based on filetype.
            filename, file_extension = os.path.splitext(download.downloadPath)
            if file_extension != "":
                if file_extension in self.analysedDownloads:
                    self.analysedDownloads[file_extension].append(download)
                else:
                    self.analysedDownloads[file_extension] = [download]

        # Find websites that content is commonly downloaded from.
        commonWebsites = {}
        for download in self.downloadHistory:
            splitURL = parse.urlsplit(download.URL).netloc
            if splitURL in commonWebsites:
                commonWebsites[splitURL] += 1
            else:
                commonWebsites[splitURL] = 1

        sortedWebsites = list(commonWebsites.items())
        sortedWebsites = sorted(
            sorted(sortedWebsites, key=lambda x: x[1], reverse=True)[:10],
            key=lambda x: x[1],
            reverse=False,
        )

        # Plot the bar chart.
        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(
            [x[0] for x in sortedWebsites],
            [x[1] for x in sortedWebsites],
            color="dodgerblue",
        )
        ax.set(
            ylabel="Website",
            xlabel="Download Count",
            title="Top Ten Most Common Websites For Downloaded Files",
        )
        ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonDownloadSites.png"),
                dpi=400,
                bbox_inches="tight",
            )

        # Produce user download timelines.
        if len(self.downloadHistory) > 0:
            self.downloadHistory.sort(
                key=lambda x: datetime.strptime(x.date, "%Y-%m-%d %H:%M:%S")
            )
            timelineDuration = datetime.strptime(
                self.downloadHistory[-1].date, "%Y-%m-%d %H:%M:%S"
            ) - datetime.strptime(self.downloadHistory[0].date, "%Y-%m-%d %H:%M:%S")

            # If month time period or less.
            if timelineDuration.days <= 30:
                timeString = "%Y-%m-%d"
            # If year time period or less.
            if timelineDuration.days <= 365:
                timeString = "%Y-%m"
            # If greater than year time period.
            else:
                timeString = "%Y"

            # Add to chart plots.
            timeDictionary = {}
            for download in self.downloadHistory:
                date = datetime.strptime(
                    datetime.strptime(download.date, "%Y-%m-%d %H:%M:%S").strftime(
                        timeString
                    ),
                    timeString,
                )
                if date in timeDictionary:
                    timeDictionary[date] += 1
                else:
                    timeDictionary[date] = 1

            # Plot the chart.
            timePlots = list(timeDictionary.items())
            plt.clf()
            fig, ax = plt.subplots()
            ax.plot(
                [x[0] for x in timePlots], [x[1] for x in timePlots], color="dodgerblue"
            )
            ax.set(ylabel="Count", xlabel="Date", title="User Downloads Over Time")

            for directory in self.diagramDirectories:
                plt.savefig(
                    os.path.join(directory, "downloadsOverTime.png"),
                    dpi=400,
                    bbox_inches="tight",
                )

        self.analysedAvailable.append(["analysedDownloads", self.analysedDownloads])

    def analyseFormHistory(self):
        """
        Performs analysis on gathered autocomplete form history.

        1. Finds interesting form history fields, such as logins, phone numbers, addresses, etc...
        2. Finds commonly used form fields.
        3. Produces graphs of most commonly used form fields.
        """

        self.analysedFormHistory = {"PII": [], "Most Common": []}

        # Sort the form history based on use count.
        self.formHistory.sort(key=lambda x: x.useCount, reverse=True)

        # Extract data
        for formField in self.formHistory:
            # Retrieve 10 most common form fields.
            if len(self.analysedFormHistory["Most Common"]) < 10:
                self.analysedFormHistory["Most Common"].append(formField)

            # Check for PII in form field
            if any(
                PII in formField.name.lower()
                for PII in [
                    "user",
                    "pass",
                    "login",
                    "name",
                    "phone",
                    "email",
                    "address",
                ]
            ):
                self.analysedFormHistory["PII"].append(formField)

        self.analysedAvailable.append(["analysedFormHistory", self.analysedFormHistory])

        # Generate graph of commonly used fields.
        labels = []
        plots = []
        for formField in self.analysedFormHistory["Most Common"][::-1]:
            labels.append("{}={}".format(formField.name, formField.value))
            plots.append(formField.useCount)

        # Plot the bar chart.
        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(labels, plots, color="dodgerblue")
        ax.set(
            ylabel="Field Name & Value",
            xlabel="Use Count",
            title="Top Ten Most Common Autocomplete Form Fields",
        )
        ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonFormHistoryFields.png"),
                dpi=400,
                bbox_inches="tight",
            )

    def analyseLogins(self):
        """
        Performs analysis on gathered logins (if decrypted).

        1. Finds commonly used login usernames/passwords.
        2. Finds common string patterns in usernames/passwords.
        """

        self.analysedLogins = {"Commonly Used": []}

        usernames = {}
        passwords = {}

        # Finds commonly used logins and passwords.
        for login in self.logins:
            if login.username != None:
                if login.username in usernames:
                    usernames[login.username] += 1
                else:
                    usernames[login.username] = 1
            if login.password != None:
                if login.password in passwords:
                    passwords[login.password] += 1
                else:
                    passwords[login.password] = 1

        # Calculate frequency and sort usernames in place.
        usernamesList = list(usernames.items())
        sortedUsernames = [
            [x[0], x[1] / sum(n for _, n in usernamesList)] for x in usernamesList
        ]
        sortedUsernames = sorted(sortedUsernames, key=lambda x: x[1], reverse=True)[:10]

        # Calculate frequency and sort passwords in place.
        passwordsList = list(passwords.items())
        sortedPasswords = [
            [x[0], x[1] / sum(n for _, n in passwordsList)] for x in passwordsList
        ]
        sortedPasswords = sorted(sortedPasswords, key=lambda x: x[1], reverse=True)[:10]

        # Add to analysed logins.
        for login in self.logins:
            if login.password in [x[0] for x in sortedPasswords] or login.username in [x[0] for x in sortedUsernames]:
                self.analysedLogins["Commonly Used"].append(login)

        self.analysedAvailable.append(["analysedLogins", self.analysedLogins])

        # Find username and password patterns based on the longest common substring.
        usernameStrings = [x[0] for x in usernamesList]
        passwordStrings = [x[0] for x in passwordsList]
        commonStrings = []

        for userPass in [usernameStrings, passwordStrings]:
            commonPatterns = {}
            for firstString, secondString in itertools.combinations(userPass, 2):
                if (
                    firstString != secondString
                    and len(firstString) > 0
                    and len(secondString) > 0
                ):
                    substring = ""
                    for i in range(len(firstString)):
                        for j in range(len(secondString) - i + 1):
                            if (
                                j > len(substring)
                                and firstString[i : i + j] in secondString
                            ):
                                substring = firstString[i : i + j]

                    # 3 seems the right number of characters to match on...
                    if len(substring) > 3:
                        # Create the regex pattern.
                        regexToCheck = [
                            r"^.+{}$".format(substring),
                            r"^{}.+$".format(substring),
                            r"^.+{}.+$".format(substring),
                        ]
                        for regex in regexToCheck:
                            if re.match(regex, firstString) and re.match(
                                regex, secondString
                            ):
                                # Get the printable common pattern.
                                commonPattern = regex.translate(
                                    str.maketrans({"+": "*", "^": "", "$": "", ".": ""})
                                )
                                # Up the common pattern count
                                if commonPattern in commonPatterns:
                                    commonPatterns[commonPattern] += 1
                                else:
                                    commonPatterns[commonPattern] = 1

            # Append to strings list.
            commonStrings.append(list(commonPatterns.items()))

        # Generate graph of commonly used passwords and patterns.
        for diagram in [
            [
                sortedUsernames[::-1],
                "Top Ten Most Common Usernames",
                "Percentage",
                "commonUsernames.png",
            ],
            [
                sortedPasswords[::-1],
                "Top Ten Most Common Passwords",
                "Percentage",
                "commonPasswords.png",
            ],
            [
                commonStrings[0][::-1],
                "Common Patterns Identified From Usernames",
                "Count",
                "commonUsernamePatterns.png",
            ],
            [
                commonStrings[1][::-1],
                "Common Patterns Identified From Passwords",
                "Count",
                "commonPasswordPatterns.png",
            ],
        ]:
            plt.clf()
            fig, ax = plt.subplots()
            ax.barh(
                [x[0] for x in diagram[0]],
                [x[1] for x in diagram[0]],
                color="dodgerblue",
            )
            ax.set(
                ylabel=diagram[1].split(" ")[-1], xlabel=diagram[2], title=diagram[1]
            )
            if diagram[2] == "Percentage":
                ax.get_xaxis().set_major_formatter(
                    mtick.PercentFormatter(xmax=1, decimals=0)
                )
            else:
                ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

            for directory in self.diagramDirectories:
                plt.savefig(
                    os.path.join(directory, diagram[3]),
                    dpi=400,
                    bbox_inches="tight",
                )

    def analyseCookies(self):
        """
        Performs analysis on gathered cookies.

        1. Finds cookies with interesting values.
        """
        self.analysedCookies = {"Base64": [], "Hexadecimal": [], "GA Cookie": []}

        # Analyse cookies.
        for cookie in self.cookies:
            # Check for base64.
            try:
                assert(b64encode(b64decode(cookie.value)).decode("utf-8") == cookie.value)
                self.analysedCookies["Base64"].append(cookie)
            except:
                pass

            # Check for hexadecimal.
            try:
                assert(int(cookie.value, 16))
                self.analysedCookies["Hexadecimal"].append(cookie)
            except:
                pass

            # Check for GA cookies.
            if "_ga" in cookie.name:
                self.analysedCookies["GA Cookie"].append(cookie)

        self.analysedAvailable.append(["analysedCookies", self.analysedCookies])

    def analyseHistorySearches(self):
        """
        Performs analysis on gathered history searches.

        1. Finds common browsing history searches.
        """

        self.analysedHistorySearches = {"Most Common": []}

        # Sort the history searches based on use count, and extract them.
        self.historySearches.sort(key=lambda x: x.useFrequency, reverse=True)
        self.analysedHistorySearches["Most Common"] = self.historySearches[:10]

        self.analysedAvailable.append(
            ["analysedHistorySearches", self.analysedHistorySearches]
        )

        # Generate graph of commonly used fields.
        labels = []
        plots = []
        for historySearch in self.analysedHistorySearches["Most Common"]:
            labels.append(historySearch.query)
            plots.append(historySearch.useFrequency)

        # Plot the bar chart.
        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(labels, plots, color="dodgerblue")
        ax.set(
            ylabel="Query",
            xlabel="Use Frequency",
            title="Top Ten Most Common History Searches",
        )

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonHistorySearches.png"),
                dpi=400,
                bbox_inches="tight",
            )

    def analyseBrowsingHistory(self):
        """
        Performs analysis on gathered browsing history items.

        1. Produces graphs of browser usage over periods of time.
        2. Produces graphs of site browsing habits.
        """

        searchEngines = [
            ("answers.yahoo.com", 0),
            ("sapo.pt", 0),
            ("iol.pt", 0),
            ("pesquisa.clix.pt", 0),
            ("aeiou.pt", 0),
            ("cuil.pt", 0),
            ("fotos.sapo.pt", 0),
            ("videos.sapo.pt", 0),
            ("sabores.sapo.pt", 0),
            ("jn.sapo.pt", 0),
            ("dn.sapo.pt", 0),
            ("rtp.pt", 0),
            ("record.pt", 0),
            ("correiodamanha.pt", 0),
            ("correiomanha.pt", 0),
            ("publico.clix.pt", 0),
            ("xl.pt", 0),
            ("abacho.com", 0),
            ("alice.it", 0),
            ("altavista.com", 0),
            ("aolsearch.aol.com", 0),
            ("as.starware.com", 0),
            ("blogs.icerocket.com", 0),
            ("blogsearch.google.com", 0),
            ("busca.orange.es", 0),
            ("buscador.lycos.es", 0),
            ("buscador.terra.es", 0),
            ("buscar.ozu.es", 0),
            ("categorico.it", 0),
            ("cuil.com", 0),
            ("clusty.com", 0),
            ("excite.com", 0),
            ("excite.it", 0),
            ("fastweb.it", 0),
            ("fastbrowsersearch.com", 0),
            ("godado.com", 0),
            ("godado.it", 0),
            ("gps.virgin.net", 0),
            ("ilmotore.com", 0),
            ("ithaki.net", 0),
            ("kataweb.it", 0),
            ("libero.it", 0),
            ("lycos.it", 0),
            ("search.aol.co.uk", 0),
            ("search.arabia.msn.com", 0),
            ("search.bbc.co.uk", 0),
            ("search.conduit.com", 0),
            ("search.icq.com", 0),
            ("search.live.com", 0),
            ("search.lycos.co.uk", 0),
            ("search.lycos.com", 0),
            ("search.msn.co.uk", 0),
            ("search.msn.com", 0),
            ("search.myway.com", 0),
            ("search.mywebsearch.com", 0),
            ("search.ntlworld.com", 0),
            ("search.orange.co.uk", 0),
            ("search.prodigy.msn.com", 0),
            ("search.sweetim.com", 0),
            ("search.virginmedia.com", 0),
            ("search.yahoo.co.jp", 0),
            ("search.yahoo.com", 0),
            ("search.yahoo.jp", 0),
            ("simpatico.ws", 0),
            ("soso.com", 0),
            ("suche.fireball.de", 0),
            ("suche.web.de", 0),
            ("suche.t-online.de", 0),
            ("thespider.it", 0),
            ("uk.altavista.com", 0),
            ("uk.ask.com", 0),
            ("uk.search.yahoo.com", 0),
            ("alltheweb.com", 0),
            ("ask.com", 0),
            ("blueyonder.co.uk", 0),
            ("feedster.com", 0),
            ("google.ad", 0),
            ("google.ae", 0),
            ("google.af", 0),
            ("google.ag", 0),
            ("google.am", 0),
            ("google.as", 0),
            ("google.at", 0),
            ("google.az", 0),
            ("google.ba", 0),
            ("google.be", 0),
            ("google.bg", 0),
            ("google.bi", 0),
            ("google.biz", 0),
            ("google.bo", 0),
            ("google.bs", 0),
            ("google.bz", 0),
            ("google.ca", 0),
            ("google.cc", 0),
            ("google.cd", 0),
            ("google.cg", 0),
            ("google.ch", 0),
            ("google.ci", 0),
            ("google.cl", 0),
            ("google.cn", 0),
            ("google.co.at", 0),
            ("google.co.bi", 0),
            ("google.co.bw", 0),
            ("google.co.ci", 0),
            ("google.co.ck", 0),
            ("google.co.cr", 0),
            ("google.co.gg", 0),
            ("google.co.gl", 0),
            ("google.co.gy", 0),
            ("google.co.hu", 0),
            ("google.co.id", 0),
            ("google.co.il", 0),
            ("google.co.im", 0),
            ("google.co.in", 0),
            ("google.co.it", 0),
            ("google.co.je", 0),
            ("google.co.jp", 0),
            ("google.co.ke", 0),
            ("google.co.kr", 0),
            ("google.co.ls", 0),
            ("google.co.ma", 0),
            ("google.co.mu", 0),
            ("google.co.mw", 0),
            ("google.co.nz", 0),
            ("google.co.pn", 0),
            ("google.co.th", 0),
            ("google.co.tt", 0),
            ("google.co.ug", 0),
            ("google.co.uk", 0),
            ("google.co.uz", 0),
            ("google.co.ve", 0),
            ("google.co.vi", 0),
            ("google.co.za", 0),
            ("google.co.zm", 0),
            ("google.co.zw", 0),
            ("google.com", 0),
            ("google.com.af", 0),
            ("google.com.ag", 0),
            ("google.com.ai", 0),
            ("google.com.ar", 0),
            ("google.com.au", 0),
            ("google.com.az", 0),
            ("google.com.bd", 0),
            ("google.com.bh", 0),
            ("google.com.bi", 0),
            ("google.com.bn", 0),
            ("google.com.bo", 0),
            ("google.com.br", 0),
            ("google.com.bs", 0),
            ("google.com.bz", 0),
            ("google.com.cn", 0),
            ("google.com.co", 0),
            ("google.com.cu", 0),
            ("google.com.do", 0),
            ("google.com.ec", 0),
            ("google.com.eg", 0),
            ("google.com.et", 0),
            ("google.com.fj", 0),
            ("google.com.ge", 0),
            ("google.com.gh", 0),
            ("google.com.gi", 0),
            ("google.com.gl", 0),
            ("google.com.gp", 0),
            ("google.com.gr", 0),
            ("google.com.gt", 0),
            ("google.com.gy", 0),
            ("google.com.hk", 0),
            ("google.com.hn", 0),
            ("google.com.hr", 0),
            ("google.com.jm", 0),
            ("google.com.jo", 0),
            ("google.com.kg", 0),
            ("google.com.kh", 0),
            ("google.com.ki", 0),
            ("google.com.kz", 0),
            ("google.com.lk", 0),
            ("google.com.lv", 0),
            ("google.com.ly", 0),
            ("google.com.mt", 0),
            ("google.com.mu", 0),
            ("google.com.mw", 0),
            ("google.com.mx", 0),
            ("google.com.my", 0),
            ("google.com.na", 0),
            ("google.com.nf", 0),
            ("google.com.ng", 0),
            ("google.com.ni", 0),
            ("google.com.np", 0),
            ("google.com.nr", 0),
            ("google.com.om", 0),
            ("google.com.pa", 0),
            ("google.com.pe", 0),
            ("google.com.ph", 0),
            ("google.com.pk", 0),
            ("google.com.pl", 0),
            ("google.com.pr", 0),
            ("google.com.pt", 0),
            ("google.com.py", 0),
            ("google.com.qa", 0),
            ("google.com.ru", 0),
            ("google.com.sa", 0),
            ("google.com.sb", 0),
            ("google.com.sc", 0),
            ("google.com.sg", 0),
            ("google.com.sv", 0),
            ("google.com.tj", 0),
            ("google.com.tr", 0),
            ("google.com.tt", 0),
            ("google.com.tw", 0),
            ("google.com.ua", 0),
            ("google.com.uy", 0),
            ("google.com.uz", 0),
            ("google.com.ve", 0),
            ("google.com.vi", 0),
            ("google.com.vn", 0),
            ("google.com.ws", 0),
            ("google.cz", 0),
            ("google.de", 0),
            ("google.dj", 0),
            ("google.dk", 0),
            ("google.dm", 0),
            ("google.ec", 0),
            ("google.ee", 0),
            ("google.es", 0),
            ("google.fi", 0),
            ("google.fm", 0),
            ("google.fr", 0),
            ("google.gd", 0),
            ("google.ge", 0),
            ("google.gf", 0),
            ("google.gg", 0),
            ("google.gl", 0),
            ("google.gm", 0),
            ("google.gp", 0),
            ("google.gr", 0),
            ("google.gy", 0),
            ("google.hk", 0),
            ("google.hn", 0),
            ("google.hr", 0),
            ("google.ht", 0),
            ("google.hu", 0),
            ("google.ie", 0),
            ("google.im", 0),
            ("google.in", 0),
            ("google.info", 0),
            ("google.is", 0),
            ("google.it", 0),
            ("google.je", 0),
            ("google.jo", 0),
            ("google.jobs", 0),
            ("google.jp", 0),
            ("google.kg", 0),
            ("google.ki", 0),
            ("google.kz", 0),
            ("google.la", 0),
            ("google.li", 0),
            ("google.lk", 0),
            ("google.lt", 0),
            ("google.lu", 0),
            ("google.lv", 0),
            ("google.ma", 0),
            ("google.md", 0),
            ("google.mn", 0),
            ("google.mobi", 0),
            ("google.ms", 0),
            ("google.mu", 0),
            ("google.mv", 0),
            ("google.mw", 0),
            ("google.net", 0),
            ("google.nf", 0),
            ("google.nl", 0),
            ("google.no", 0),
            ("google.nr", 0),
            ("google.nu", 0),
            ("google.off.ai", 0),
            ("google.ph", 0),
            ("google.pk", 0),
            ("google.pl", 0),
            ("google.pn", 0),
            ("google.pr", 0),
            ("google.pt", 0),
            ("google.ro", 0),
            ("google.ru", 0),
            ("google.rw", 0),
            ("google.sc", 0),
            ("google.se", 0),
            ("google.sg", 0),
            ("google.sh", 0),
            ("google.si", 0),
            ("google.sk", 0),
            ("google.sm", 0),
            ("google.sn", 0),
            ("google.sr", 0),
            ("google.st", 0),
            ("google.tk", 0),
            ("google.tm", 0),
            ("google.to", 0),
            ("google.tp", 0),
            ("google.tt", 0),
            ("google.tv", 0),
            ("google.tw", 0),
            ("google.ug", 0),
            ("google.us", 0),
            ("google.uz", 0),
            ("google.vg", 0),
            ("google.vn", 0),
            ("google.vu", 0),
            ("google.ws", 0),
            ("hotbot.com", 0),
            ("in.gr", 0),
            ("mamma.com", 0),
            ("mahalo.com", 0),
            ("megasearching.net", 0),
            ("mirago.co.uk", 0),
            ("netscape.com", 0),
            ("community.paglo.com", 0),
            ("pathfinder.gr", 0),
            ("phantis.com", 0),
            ("robby.gr", 0),
            ("sproose.com", 0),
            ("technorati.com", 0),
            ("tesco.net", 0),
            ("tiscali.co.uk", 0),
            ("bing.com", 0),
            ("acbusca.com", 0),
            ("atalhocerto.com.br", 0),
            ("bastaclicar.com.br", 0),
            ("bemrapido.com.br", 0),
            ("br.altavista.com", 0),
            ("br.search.yahoo.com", 0),
            ("busca.uol.com.br", 0),
            ("buscaaqui.com.br", 0),
            ("buscador.terra.com.br", 0),
            ("cade.search.yahoo.com", 0),
            ("clickgratis.com.br", 0),
            ("entrada.com.br", 0),
            ("gigabusca.com.br", 0),
            ("internetica.com.br", 0),
            ("katatudo.com.br", 0),
            ("minasplanet.com.br", 0),
            ("speedybusca.com.br", 0),
            ("vaibuscar.com.br", 0),
            ("search.conduit.com", 0),
            ("in.search.yahoo.com", 0),
            ("rediff.com", 0),
            ("guruji.com", 0),
            ("duckduckgo.com", 0),
        ]
        socialMedia = [
            ("facebook", 0),
            ("twitter", 0),
            ("tumblr", 0),
            ("instagram", 0),
            ("pinterest", 0),
            ("linkedin", 0),
            ("gmail", 0),
            ("whatsapp", 0),
            ("telegram", 0),
            ("vk", 0),
            ("signal", 0),
        ]
        commonWebsites = {}
        browseTimes = {
            "00:00": 0,
            "01:00": 0,
            "02:00": 0,
            "03:00": 0,
            "04:00": 0,
            "05:00": 0,
            "06:00": 0,
            "07:00": 0,
            "08:00": 0,
            "09:00": 0,
            "10:00": 0,
            "11:00": 0,
            "12:00": 0,
            "13:00": 0,
            "14:00": 0,
            "15:00": 0,
            "16:00": 0,
            "17:00": 0,
            "18:00": 0,
            "19:00": 0,
            "20:00": 0,
            "21:00": 0,
            "22:00": 0,
            "23:00": 0,
        }
        browseDays = {
            "Monday": 0,
            "Tuesday": 0,
            "Wednesday": 0,
            "Thursday": 0,
            "Friday": 0,
            "Saturday": 0,
            "Sunday": 0,
        }

        # Loop through browsing history.
        for browse in self.browsingHistory:
            # Gather most popular search engines.
            searchEngines = [
                (x[0], x[1] + 1) if x[0] in browse.URL else (x[0], x[1])
                for x in searchEngines
            ]

            # Gather top 10 most visited sites.
            splitURL = parse.urlsplit(browse.URL).netloc
            if splitURL in commonWebsites:
                commonWebsites[splitURL] += 1
            else:
                commonWebsites[splitURL] = 1

            # Gather browse times.
            browseTime = datetime.strptime(browse.date, "%Y-%m-%d %H:%M:%S").strftime(
                "%H:00"
            )
            browseTimes[browseTime] += 1

            # Gather browse days.
            browseDay = datetime.strptime(browse.date, "%Y-%m-%d %H:%M:%S").strftime(
                "%A"
            )
            browseDays[browseDay] += 1

            # Gather most popular social media sites.
            socialMedia = [
                (x[0], x[1] + 1)
                if x[0] in parse.urlsplit(browse.URL).netloc
                else (x[0], x[1])
                for x in socialMedia
            ]

        # Produce most popular search engines.
        searchEngines = sorted(
            sorted(
                [x for x in searchEngines if x[1] != 0],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            key=lambda x: x[1],
            reverse=False,
        )

        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(
            [x[0] for x in searchEngines],
            [x[1] for x in searchEngines],
            color="dodgerblue",
        )
        ax.set(
            ylabel="Search Engine",
            xlabel="Use Count",
            title="Top Ten Most Common Search Engines",
        )
        ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonSearchEngines.png"),
                dpi=400,
                bbox_inches="tight",
            )

        # Produce Top 10 most visited sites.
        sortedWebsites = list(commonWebsites.items())
        sortedWebsites = sorted(
            sorted(sortedWebsites, key=lambda x: x[1], reverse=True)[:10],
            key=lambda x: x[1],
            reverse=False,
        )

        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(
            [x[0] for x in sortedWebsites],
            [x[1] for x in sortedWebsites],
            color="dodgerblue",
        )
        ax.set(
            ylabel="Website",
            xlabel="Use Count",
            title="Top Ten Most Commonly Browsed Websites",
        )
        ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonWebsites.png"),
                dpi=400,
                bbox_inches="tight",
            )

        # Produce times when user most active.
        browseTimes = list(browseTimes.items())

        plt.clf()
        fig, ax = plt.subplots()
        ax.plot(
            [datetime.strptime(x[0], "%H:00") for x in browseTimes],
            [x[1] for x in browseTimes],
            color="dodgerblue",
        )
        ax.set(
            ylabel="Sites Visited", xlabel="Time", title="Times When User Most Active"
        )
        ax.get_xaxis().set_major_formatter(mdates.DateFormatter("%H:00"))
        ax.get_yaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "activeTimes.png"),
                dpi=400,
                bbox_inches="tight",
            )

        # Produce days when user most active.
        browseDays = list(browseDays.items())

        plt.clf()
        fig, ax = plt.subplots()
        ax.plot(
            [x[0] for x in browseDays], [x[1] for x in browseDays], color="dodgerblue"
        )
        ax.set(ylabel="Sites Visited", xlabel="Day", title="Days When User Most Active")
        ax.get_yaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "activeDays.png"),
                dpi=400,
                bbox_inches="tight",
            )

        # Produce social media activity.
        socialMedia = sorted(
            sorted(
                [x for x in socialMedia if x[1] != 0], key=lambda x: x[1], reverse=True
            )[:10],
            key=lambda x: x[1],
            reverse=False,
        )

        plt.clf()
        fig, ax = plt.subplots()
        ax.barh(
            [x[0] for x in socialMedia], [x[1] for x in socialMedia], color="dodgerblue"
        )
        ax.set(
            ylabel="Social Media Site",
            xlabel="Use Count",
            title="Top Social Media Sites Used",
        )
        ax.get_xaxis().set_major_locator(mtick.MaxNLocator(integer=True))

        for directory in self.diagramDirectories:
            plt.savefig(
                os.path.join(directory, "commonSocialMediaSites.png"),
                dpi=400,
                bbox_inches="tight",
            )

    def analyse(self):
        """Perform analysis on gathered data."""

        # Analyse data.
        logging.debug("[*] Attempting to Analyse Addons...")
        self.analyseAddons()
        logging.debug("[^] Finished Analysis of Addons!\n")
        logging.debug("[*] Attempting to Analyse Extensions...")
        self.analyseExtensions()
        logging.debug("[^] Finished Analysis of Extensions!\n")
        logging.debug("[*] Attempting to Analyse Certificates...")
        self.analyseCertificates()
        logging.debug("[^] Finished Analysis of Certificates!\n")
        logging.debug("[*] Attempting to Analyse Cookies...")
        self.analyseCookies()
        logging.debug("[^] Finished Analysis of Cookies!\n")
        logging.debug("[*] Attempting to Analyse Form History...")
        self.analyseFormHistory()
        logging.debug("[^] Finished Analysis of Form History!\n")
        logging.debug("[*] Attempting to Analyse History Searches...")
        self.analyseHistorySearches()
        logging.debug("[^] Finished Analysis of History Searches!\n")
        logging.debug("[*] Attempting to Analyse Download History...")
        self.analyseDownloads()
        logging.debug("[^] Finished Analysis of Download History!\n")
        logging.debug("[*] Attempting to Analyse Browsing History...")
        self.analyseBrowsingHistory()
        logging.debug("[^] Finished Analysis of Browsing History!\n")
        logging.debug("[*] Attempting to Analyse Bookmarks...")
        self.analyseBookmarks()
        logging.debug("[^] Finished Analysis of Bookmarks!\n")
        logging.debug("[*] Attempting to Analyse Logins...")
        self.analyseLogins()
        logging.debug("[^] Finished Analysis of Logins!")


def directoryPath(dir):
    """
    Checks that the specified path is a directory.

    Parameters
    ----------
    dir : str
    The directory path to check.

    Return Values
    -------------
    dir : str
    The checked directory path.
    """
    if os.path.isdir(dir):
        return dir
    else:
        logging.error("[!] No such directory '{}'\n".format(dir))
        sys.exit(1)


def fileExists(filePath):
    """
    Checks that the file specified exists.

    Parameters
    ----------
    filePath : str
    The path to the file.

    Return Values
    -------------
    status : bool
    Set if the file exists, unset if no such file.
    """
    if os.path.isfile(filePath):
        return True
    else:
        return False


def dirExists(dirPath):
    """
    Checks that the file specified exists.

    Parameters
    ----------
    dirPath : str
    The path to the directory.

    Return Values
    -------------
    status : bool
    Set if the file exists, unset if no such file.
    """
    if os.path.isdir(dirPath):
        return True
    else:
        return False


def chooseFirefoxProfileDirectory():
    """
    Searches for Firefox profiles on the user's system.

    Return Values
    -------------
    profile : str
    The path to the chosen profile.
    """
    firefoxProfiles = []

    logging.info("[*] No Profile Directory Specified - Finding Firefox Profiles...\n")
    # Recursively search from root directory.
    for root, dirnames, filenames in os.walk("/"):
        # Find profiles.ini file.
        for filename in fnmatch.filter(filenames, "profiles.ini"):
            # Verify profiles.ini is from firefox folder.
            if root.split("/")[-1] == "firefox":
                # Find the profiles listed in the file and add them to the list.
                with open(os.path.join(root, filename)) as profilesFile:
                    for line in profilesFile:
                        if "Path=" in line:
                            firefoxProfiles.append(
                                os.path.join(root, line.split("=")[1].rstrip())
                            )

    # Display the profiles to the user, and return the chosen one.
    return displayFirefoxProfiles(firefoxProfiles)


def displayFirefoxProfiles(firefoxProfiles):
    """
    Displays found profiles to the user and lets them choose which one to proceed with.

    Parameters
    ----------
    firefoxProfiles : [str]
    List of paths to profiles.

    Return Values
    -------------
    profile : str
    Path to chosen profile.
    """
    # Display the found profiles to the screen.
    logging.info("[*] Displaying Found Firefox Profiles:")
    for profileCount in range(len(firefoxProfiles)):
        logging.info(
            "[-] Option {}: {}".format(profileCount + 1, firefoxProfiles[profileCount])
        )

    # Allow the user to select an option.
    selectedProfile = input("\n[+] Please Enter a Profile Option: ")

    # Validation checking for profiles.
    while selectedProfile not in [str(x) for x in range(1, len(firefoxProfiles) + 1)]:
        logging.error(
            "[!] Invalid Profile Option Selected. Must be an integer within range 0 to {}\n".format(
                len(firefoxProfiles)
            )
        )
        selectedProfile = input(
            "[+] Please Enter an Number Corresponding to a Profile: "
        )

    # Return the selected profile path.
    return firefoxProfiles[int(selectedProfile) - 1]


def findAddons(addonsPath):
    """
    Finds addons in the selected Firefox profile.

    Parameters
    ----------
    addonsPath : str
    Path to the addons.json file.

    Return Values
    -------------
    addonsList : [Addon]
    List of identified addons.
    """
    addonList = []

    # Check for presence of addons.json in profile folder. Return if not found.
    if not fileExists(addonsPath):
        logging.debug("[!] Failed to Gather Addons from 'addons.json'")
        return addonList

    # Open the file containing addons and load as json object.
    with open(addonsPath) as addonsFile:
        addonsExtracted = json.load(addonsFile)["addons"]

    # Loop through addons in file and instanciate python objects with relevant attributes.
    for profileAddon in addonsExtracted:
        addonObject = Addon(
            name=profileAddon["name"],
            version=profileAddon["version"],
            URL=profileAddon["sourceURI"],
            storeURL=profileAddon["reviewURL"].replace("reviews/", ""),
            downloads=profileAddon["weeklyDownloads"],
            screenshots=[
                screenshot["url"] for screenshot in profileAddon["screenshots"]
            ],
            rating=profileAddon["averageRating"],
        )
        addonList.append(addonObject)

    # Return list of addon objects.
    logging.debug("[^] Successfully Gathered Addons From 'addons.json'")
    return addonList


def findExtensions(extensionsPath):
    """
    Finds extensions in the selected Firefox profile.

    Parameters
    ----------
    extensionsPath : str
    Path to the extensions.json file.

    Return Values
    -------------
    extensionsList : [Extension]
    List of identified extensions.
    """
    extensionList = []

    # Check for presence of extensions.json in profile folder. Return if not found.
    if not fileExists(extensionsPath):
        logging.debug("[!] Failed to Gather Extensions from 'extensions.json'")
        return extensionList

    # Open the file containing addons and load as json object.
    with open(extensionsPath) as extensionsFile:
        extractedExtensions = json.load(extensionsFile)["addons"]

    # Loop through extensions in file and instanciate python objects with relevant attributes.
    for profileExtension in extractedExtensions:
        name = profileExtension["defaultLocale"]["name"]
        URL = profileExtension["sourceURI"]
        permissions = profileExtension["userPermissions"]
        if permissions != None:
            permissions = permissions["permissions"]
        else:
            permissions = []

        extensionObject = Extension(
            name=name,
            URL=URL,
            permissions=permissions,
        )
        extensionList.append(extensionObject)

    # Return list of extension objects.
    logging.debug("[^] Successfully Gathered Extensions From 'extensions.json'")
    return extensionList


def findCertificates(certificatesPath):
    """
    Finds trusted certificates in the selected Firefox profile.

    Parameters
    ----------
    certificatesPath : str
    Path to the cert9.db file.

    Return Values
    -------------
    certificatesList : [Certificate]
    List of identified certificates.
    """
    certificatesList = []

    # Check for presence of certs9.db in profile folder. Return if not found.
    if not fileExists(certificatesPath):
        logging.debug("[!] Failed to Gather Certificates from 'cert9.db'")
        return certificatesList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(certificatesPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the certificate fields from the nssPublic table.
        for extractedCert in databaseCursor.execute("SELECT a11 FROM nssPublic"):
            try:

                # Gather certificate nickname from extracted data.
                cert = x509.Certificate.load(extractedCert[0])
                version = cert.native["tbs_certificate"]["version"]
                serial = cert.native["tbs_certificate"]["serial_number"]
                hashAlgo = cert.hash_algo
                issuer = cert.issuer.human_friendly
                validFrom = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
                validUntil = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
                subject = cert.subject.human_friendly
                subjectKeyAlgorithm = cert.public_key.algorithm
                subjectKeyBitSize = cert.public_key.bit_size
                extensions = [
                    x["extn_id"] for x in cert.native["tbs_certificate"]["extensions"]
                ]

                # Create the certificate object from parameters.
                certificateObject = Certificate(
                    version=version,
                    serial=serial,
                    hashAlgo=hashAlgo,
                    issuer=issuer,
                    validFrom=validFrom,
                    validUntil=validUntil,
                    subject=subject,
                    subjectKeyAlgorithm=subjectKeyAlgorithm,
                    subjectKeyBitSize=subjectKeyBitSize,
                    extensions=extensions,
                    cert=extractedCert[0],
                )
                certificatesList.append(certificateObject)
            except:
                continue

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of certificate objects.
    logging.debug("[^] Successfully Gathered Certificates From 'cert9.db'")
    return certificatesList


def findCookies(cookiesPath):
    """
    Finds cookies in the selected Firefox profile.

    Parameters
    ----------
    cookiesPath : str
    Path to the cookies.sqlite file.

    Return Values
    -------------
    cookiesList : [Cookie]
    List of identified cookies.
    """
    cookiesList = []

    # Check for presence of cookies.sqlite in profile folder. Return if not found.
    if not fileExists(cookiesPath):
        logging.debug("[!] Failed to Gather Cookies from 'cookies.sqlite'")
        return cookiesList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(cookiesPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the cookie fields from the moz_cookies table.
        for extractedCookie in databaseCursor.execute(
            "SELECT host, path, name, value, datetime((expiry),'unixepoch','localtime'), datetime((lastAccessed/1000000),'unixepoch','localtime'), datetime((creationTime/1000000),'unixepoch','localtime'), isSecure, isHttpOnly, sameSite FROM moz_cookies"
        ):
            cookieObject = Cookie(
                host=extractedCookie[0] + extractedCookie[1],
                name=extractedCookie[2],
                value=extractedCookie[3],
                expiry=extractedCookie[4],
                lastAccessed=extractedCookie[5],
                creationTime=extractedCookie[6],
                secure=bool(extractedCookie[7]),
                httpOnly=bool(extractedCookie[8]),
                sameSite=bool(extractedCookie[9]),
            )
            cookiesList.append(cookieObject)

    # Exit when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of cookie objects.
    logging.debug("[^] Successfully Gathered Cookies From 'cookies.sqlite'")
    return cookiesList


def findFormHistory(formHistoryPath):
    """
    Finds autocomplete form history fields in the selected Firefox profile.

    Parameters
    ----------
    formHistoryPath : str
    Path to the formhistory.sqlite file.

    Return Values
    -------------
    formHistoryList : [FormField]
    List of identified autocomplete form history fields.
    """
    formHistoryList = []

    # Check for presence of formhistory.sqlite in profile folder. Return if not found.
    if not fileExists(formHistoryPath):
        logging.debug(
            "[!] Failed to Gather Autocomplete History from 'formhistory.sqlite'"
        )
        return formHistoryList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(formHistoryPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_formhistory table.
        for extractedFormHistoryField in databaseCursor.execute(
            "SELECT fieldName, value, timesUsed FROM moz_formhistory"
        ):
            formFieldObject = FormField(
                name=extractedFormHistoryField[0],
                value=extractedFormHistoryField[1],
                useCount=extractedFormHistoryField[2],
            )
            formHistoryList.append(formFieldObject)

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of form field history objects.
    logging.debug(
        "[^] Successfully Gathered Autocomplete History From 'formhistory.sqlite'"
    )
    return formHistoryList


def findHistorySearches(historySearchPath):
    """
    Finds browsing history searches in the selected Firefox profile.

    Parameters
    ----------
    historySearchPath : str
    Path to the places.sqlite file.

    Return Values
    -------------
    historySearchList : [HistorySearch]
    List of identified browsing history searches.
    """
    historySearchList = []

    # Check for presence of places.sqlite in profile folder. Return if not found.
    if not fileExists(historySearchPath):
        logging.debug("[!] Failed to Gather History Searches from 'places.sqlite'")
        return historySearchList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(historySearchPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_inputhistory table.
        for extractedHistorySearch in databaseCursor.execute(
            "SELECT input, use_count FROM moz_inputhistory"
        ):

            historySearchObject = HistorySearch(
                query=extractedHistorySearch[0],
                useFrequency=extractedHistorySearch[1],
            )
            historySearchList.append(historySearchObject)

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of history search objects.
    logging.debug("[^] Successfully Gathered History Searches From 'places.sqlite'")
    return historySearchList


def findDownloadHistory(downloadHistoryPath):
    """
    Finds download history items in the selected Firefox profile.

    Parameters
    ----------
    downloadHistoryPath : str
    Path to the places.sqlite file.

    Return Values
    -------------
    downloadHistoryList : [Download]
    List of identified downloads.
    """
    downloadHistoryList = []

    # Check for presence of places.sqlite in profile folder. Return if not found.
    if not fileExists(downloadHistoryPath):
        logging.debug("[!] Failed to Gather Download History from 'places.sqlite'")
        return downloadHistoryList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(downloadHistoryPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_places and moz_annos tables.
        for extractedDownloadHistory in databaseCursor.execute(
            "SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content, url FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id"
        ):
            if "file://" in extractedDownloadHistory[1]:
                downloadObject = Download(
                    date=extractedDownloadHistory[0],
                    downloadPath=parse.unquote(
                        extractedDownloadHistory[1].replace("file://", "")
                    ),
                    URL=extractedDownloadHistory[2],
                )
                downloadHistoryList.append(downloadObject)

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of download history objects.
    logging.debug("[^] Successfully Gathered Download History From 'places.sqlite'")
    return downloadHistoryList


def findBrowsingHistory(browsingHistoryPath):
    """
    Finds browsing history items in the selected Firefox profile.

    Parameters
    ----------
    browsingHistoryPath : str
    Path to the places.sqlite file.

    Return Values
    -------------
    browsingHistoryList : [Browse]
    List of identified browsing history items.
    """
    browsingHistoryList = []

    # Check for presence of places.sqlite in profile folder. Return if not found.
    if not fileExists(browsingHistoryPath):
        logging.debug("[!] Failed to Gather Browsing History from 'places.sqlite'")
        return browsingHistoryList

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(browsingHistoryPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_places and moz_historyvisits tables.
        for extractedBrowsingHistory in databaseCursor.execute(
            "select datetime(last_visit_date/1000000,'unixepoch') as visit_date, url, title, visit_type, visit_count FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id"
        ):
            browsingHistoryObject = Browse(
                date=extractedBrowsingHistory[0],
                URL=extractedBrowsingHistory[1],
                title=extractedBrowsingHistory[2],
                visitType=extractedBrowsingHistory[3],
                visitCount=extractedBrowsingHistory[4],
            )
            browsingHistoryList.append(browsingHistoryObject)

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of brrowsing history objects.
    logging.debug("[^] Successfully Gathered Browsing History From 'places.sqlite'")
    return browsingHistoryList


def findBookmarkChildren(element, type, returnList):
    """
    Recursively extracts individual bookmarks from .mozlz4 nested JSON.

    Parameters
    ----------
    element : dict
    A nested JSON element.

    type : str
    The specified type to extract on.

    returnList : [dict]
    List of extracted bookmarks so far.

    Return Values
    -------------
    returnList : [dict]
    List of extracted bookmarks in addition to new ones found in deeper searches.
    """
    if element.get("type", None) == type:
        returnList.append(element)
        return returnList

    for child in element.get("children", []):
        newReturnList = findBookmarkChildren(child, type, returnList)
        if newReturnList is not returnList:
            returnList = newReturnList

    return returnList


def findBookmarks(bookmarksPath, bookmarksFolder):
    """
    Finds bookmarks in the selected Firefox profile.

    Parameters
    ----------
    bookmarksPath : str
    Path to the places.sqlite file.

    bookmarksFolder : str
    Path to the bookmarkbackups folder.

    Return Values
    -------------
    bookmarksList : [Bookmark]
    List of identified bookmarks.
    """
    bookmarksList = []

    # Check for presence of places.sqlite in profile folder. Return if not found.
    if not fileExists(bookmarksPath):
        logging.debug("[!] Failed to Gather Active Bookmarks from 'places.sqlite'")
        return bookmarksList

    # Extraction of ACTIVE bookmarks (places.sqlite)
    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(bookmarksPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_places and moz_annos tables.
        for extractedBookmark in databaseCursor.execute(
            "SELECT datetime((moz_bookmarks.dateAdded/1000000),'unixepoch','localtime'), moz_places.url, moz_places.title FROM moz_bookmarks, moz_places WHERE moz_bookmarks.fk=moz_places.id"
        ):
            bookmarkObject = Bookmark(
                dateAdded=extractedBookmark[0],
                URL=extractedBookmark[1],
                title=extractedBookmark[2],
                active=True,
            )
            bookmarksList.append(bookmarkObject)

    # Error out when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    logging.debug("[^] Successfully Gathered Active Bookmarks From 'places.sqlite'")

    # Extraction of BACKUP bookmarks (maybe deleted...)
    if dirExists(bookmarksFolder):
        for bookmarkBackup in os.listdir(bookmarksFolder):
            with open(
                os.path.join(bookmarksFolder, bookmarkBackup), "rb"
            ) as backupMozFile:
                # Check that file is mozlz4 compressed.
                if backupMozFile.read(8) == b"mozLz40\0":
                    # Gather root bootmark, and recursively find child bookmarks.
                    rootBookmark = json.loads(lz4.decompress(backupMozFile.read()))
                    childBookmarks = findBookmarkChildren(
                        rootBookmark, "text/x-moz-place", []
                    )
                    for childBookmark in childBookmarks:
                        # Check if bookmark has been deleted. Add it to the bookmarks list if it has.
                        if childBookmark["uri"] not in [x.URL for x in bookmarksList]:
                            bookmarkObject = Bookmark(
                                dateAdded=datetime.utcfromtimestamp(
                                    float(childBookmark["dateAdded"] / 1000000)
                                ).strftime("%Y-%m-%d %H:%M:%S"),
                                URL=childBookmark["uri"],
                                title=childBookmark["title"],
                                active=False,
                            )
                            bookmarksList.append(bookmarkObject)

        logging.debug(
            "[^] Successfully Gathered Deleted Bookmarks From 'bookmarkbackups/'"
        )

    # Return the list of bookmark objects.
    return bookmarksList


def findLoginData(loginPath, keyPath):
    """
    Finds logins in the selected Firefox profile.

    Parameters
    ----------
    loginPath : str
    Path to the logins.json file.

    keyPath : str
    Path to the key4.db file.

    Return Values
    -------------
    loginList : [Login]
    List of identified logins.
    """
    loginList = []
    decryptionSkip = False

    # Check for presence of logins.json in profile folder. Return if not found.
    if not fileExists(loginPath):
        logging.debug("[!] Failed to Gather Login Data from 'logins.json'")
        return loginList

    # Check for presence of key4.db in profile folder. Skip Decryption if not found.
    if not fileExists(keyPath):
        logging.debug("[!] Failed to Gather Key Database 'key4.db'.")
        decryptionSkip = True

    # Create the LoginData object used for storing logins and decrypting.
    loginData = LoginData(profile="/".join(loginPath.split("/")[:-1]))

    # Initialise the NSS library using the firefox profile.
    loginData.initialiseProfile()

    # Open the file containing logins and load as json object.
    with open(loginPath) as loginsFile:
        extractedLogins = json.load(loginsFile)["logins"]

    # Loop through logins in file and instanciate python objects with relevant attributes.
    for login in extractedLogins:
        loginObject = Login(
            host=login["hostname"],
            encryptedUsername=login["encryptedUsername"],
            encryptedPassword=login["encryptedPassword"],
        )
        loginData.logins.append(loginObject)

    logging.debug("[^] Successfully Gathered Encrypted Logins From 'logins.json'")

    # If decryption step not skipped, attempt decrypt of passwords.
    if not decryptionSkip:

        # Attempt decryption using no password.
        blankResult = loginData.attemptBlankAuthentication()

        # If blank authentication succeeds:
        if blankResult == True:
            # Decrypt using blank password.
            if loginData.authenticate(""):
                logging.debug(
                    "[^] Successfully Attempted Blank Authentication on Key Database"
                )
                loginData.decryptLogins()
                loginData.deactivateProfile()
            return loginData.logins

        # Blank authentication failed, password in use.
        elif blankResult == False:
            selectedOption = -1

            while selectedOption != "3":
                logging.info("\n[*] Login Data Protected With Master Password. ")
                logging.info("[-] Option 1: Enter the Password")
                logging.info("[-] Option 2: Bruteforce the Password Using a Dictionary")
                logging.info("[-] Option 3: Give Up")

                # Allow the user to select an option.
                selectedOption = input("\n[+] Please Enter an Option: ")

                # Validation checking for profiles.
                while selectedOption not in ["1", "2", "3"]:
                    logging.error(
                        "[!] Invalid Option Selected. Must be an Integer Within Range 1 to 3\n"
                    )
                    selectedOption = input(
                        "[+] Please Enter an Number Corresponding to an Option: "
                    )

                # Password authentication selected.
                if selectedOption == "1":
                    password = input(
                        "[+] Please Enter the Master Password to Decrypt Usernames & Passwords: "
                    )

                    # Attempt authentication with entered password.
                    passwordResult = loginData.attemptPasswordAuthentication(password)

                    # Decrypt logins if correct.
                    if passwordResult == True:
                        if loginData.authenticate(password):
                            logging.debug(
                                "[^] Successfully Attempted Password Authentication on Key Database"
                            )
                            loginData.decryptLogins()
                            loginData.deactivateProfile()
                        return loginData.logins
                    # Notify the user of incorrect password.
                    elif passwordResult == False:
                        logging.error("[!] Wrong Master Password.")
                    # Error whilst decrypting, skip decryption.
                    else:
                        break

                # Bruteforce attack selected.
                elif selectedOption == "2":
                    # Get the wordlist from the user
                    dictionary = input("[+] Please Enter the Path to the Wordlist: ")
                    if fileExists(dictionary):
                        logging.info(
                            "[*] Attempting to Brute Force (This May Take a While...)"
                        )
                        # Attempt the bruteforce attack.
                        bruteForceAttempt = loginData.attemptBruteForceAuthentication(
                            dictionary
                        )

                        # Break if an error occurs.
                        if bruteForceAttempt == True:
                            break
                        # Log an error if the master password is not found in the wordlist.
                        elif bruteForceAttempt == None:
                            logging.error(
                                "[!] Master Password Not Found in Dictionary."
                            )
                        # Decrypt logins if password is found.
                        else:
                            if loginData.authenticate(bruteForceAttempt):
                                logging.debug(
                                    "[^] Successfully Attempted Brute Force Attack With Password '{}' on Key Database".format(
                                        bruteForceAttempt
                                    )
                                )
                                loginData.decryptLogins()
                                loginData.deactivateProfile()
                            return loginData.logins

                    # Wordlist not found!
                    else:
                        logging.error("[!] No Such File '{}'".format(dictionary))
            return loginData.logins


def dumpData(foxHunter, type, directory):
    """
    Dumps extracted Firefox data to various file formats.

    Parameters
    ----------
    foxHunter : FoxHunter
    The FoxHunter object containing data to dump.

    type : str
    File type to dump to.

    directory : str
    Path to store dumped data.
    """

    # Add newline for clarity.
    logging.debug("")

    # Check for lack of data to dump.
    if not foxHunter.findAvailable():
        logging.error("[!] No Data Gathered From FoxHunter.")
        sys.exit(1)

    # Dump certificates first.
    availableList = foxHunter.findAvailable()

    if "certificates" in [f[0] for f in availableList]:
        # Get the list of certificates.
        certificateList = [f[1] for f in availableList if f[0] == "certificates"][0]
        # Create the certificate directory.
        certDirectory = os.path.join(directory, "certificates")
        if not dirExists(certDirectory):
            os.makedirs(certDirectory)

        # Loop through certificates, dump the bytes in the specified filename.
        for certificate in certificateList:
            if certificate.cert != 1:
                with open(os.path.join(directory, certificate.path), "wb") as certFile:
                    certFile.write(pem.armor("CERTIFICATE", certificate.cert))
                certificate.cert = 1
        else:
            logging.debug(
                "[^] Successfully Dumped Certificate Files to 'certificates/'"
            )

    # Loop through all gathered datasets one by one
    for attribute, values in foxHunter.findAvailable():

        # Create a printable version of the attribute.
        printableAttribute = (
            "".join(
                " " + char if char.isupper() else char.strip() for char in attribute
            )
            .strip()
            .title()
        )
        filename = "{}.{}".format(attribute, type)

        # Deal with CSV formatting.
        if type == "csv":
            try:
                with open(
                    os.path.join(directory, filename), "w+", newline=""
                ) as csvFile:
                    writer = csv.writer(csvFile)
                    writer.writerow(list(values[0].__dict__.keys()))
                    for item in values:
                        writer.writerow(list(item.__dict__.values()))

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )

        # Deal with JSON formatting.
        if type == "json":
            try:
                with open(
                    os.path.join(directory, filename), "w+", newline=""
                ) as jsonFile:

                    jsonString = json.dumps([object.__dict__ for object in values])
                    jsonFile.write(jsonString)

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )

        # Deal with XML formatting.
        if type == "xml":
            try:
                # Create the XML tree.
                root = ET.Element(attribute)
                for object in values:
                    sub = ET.SubElement(root, object.__class__.__name__.lower())
                    for key in object.__dict__.keys():
                        ET.SubElement(sub, key).text = str(object.__dict__[key])

                # Write the XML tree to file.
                tree = ET.ElementTree(root)
                tree.write(os.path.join(directory, filename))

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )


def findAnalysedKeys(dictionary):
    for key in dictionary.keys():
        if dictionary[key] != []:
            return dictionary[key][0].__dict__.keys()


def dumpAnalysed(foxHunter, type, directory):
    """
    Dumps analysed Firefox data to various file formats.

    Parameters
    ----------
    foxHunter : FoxHunter
    The FoxHunter object containing data to dump.

    type : str
    File type to dump to.

    directory : str
    Path to store dumped data.
    """

    # Add newline for clarity.
    logging.debug("")

    # Check for lack of data to dump.
    if not foxHunter.findAnalysedAvailable():
        logging.error("[!] No Analysed Data Available From FoxHunter.")
        sys.exit(1)

    availableList = foxHunter.findAnalysedAvailable()

    logging.debug("[*] Successfully Dumped Created Diagrams to 'diagrams/'")

    # Loop through all gathered datasets one by one.
    for attribute, values in availableList:

        # Create a printable version of the attribute.
        printableAttribute = (
            "".join(
                " " + char if char.isupper() else char.strip() for char in attribute
            )
            .strip()
            .title()
        )
        filename = "{}.{}".format(attribute, type)
        
        # Check that there is data to dump.
        gatheredValues = [x for x in values.items() if x[1] != []]
        if gatheredValues == []:
            continue
            
        # Deal with CSV formatting.
        if type == "csv":
            try:
                with open(
                    os.path.join(directory, filename), "w+", newline=""
                ) as csvFile:
                    writer = csv.writer(csvFile)
                    writer.writerow(["reason"] + list(findAnalysedKeys(values)))
                    for item in values:
                        for object in values[item]:
                            writer.writerow([item] + list(object.__dict__.values()))

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )

        # Deal with JSON formatting.
        if type == "json":
            try:
                with open(
                    os.path.join(directory, filename), "w+", newline=""
                ) as jsonFile:

                    for item in values:
                        values[item] = [object.__dict__ for object in values[item]]
                    jsonString = json.dumps(values)
                    jsonFile.write(jsonString)

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )

        # Deal with XML formatting.
        if type == "xml":
            try:
                # Create the XML tree.
                root = ET.Element(attribute)
                for item in values:
                    sub = ET.SubElement(
                        root, item[0].lower() + item[1:].replace(" ", "")
                    )
                    for object in values[item]:
                        sub2 = ET.SubElement(sub, object.__class__.__name__.lower())
                        for key in object.__dict__.keys():
                            ET.SubElement(sub2, key).text = str(object.__dict__[key])

                # Write the XML tree to file.
                tree = ET.ElementTree(root)
                tree.write(os.path.join(directory, filename))

            except BaseException:
                logging.error(
                    "[!] Failed to Dump {} to '{}'".format(printableAttribute, filename)
                )
            else:
                logging.debug(
                    "[^] Successfully Dumped {} to '{}'".format(
                        printableAttribute, filename
                    )
                )


if __name__ == "__main__":

    # Remove warnings.
    logging.getLogger("matplotlib").setLevel(logging.CRITICAL)
    logging.getLogger("requests").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    # Display foxhunter logo.
    print(
        r"""                                                           
                          :!JPB&&&&&&&&&&&#BP?~.                           
                      ^Y#@@&#PJ!^:.....::~7YB@@@@B?:                       
              ~~   :P@@&P!.                   :^?G@@&Y.                    
             ?@@7!#@&J.   .!YGJ.              .!YB&@@@@&Y.                 
            :@@@@@@&P55Y?G@@@7                   .^J#@@@@@P:J              
            !@@@@@@@@@@@@@@@B          .~?JYJ?!.     .5@@@@&&P             
            5@@@@@@@@@@@@@@@@&J!!!!^  YGJ~:.:~7Y5      .B@@@@@!            
           G@@@@@@@@@@@@@@@@@@@@@@@P GJ:        7#    :^#@@@@&            
          5@@@@@@@@@@@@@@@@@@@@@G!.  &.          &.    ~@&@@@@@7           
         ^@@@@@@@@@@@@@@@@@@@@#     YG         55     .@@@@@@@B^          
         ~@@@@@@@@@@@@@@@@@&B#G       ~P?^...^75!      .@@@@@@@@5          
         !@@@@@@@@@@@@@@@@G            B&P~!!^.      7.7@@@@@@@@?          
         J@@@@@@@@@@@@@@@@@!         .&@&            B@@@@@@@@@@.          
         :@@@@@@@@@@@@@@@@@@&5!^:^75B@@@&5:          #@@@@@@@@@B           
          5@@@@@@@@@@@@@@@@@@@@@@@@@@@@#P5!       . .@@@@@@@@@@:           
           &@@@@@@@@@@@@@@@@@@@@@@@&BJ:          7G B@@@@@@@@@J            
           .&@@@@@@@@@@@@@@@@@#?^.             7&@#&@@@@@@@@@P             
            .#@@@@@@@@@@@@@@@@@@&B57^:.  ..^?B@@@@@@@@@@@@@@5              
              J@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&!               
               .G@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@5.                
                 :5@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&Y.                  
                    !G&@@@@@@@@@@@@@@@@@@@@@@@@@@@@&P~                     
                       :?P#@@@@@@@@@@@@@@@@@@@&B5!.                        
                            .^!?JY5PPP55Y?7~:.    

                     FoxHunter v1.0 by Cameron Wickes         
        """
    )

    # Set logging level to INFO and above, and set format.
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Create the argument parser and add required arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="don't display debug messages",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--profile",
        type=directoryPath,
        help="directory of firefox profile to seek artifacts",
        required=False,
    )
    parser.add_argument(
        "-oC",
        "--output-csv",
        type=directoryPath,
        metavar="OUTPUT_DIR",
        help="directory to dump artifacts in CSV format",
        required=False,
    )
    parser.add_argument(
        "-oJ",
        "--output-json",
        type=directoryPath,
        metavar="OUTPUT_DIR",
        help="directory to dump artifacts in JSON format",
        required=False,
    )
    parser.add_argument(
        "-oX",
        "--output-xml",
        type=directoryPath,
        metavar="OUTPUT_DIR",
        help="directory to dump artifacts in XML format",
        required=False,
    )
    parser.add_argument(
        "-A",
        "--analyse",
        action="store_true",
        help="analyse gathered artifacts",
        required=False,
    )

    # Parse the arguments.
    arguments = parser.parse_args()

    # If no profile directory specified, search the system for them, and let the user choose.
    if arguments.profile == None:
        arguments.profile = chooseFirefoxProfileDirectory()

    # If quiet flag is not set, allow DEBUG levels and above through, and force handlers to change.
    if arguments.quiet == False:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s", force=True)

    logging.debug("[*] Received Firefox Profile!")
    logging.debug("[*] Searching Selected Profile Directory for Artifacts...")

    logging.debug("\n\033[1m\033[4m[*] Extracting Addons and Extensions...\033[0m\n")

    # Search for addons within selected firefox profile (addons.json)
    addons = findAddons(os.path.join(arguments.profile, "addons.json"))

    # Search for extensions within selected firefox profile (extensions.json).
    extensions = findExtensions(os.path.join(arguments.profile, "extensions.json"))

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting Certificates, Cookies and Form History...\033[0m\n"
    )

    # Search for certificates within selected firefox profile (cert9.db)
    certificates = findCertificates(os.path.join(arguments.profile, "cert9.db"))

    # Search for cookies within selected firefox profile (cookies.sqlite)
    cookies = findCookies(os.path.join(arguments.profile, "cookies.sqlite"))

    # Search for web form data within selected firefox profile (formhistory.sqlite)
    formHistory = findFormHistory(os.path.join(arguments.profile, "formhistory.sqlite"))

    logging.debug("\n\033[1m\033[4m[*] Extracting History Items...\033[0m\n")

    # Search for history searches within selected firefox profile (places.sqlite)
    historySearches = findHistorySearches(
        os.path.join(arguments.profile, "places.sqlite")
    )

    # Search for downloads within selected firefox profile. (places.sqlite)
    downloadHistory = findDownloadHistory(
        os.path.join(arguments.profile, "places.sqlite")
    )

    # Search for browsing history within selected firefox profile (places.sqlite)
    browsingHistory = findBrowsingHistory(
        os.path.join(arguments.profile, "places.sqlite")
    )

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting Active and Deleted Bookmarks...\033[0m\n"
    )

    # Search for bookmarks within selected firefox profile. (places.sqlite/bookmarkbackups)
    bookmarks = findBookmarks(
        os.path.join(arguments.profile, "places.sqlite"),
        os.path.join(arguments.profile, "bookmarkbackups"),
    )

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting and Decrypting Login Data...\033[0m\n"
    )

    # Search for logins and passwords within selected firefox profile (logins.json/key4.db)
    # Inspiration from https://gist.github.com/dhondta/2e4946f791e5860bdb588d452b5b1570#file-firefox_decrypt_modified-py
    logins = findLoginData(
        os.path.join(arguments.profile, "logins.json"),
        os.path.join(arguments.profile + "/key4.db"),
    )

    # Create the FoxHunter object to analyse data.
    foxHunter = FoxHunter(
        addons,
        extensions,
        certificates,
        cookies,
        formHistory,
        historySearches,
        downloadHistory,
        browsingHistory,
        bookmarks,
        logins,
    )

    # Add diagram directories
    if arguments.output_csv:
        directory = os.path.join(arguments.output_csv, "diagrams/")
        if not dirExists(directory):
            os.makedirs(directory)
        foxHunter.diagramDirectories.append(directory)
    if arguments.output_json:
        directory = os.path.join(arguments.output_json, "diagrams/")
        if not dirExists(directory):
            os.makedirs(directory)
        foxHunter.diagramDirectories.append(directory)
    if arguments.output_xml:
        directory = os.path.join(arguments.output_xml, "diagrams/")
        if not dirExists(directory):
            os.makedirs(directory)
        foxHunter.diagramDirectories.append(directory)

    # Analyse the data if necessary.
    if arguments.analyse:
        logging.debug("\n\033[1m\033[4m[*] Analysing Gathered Data...\033[0m\n")
        foxHunter.analyse()

    # Print message if appropriate.
    if arguments.output_csv or arguments.output_json or arguments.output_xml:
        logging.debug("\n\033[1m\033[4m[*] Dumping Gathered Data...\033[0m")

    # Check the input arguments for correct formatting.
    if arguments.output_csv:
        dumpData(foxHunter, "csv", arguments.output_csv)
        if arguments.analyse:
            dumpAnalysed(foxHunter, "csv", arguments.output_csv)
    if arguments.output_json:
        dumpData(foxHunter, "json", arguments.output_json)
        if arguments.analyse:
            dumpAnalysed(foxHunter, "json", arguments.output_json)
    if arguments.output_xml:
        dumpData(foxHunter, "xml", arguments.output_xml)
        if arguments.analyse:
            dumpAnalysed(foxHunter, "xml", arguments.output_xml)

    # Print summary.
    logging.info("\n\033[1m\033[4m[+] Artifact Statistics\033[0m\n")
    for attribute, values in foxHunter.findAvailable():
        # Create a printable version of the attribute.
        printableAttribute = (
            "".join(
                " " + char if char.isupper() else char.strip() for char in attribute
            )
            .strip()
            .title()
        )
        print("Total {}: {}".format(printableAttribute, len(values)))

    print("\n[*] Shutting Down...")
