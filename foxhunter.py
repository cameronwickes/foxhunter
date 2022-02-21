# Import Required Libraries
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
from base64 import b64decode
from urllib import parse
import lz4.block as lz4
from datetime import datetime
import xml.etree.cElementTree as ET


class Addon:
    """
    Stores data relating to a Firefox addon.
    """

    def __init__(
        self,
        name,
        version,
        URL,
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
        self.downloads = downloads
        self.screenshots = screenshots
        self.rating = rating

    def getName(self):
        """Returns the name attribute of the addon."""
        return self.getName

    def getVersion(self):
        """Returns the version attribute of the addon."""
        return self.getVersion

    def getURL(self):
        """Returns the URL attribute of the addon."""
        return self.URL

    def getDownloads(self):
        """Returns the downloads attribute of the addon."""
        return self.downloads

    def getScreenshots(self):
        """Returns the screenshots attribute of the addon."""
        return self.screenshots

    def getRating(self):
        """Returns the rating attribute of the addon."""
        return self.rating


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

    def getName(self):
        """Returns the name attribute of the extension."""
        return self.getName

    def getURL(self):
        """Returns the URL attribute of the extension."""
        return self.URL

    def getPermissions(self):
        """Returns the permissions attribute of the extension."""
        return self.permissions


class Certificate:
    """
    Stores data relating to a trusted imported X509 certificate.
    """

    def __init__(
        self,
        authority,
        cert,
    ):
        """
        Parameters
        ----------
        authority : str
        Nickname for the certificate.

        cert : bytes
        The certificate.
        """
        self.authority = authority
        self.cert = cert

    def getAuthority(self):
        """Returns the authority attribute of the certificate."""
        return self.authority()

    def getCert(self):
        """Returns the certificate attribute of the certificate."""
        return self.cert


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

    def getHost(self):
        """Returns the host attribute of the cookie."""
        return self.host

    def getName(self):
        """Returns the name attribute of the cookie."""
        return self.name

    def getValue(self):
        """Returns the value attribute of the cookie."""
        return self.value

    def getExpiry(self):
        """Returns the expiry attribute of the cookie."""
        return self.expiry

    def getLastAccessed(self):
        """Returns the lastAccessed attribute of the cookie."""
        return self.lastAccessed

    def getCreationTime(self):
        """Returns the creationTime attribute of the cookie."""
        return self.getCreationTime

    def getSecure(self):
        """Returns the secure attribute of the cookie."""
        return self.secure

    def getHTTPOnly(self):
        """Returns the httpOnly attribute of the cookie."""
        return self.httpOnly

    def getSameSite(self):
        """Returns the sameSite attribute of the cookie."""
        return self.sameSite


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

    def getName(self):
        """Returns the name attribute of the form history."""
        return self.name

    def getValue(self):
        """Returns the value attribute of the form history."""
        return self.value

    def getUseCount(self):
        """Returns the useCount attribute of the form history."""
        return self.useCount


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

    def getQuery(self):
        """Returns the query attribute of the history search."""
        return self.query

    def getUseFrequency(self):
        """Returns the useFrequency attribute of the history search."""
        return self.useFrequency


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

    def getDate(self):
        """Returns the date attribute of the download."""
        return self.date

    def getDownloadPath(self):
        """Returns the downloadPath attribute of the download."""
        return self.downloadPath

    def getURL(self):
        """Returns the URL attribute of the download."""
        return self.URL


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

    def getDate(self):
        """Returns the date attribute of the browsing history entry."""
        return self.date

    def getURL(self):
        """Returns the URL attribute of the browsing history entry."""
        return self.URL

    def getTitle(self):
        """Returns the title attribute of the browsing history entry."""
        return self.title

    def getVisitType(self):
        """Returns the visitType attribute of the browsing history entry."""
        return self.visitType

    def getVisitCount(self):
        """Returns the visitCount attribute of the browsing history entry."""
        return self.visitCount


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

    def getDateAdded(self):
        """Returns the dateAdded attribute of the bookmark."""
        return self.dateAdded

    def getURL(self):
        """Returns the URL attribute of the bookmark."""
        return self.URL

    def getTitle(self):
        """Returns the title attribute of the bookmark."""
        return self.title

    def getActive(self):
        """Returns the active attribute of the bookmark."""
        return self.active


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
        self.decryptionAvailable = True
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
        self.decryptionAvailable = status

    def getDecryptionStatus(self):
        """Returns the decryptionAvailable attribute of the LoginDecrypter."""
        return self.decryptionAvailable

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
            self.decryptionAvailable = False

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
        if self.decryptionAvailable:
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

    def addLogin(self, login):
        """Adds a specified login to the list of logins."""
        self.logins.append(login)

    def getLogins(self):
        """Returns all logins."""
        return self.logins

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
            # Fetch and decode the encrypted usernames and passwords from the login objects.
            username = self.decrypter.decode(login.getEncryptedUsername())
            password = self.decrypter.decode(login.getEncryptedPassword())
            # Set the decrypted usernames and passwords in the login objects.
            login.setUsername(username)
            login.setPassword(password)

    def deactivateProfile(self):
        """Deactivate the NSS profile and library once finished."""
        errorCode = self.decrypter.NSS_Shutdown()


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

    def getHost(self):
        """Returns the host attribute of the login object."""
        return self.host

    def getEncryptedUsername(self):
        """Returns the encryptedUsername attribute of the login object."""
        return self.encryptedUsername

    def getEncryptedPassword(self):
        """Returns the encryptedPassword attribute of the login object."""
        return self.encryptedPassword

    def getUsername(self):
        """Returns the username attribute of the login object."""
        return self.username

    def getPassword(self):
        """Returns the password attribute of the login object."""
        return self.password

    def setUsername(self, username):
        """Sets the decrypted username to the specified argument. Should be called from LoginData class only."""
        self.username = username

    def setPassword(self, password):
        """Sets the decrypted password to the specified argument. Should be called from LoginData class only."""
        self.password = password


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

    def findAvailable(self):
        """Returns the list of set attributes."""
        return self.available


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
        logging.error("[!] No such directory {}\n".format(dir))
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
    if os.path.exists(filePath):
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

    logging.debug("[*] No Profile Directory Specified - Finding Firefox Profiles...\n")
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
        for extractedCert in databaseCursor.execute("SELECT * FROM nssPublic"):
            try:
                # Filter out None's from tuples where no data is present in column.
                filteredCertificate = list(filter(None, list(extractedCert)))
                # Gather certificate nickname from extracted data.
                nickname = filteredCertificate[4].decode("utf-8")
                # print(filteredCertificate[5:])
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
    for bookmarkBackup in os.listdir(bookmarksFolder):
        with open(os.path.join(bookmarksFolder, bookmarkBackup), "rb") as backupMozFile:
            # Check that file is mozlz4 compressed.
            if backupMozFile.read(8) == b"mozLz40\0":
                # Gather root bootmark, and recursively find child bookmarks.
                rootBookmark = json.loads(lz4.decompress(backupMozFile.read()))
                childBookmarks = findBookmarkChildren(
                    rootBookmark, "text/x-moz-place", []
                )
                for childBookmark in childBookmarks:
                    # Check if bookmark has been deleted. Add it to the bookmarks list if it has.
                    if childBookmark["uri"] not in [x.getURL() for x in bookmarksList]:
                        bookmarkObject = Bookmark(
                            dateAdded=datetime.utcfromtimestamp(
                                float(childBookmark["dateAdded"] / 1000000)
                            ).strftime("%Y-%m-%d %H:%M:%S"),
                            URL=childBookmark["uri"],
                            title=childBookmark["title"],
                            active=False,
                        )
                        bookmarksList.append(bookmarkObject)

    # Return the list of bookmark objects.
    logging.debug("[^] Successfully Gathered Deleted Bookmarks From 'bookmarkbackups/'")
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
        loginData.addLogin(loginObject)

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
            return loginData.getLogins()

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
                        return loginData.getLogins()
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
                    if os.path.exists(dictionary):
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
                            return loginData.getLogins()

                    # Wordlist not found!
                    else:
                        logging.error(
                            "[!] No Such File or Directory {}".format(dictionary)
                        )
            return loginData.getLogins()


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
    # Check for lack of data to dump.
    if not foxHunter.findAvailable():
        logging.error("[!] No Data Gathered From FoxHunter.")
        sys.exit(1)

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

    logging.info("[^] Data Dump Complete!")


if __name__ == "__main__":

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

    # Parse the arguments.
    arguments = parser.parse_args()

    # If quiet flag is not set, allow DEBUG levels and above through, and force handlers to change.
    if arguments.quiet == False:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s", force=True)

    # Check for presence of at least one output argument.
    if (
        arguments.output_csv is None
        and arguments.output_json is None
        and arguments.output_xml is None
    ):
        parser.error(
            "one of the following arguments is required: -oC/--output-csv, -oJ/--output-json, -oX/--output-xml"
        )

    # If no profile directory specified, search the system for them, and let the user choose.
    if arguments.profile == None:
        arguments.profile = chooseFirefoxProfileDirectory()

    logging.debug("[*] Received Firefox Profile!")
    logging.debug("[*] Searching Selected Profile Directory for Artifacts...")

    logging.debug("\n\033[1m\033[4m[*] Extracting Addons and Extensions...\033[0m\n")

    # Search for addons within selected firefox profile (addons.json)
    addons = findAddons(arguments.profile + "/addons.json")

    # Search for extensions within selected firefox profile (extensions.json).
    extensions = findExtensions(arguments.profile + "/extensions.json")

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting Certificates, Cookies and Form History...\033[0m\n"
    )

    # Search for certificates within selected firefox profile (cert9.db)
    certificates = findCertificates(arguments.profile + "/cert9.db")

    # Search for cookies within selected firefox profile (cookies.sqlite)
    cookies = findCookies(arguments.profile + "/cookies.sqlite")

    # Search for web form data within selected firefox profile (formhistory.sqlite)
    formHistory = findFormHistory(arguments.profile + "/formhistory.sqlite")

    logging.debug("\n\033[1m\033[4m[*] Extracting History Items...\033[0m\n")

    # Search for history searches within selected firefox profile (places.sqlite)
    historySearches = findHistorySearches(arguments.profile + "/places.sqlite")

    # Search for downloads within selected firefox profile. (places.sqlite)
    downloadHistory = findDownloadHistory(arguments.profile + "/places.sqlite")

    # Search for browsing history within selected firefox profile (places.sqlite)
    browsingHistory = findBrowsingHistory(arguments.profile + "/places.sqlite")

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting Active and Deleted Bookmarks...\033[0m\n"
    )

    # Search for bookmarks within selected firefox profile. (places.sqlite/bookmarkbackups)
    bookmarks = findBookmarks(
        arguments.profile + "/places.sqlite", arguments.profile + "/bookmarkbackups"
    )

    logging.debug(
        "\n\033[1m\033[4m[*] Extracting and Decrypting Login Data...\033[0m\n"
    )

    # Search for logins and passwords within selected firefox profile (logins.json/key4.db)
    # Inspiration from https://gist.github.com/dhondta/2e4946f791e5860bdb588d452b5b1570#file-firefox_decrypt_modified-py
    logins = findLoginData(
        arguments.profile + "/logins.json",
        arguments.profile + "/key4.db",
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

    logging.debug("\n\033[1m\033[4m[*] Dumping Gathered Data...\033[0m\n")

    # Check the input arguments for correct formatting.
    if arguments.output_csv:
        dumpData(foxHunter, "csv", arguments.output_csv)
    elif arguments.output_json:
        dumpData(foxHunter, "json", arguments.output_json)
    elif arguments.output_xml:
        dumpData(foxHunter, "xml", arguments.output_xml)

    print("\n[*] Shutting Down...")

# Certificates
# Relative Paths & Check File vs Directory
# Analysis Mode
