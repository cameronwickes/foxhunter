import argparse
import ctypes
import fnmatch
import logging
import sys
import os
import json
import sqlite3
import ctypes
from base64 import b64decode


class Addon:
    def __init__(
        self,
        name,
        version,
        URL,
        downloads,
        screenshots,
        rating,
    ):
        self.name = name
        self.version = version
        self.URL = URL
        self.downloads = downloads
        self.screenshots = screenshots
        self.rating = rating

    def getName(self):
        return self.getName

    def getVersion(self):
        return self.getVersion

    def getURL(self):
        return self.URL

    def getDownloads(self):
        return self.downloads

    def getScreenshots(self):
        return self.screenshots

    def getRating(self):
        return self.rating


class Extension:
    def __init__(
        self,
        name,
        URL,
        permissions,
    ):
        self.name = name
        self.URL = URL
        self.permissions = permissions

    def getName(self):
        return self.getName

    def getURL(self):
        return self.URL

    def getPermissions(self):
        return self.permissions


class Certificate:
    def __init__(
        self,
        authority,
        cert,
    ):
        self.authority = authority
        self.cert = cert

    def getAuthority(self):
        return self.authority()

    def getCert(self):
        return self.cert


class Cookie:
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
        return self.host

    def getName(self):
        return self.name

    def getValue(self):
        return self.value

    def getExpiry(self):
        return self.expiry

    def getLastAccessed(self):
        return self.lastAccessed

    def getCreationTime(self):
        return self.getCreationTime

    def getSecure(self):
        return self.secure

    def getHTTPOnly(self):
        return self.httpOnly

    def getSameSite(self):
        return self.sameSite


class FormField:
    def __init__(
        self,
        name,
        value,
        useCount,
    ):
        self.name = name
        self.value = value
        self.useCount = useCount

    def getName(self):
        return self.name

    def getValue(self):
        return self.value

    def getUseCount(self):
        return self.useCount


class HistorySearch:
    def __init__(
        self,
        query,
        useFrequency,
    ):
        self.query = query
        self.useFrequency = useFrequency

    def getQuery(self):
        return self.query

    def getUseFrequency(self):
        return self.useFrequency


class LoginDecrypter:
    class SECItem(ctypes.Structure):
        """
        Structure Representing SECItem Type for NSS Decoding
        """

        _fields_ = [
            ("type", ctypes.c_uint),
            ("data", ctypes.c_char_p),
            ("len", ctypes.c_uint),
        ]

    class PK11SlotInfo(ctypes.Structure):
        """
        Structure Representing a PKCS Slot
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

    def getDecryptionStatus(self):
        return self.decryptionAvailable

    # Set the input/output types for NSS functions.
    def setCTypes(self, name, returnType, *inputTypes):
        result = getattr(self.NSS, name)
        result.restype = returnType
        result.argtypes = inputTypes
        setattr(self, name, result)

    # Find and load LibNSS from the system.
    def loadLibNSS(self):
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
            try:
                nss: ctypes.CDLL = ctypes.CDLL(nssPath)
            except OSError:
                continue
            else:
                self.NSS = nss
        if self.NSS == None:
            logging.error("[!] Couldn't find NSS Library on System. Exiting...")
            self.decryptionAvailable = False

    def decode(self, base64Data):
        if self.decryptionAvailable:
            # Base64 decode the password.
            decodedData = b64decode(base64Data)
            encryptedData = self.SECItem(0, decodedData, len(decodedData))
            decryptedData = self.SECItem(0, None, 0)

            errorCode = self.PK11SDR_Decrypt(encryptedData, decryptedData, None)
            try:
                if errorCode == -1:
                    logging.error(
                        "[!] Password decryption failed. Passwords protected by a Master Password!"
                    )

                finalData = ctypes.string_at(
                    decryptedData.data, decryptedData.len
                ).decode("utf-8")
            finally:
                # Free the decryption object.
                self.SECITEM_ZfreeItem(decryptedData, 0)

            return finalData
        else:
            return "N/A"


class LoginData:
    def __init__(self, profile):
        self.logins = []
        self.profile = profile

        # Create the NSS decrypter.
        self.decrypter = LoginDecrypter()
        self.decryptionAvailable = self.decrypter.getDecryptionStatus()

    def getDecryptionStatus(self):
        return self.decryptionAvailable

    def addLogin(self, login):
        self.logins.append(login)

    def getLogins(self):
        return self.logins

    def initialiseProfile(self):
        # UTF-8 encode the firefox profile folder in case of foreign characters.
        profile = self.profile.encode("utf-8")

        # Initialise NSS with the profile.
        errorCode = self.decrypter.NSS_Init(b"sql:" + profile)

        # Check for error on initialisation.
        if errorCode != 0:
            logging.error("[!] NSS Profile Failure.")
            self.decryptionAvailable = False

    def attemptBlankAuthentication(self):
        # Get a keyslot from the decrypter and call the CheckUserPassword function with a blank password.
        keySlot = self.decrypter.PK11_GetInternalKeySlot()
        errorCode = self.decrypter.PK11_CheckUserPassword(keySlot, "".encode("utf-8"))

        # Check the result of authentication and return as necessary.
        if errorCode != 0:
            logging.info("[*] Blank Password Authentication Failed...")
            self.decrypter.PK11_FreeSlot(keySlot)
            return False
        else:
            logging.info("[*] Blank Password Authentication Succeeded...")
            self.decrypter.PK11_FreeSlot(keySlot)
            return True

    def attemptPasswordAuthentication(self, password):
        # Get a keyslot from the decrypter and call the CheckUserPassword function with a blank password.
        keySlot = self.decrypter.PK11_GetInternalKeySlot()
        errorCode = self.decrypter.PK11_CheckUserPassword(
            keySlot, password.encode("utf-8")
        )

        # Check the result of authentication and return as necessary.
        if errorCode != 0:
            logging.info("[*] Password Authentication Failed...")
            self.decrypter.PK11_FreeSlot(keySlot)
            return False
        else:
            logging.info("[*] Password Authentication Succeeded!")
            self.decrypter.PK11_FreeSlot(keySlot)
            return True

    def attemptBruteForceAuthentication(self, wordlist):
        with open(wordlist) as wordlistFile:
            for line in wordlistFile:
                guess = line.rstrip()
                if guess == "" or guess[0] == "#":
                    continue

                keySlot = self.decrypter.PK11_GetInternalKeySlot()
                errorCode = self.decrypter.PK11_CheckUserPassword(
                    keySlot, guess.encode("utf-8")
                )
                if errorCode == 0:
                    logging.info(
                        '[*] Brute Force Authentication Succeeded With Password "{}"!'.format(
                            guess
                        )
                    )
                    return guess
        return False

    def authenticate(self, correctPassword):
        keySlot = self.decrypter.PK11_GetInternalKeySlot()

        if not keySlot:
            logging.error("[!] Couldn't retrieve keyslot.")

        errorCode = self.decrypter.PK11_CheckUserPassword(
            keySlot, correctPassword.encode("utf-8")
        )

        self.decrypter.PK11_FreeSlot(keySlot)

    def decryptLogins(self):
        for login in self.logins:
            username = self.decrypter.decode(login.getEncryptedUsername())
            password = self.decrypter.decode(login.getEncryptedPassword())
            login.setUsername(username)
            login.setPassword(password)

    def deactivateProfile(self):
        errorCode = self.decrypter.NSS_Shutdown()


class Login:
    def __init__(self, host, encryptedUsername, encryptedPassword):
        self.host = host
        self.encryptedUsername = encryptedUsername
        self.encryptedPassword = encryptedPassword

        self.username = "N/A"
        self.password = "N/A"

    def getHost(self):
        return self.host

    def getEncryptedUsername(self):
        return self.encryptedUsername

    def getEncryptedPassword(self):
        return self.encryptedPassword

    def getUsername(self):
        return self.username

    def getPassword(self):
        return self.password

    def setUsername(self, username):
        self.username = username

    def setPassword(self, password):
        self.password = password


def directoryPath(dir):
    if os.path.isdir(dir):
        return dir
    else:
        logging.error("[!] No such directory {}\n".format(dir))
        sys.exit(1)


def chooseFirefoxProfileDirectory():
    firefoxProfiles = []

    logging.debug("[*] No Directory Specified - Finding Firefox Profiles...\n")
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
    return displayFirefoxProfiles(firefoxProfiles)


def displayFirefoxProfiles(firefoxProfiles):
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


def fileExists(filePath):
    if os.path.exists(filePath):
        return True
    else:
        return False


def findAddons(addonsPath):
    addonList = []

    # Check for presence of addons.json in profile folder. Return if not found.
    if not fileExists(addonsPath):
        logging.debug("[!] Could not find addons.json in profile. Skipping...")
        return addonList

    logging.debug("[*] Extracting Addons from addons.json...")

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
    return addonList


def findExtensions(extensionsPath):
    extensionList = []

    # Check for presence of extensions.json in profile folder. Return if not found.
    if not fileExists(extensionsPath):
        logging.debug("[!] Could not find extensions.json in profile. Skipping...")
        return extensionList

    logging.debug("[*] Extracting Addons from extensions.json...")

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

    # Return list of addon objects.
    return extensionList


def findCertificates(certificatesPath):
    certificatesList = []

    # Check for presence of certs9.db in profile folder. Return if not found.
    if not fileExists(certificatesPath):
        logging.debug("[!] Could not find cert9.db in profile. Skipping...")
        return certificatesList

    logging.debug("[*] Extracting Certificates from cert9.db...")

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
    return certificatesList


def findCookies(cookiesPath):
    cookiesList = []

    # Check for presence of cookies.sqlite in profile folder. Return if not found.
    if not fileExists(cookiesPath):
        logging.debug("[!] Could not find cookies.sqlite in profile. Skipping...")
        return cookiesList

    logging.debug("[*] Extracting Cookies from cookies.sqlite...")

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
                secure=extractedCookie[7],
                httpOnly=extractedCookie[8],
                sameSite=extractedCookie[9],
            )
            cookiesList.append(cookieObject)

    # Exit when database is locked.
    except:
        logging.error(
            "\n[!] Database is Locked. Make Sure Firefox is Closed and Try Again."
        )
        sys.exit(1)

    # Return the list of cookie objects.
    return cookiesList


def findFormHistory(formHistoryPath):
    formHistoryList = []

    # Check for presence of certs9.db in profile folder. Return if not found.
    if not fileExists(formHistoryPath):
        logging.debug("[!] Could not find formhistory.sqlite in profile. Skipping...")
        return formHistoryList

    logging.debug("[*] Extracting Autocomplete Form History from formhistory.sqlite...")

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

    # Return the list of certificate objects.
    return formHistoryList


def findHistorySearches(historySearchPath):
    historySearchList = []

    # Check for presence of places.sqlite in profile folder. Return if not found.
    if not fileExists(historySearchPath):
        logging.debug("[!] Could not find places.sqlite in profile. Skipping...")
        return historySearchList

    logging.debug("[*] Extracting History Searches from places.sqlite...")

    try:
        # Create connection to database and create cursor.
        databaseConnection = sqlite3.connect(historySearchPath)
        databaseCursor = databaseConnection.cursor()

        # Extract the form field history from the moz_formhistory table.
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
    return historySearchList


def findLoginData(loginPath, keyPath):
    loginList = []
    decryptionSkip = False

    # Check for presence of logins.json in profile folder. Return if not found.
    if not fileExists(loginPath):
        logging.debug("[!] Could not find logins.json in profile. Skipping...")
        return loginList

    # Check for presence of key4.db in profile folder. Skip Decryption if not found.
    if not fileExists(keyPath):
        logging.debug("[!] Could not find key4.db in profile. Skipping Decryption...")
        decryptionSkip = True

    logging.debug("[*] Extracting Login Data from logins.json...")

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

    # If decryption step not skipped, attempt decrypt of passwords.
    if not decryptionSkip:

        # Attempt decryption using no password.
        if loginData.attemptBlankAuthentication():
            # Decrypt using blank password.
            loginData.authenticate("")
            loginData.decryptLogins()
            loginData.deactivateProfile()
            return loginData.getLogins()

        else:
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

                if selectedOption == "1":
                    password = input(
                        "\n[+] Please Enter the Master Password to Decrypt Usernames & Passwords: "
                    )
                    if loginData.attemptPasswordAuthentication(password):
                        loginData.authenticate(password)
                        loginData.decryptLogins()
                        loginData.deactivateProfile()
                        return loginData.getLogins()
                    else:
                        logging.error("[!] Wrong Master Password.")

                elif selectedOption == "2":
                    dictionary = input("\n[+] Please Enter the Path to the Wordlist: ")
                    if os.path.exists(dictionary):
                        logging.info(
                            "[*] Attempting to Brute Force (This May Take a While...)"
                        )
                        bruteForceAttempt = loginData.attemptBruteForceAuthentication(
                            dictionary
                        )
                        if bruteForceAttempt != False:
                            loginData.authenticate(bruteForceAttempt)
                            loginData.decryptLogins()
                            loginData.deactivateProfile()
                            return loginData.getLogins()
                        else:
                            logging.error(
                                "[!] Master Password Not Found in Dictionary."
                            )
                    else:
                        logging.error(
                            "[!] No Such File or Directory {}".format(dictionary)
                        )


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
           G@@@@@@@@@@@@@@@@@@@@@@@P GJ:        7#     :^#@@@@&            
          5@@@@@@@@@@@@@@@@@@@@@G!.  &.          &.    ~@&@@@@@7           
         ^@@@@@@@@@@@@@@@@@@@@#      YG         55     .@@@@@@@B^          
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
        "-d",
        "--directory",
        type=directoryPath,
        help="directory of firefox profile to seek artifacts",
        required=False,
    )

    # Parse the arguments.
    arguments = parser.parse_args()

    # If quiet flag is not set, allow DEBUG levels and above through, and force handlers to change.
    if arguments.quiet == False:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s", force=True)

    # If no profile directory specified, search the system for them, and let the user choose.
    if arguments.directory == None:
        arguments.directory = chooseFirefoxProfileDirectory()

    logging.debug("\n[*] Searching Selected Profile Directory for Artifacts...")

    # Search for addons within selected firefox profile (addons.json)
    addons = findAddons(arguments.directory + "/addons.json")

    # Search for extensions within selected firefox profile (extensions.json).
    extensions = findExtensions(arguments.directory + "/extensions.json")

    # Search for certificates within selected firefox profile (cert9.db)
    certificates = findCertificates(arguments.directory + "/cert9.db")

    # Search for cookies within selected firefox profile (cookies.sqlite)
    cookies = findCookies(arguments.directory + "/cookies.sqlite")

    # Search for web form data within selected firefox profile (formhistory.sqlite)
    formHistory = findFormHistory(arguments.directory + "/formhistory.sqlite")

    # Search for browsing history within selected firefox profile (places.sqlite)

    # Search for history searches within selected firefox profile (places.sqlite)
    historySearches = findHistorySearches(arguments.directory + "/places.sqlite")

    # Search for downloads within selected firefox profile. (places.sqlite)

    # Search for bookmarks within selected firefox profile. (places.sqlite/bookmarkbackups)

    # Search for logins and passwords within selected firefox profile (logins.json/key4.db)
    logins = findLoginData(
        arguments.directory + "/logins.json",
        arguments.directory + "/key4.db",
    )

    print("[*] Shutting Down...")


# TODO: Bookmark Functionality
# TODO: History Functionality
# TODO: Downloads Functionality
# TODO: Comment + Cleanup Code
# TODO: DocStrings
# TODO: Sort out Debug/Info
# TODO: Sort out Menu Formatting
# TODO: Relative Paths & Check File vs Directory
# TODO: Other QOL Improvements
# TODO: Dump Directory + Output to CSV, JSON
# TODO: Analysis Mode