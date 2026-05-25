# NOTE: in pycryptox_exceptions it is forbidden to import
# modules, create functions, create global variables,
# or anything else outside of the child classes of
# PycryptoxError for the cleanliness of pycryptox.

# Classes (And that's all):
class PycryptoxError(Exception):
    ...

class VersionNotFoundError(PycryptoxError):
    def __init__(self, version_name="Unknown"):
        message = f"The version '{version_name}' being sought could not be found"
        super().__init__(message)

class ArgumentTypeError(PycryptoxError):
    def __init__(self, argument_name="Unknown", argument_type="Unknown"):
        message = f"The variable type '{argument_type}' used for the value of the argument '{argument_name}' is invalid"
        super().__init__(message)

class DecryptionError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error during decryption because '{reason}'"
        super().__init__(message)

class EncryptionError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error during encryption because '{reason}'"
        super().__init__(message)

class StegaError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error during stega because '{reason}'"
        super().__init__(message)

class UnstegaError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error during unstega because '{reason}'"
        super().__init__(message)

class KeyxError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error with Keyx because '{reason}'"
        super().__init__(message)
 
class KeyNameError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Error with key name because '{reason}'"
        super().__init__(message)

class WrongPasswordError(PycryptoxError):
    def __init__(self, reason="Unknown reason"):
        message = f"Wrong password because '{reason}'"
        super().__init__(message)

class DowngradeError(PycryptoxError):
    def __init__(self, old_version="Unknown", new_version="Unknown"):
        message = f"Refused to downgrade from v{old_version} to v{new_version}; pass downgrade=True to force"
        super().__init__(message)