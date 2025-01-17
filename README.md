# PowerShell Credential Manager
PowerShell Module to Read and Write Credentials from the Windows Credential Manager

## Ongoing Development and Support
This is a fork of the original CredentialManager module by Dave Garnar and has been made Powershell Core compatible (but is also backwards compatible with older Powershell versions and uses the same cmdlet names/parameters as the original module).

## Installation
### PowerShell Gallery Installation
The module is available on the PowerShell Gallery: https://www.powershellgallery.com/packages/TUN.CredentialManager.

1. PS> Save-Module -Name TUN.CredentialManager -Path <path>
2. PS> Install-Module -Name TUN.CredentialManager

### Manual Installation

1. Dowload the latest verion of the module code from https://github.com/echalone/PowerShell_Credential_Manager/releases
2. Unzip TUN.CredentialManager.zip and copy the contents to you preferred module path. Usually C:\Users\UserName\Documents\WindowsPowerShell\Modules.
3. In your PowerShell session run the command Import-Module TUN.CredentialManager

## Usage

Import the module in to your PowerShell session and full help is available in the module with Get-Help.

### New with version 3.0
* Use New-StoredCredential with SecurePassword (of type secure string) or Credentials (of type PSCredential) parameter to use only secure string internally
* Use Get-StoredCredential with ExcludeClearPassword and IncludeSecurePassword switches to exclude the clear password being stored (even in memory) and to only retrieve and store the password as a secure string (including secure passwords may lengthen execution time)
* Excluding the clear password and only working with secure password/secure string will also set the PasswordSize to 0
* Passwords up to 1280 unicode characters (2560 bytes) are now supported (up from 256 unicode characters)
* Notice: A breaking change with version 3.0 to previous versions is that New-StoredCredential will no longer return the clear password in the property Password of the returned object if you used the Credentials or SecurePassword parameters instead of the clear string Password parameter (if you really need the clear password you can always retrieve it with the Get-StoredProcedure default call afterwards, or just remember it beforehand)

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

### v3.0
- Extended possible password length to 1280 unicode characters (2560 bytes)
- Rewriting internal code to work mainly with secure strings if possible
- Expanded stored credential object with property SecurePassword to store password as secure string
- Expanded Get-StoredCredential with switches IncludeSecurePassword and ExcludeClearPassword
- Returning only clear password in New-StoredCredential if clear Password parameter was provided, but not if secure string SecurePassword parameter or PSCredential Credentials parameter was provided (in this case, only return secure string password in SecurePassword)
- Extended UnitTests with new test cases
- Better error messages if credentials to remove weren't found or if password in provided credentials object was too long

### v2.1
- Explicit naming of cmdlets to export in psd1 for Powershell Core compatibility
- Rewriting of some internal code to make it compatible with Powershell Core
- Expanded copyright notices and counted up version number
- Renamed module from CredentialManager to TUN.CredentialManager

### v2.0
- Implemented pipeline support for Get-StoredCredential.
- Implemented pipeline support for New-StoredCredential.
- Implemented pipeline support for Remove-StoredCredential.
- Improved error handling to respect the Error Action Preference in PowerShell.
- Changed AsPSCredential to a Switch parameter and renamed to AsCredentialObject on Get-StoredCredential to make it easier to use.
- Added Credentials parameter to New-StoredCredential which accepts a PSCredential object instead of User name and Password.
- Added SecuserPassword parameter to New-StoredCredential which accepts a SecureString as the password.
- Credential object now returns LastWritten as a DateTime instead of a ComType.FILETIME
- Changing license to MIT from GPL
- General refactoring and bug fixes. 

### v1.1 Bug Fix
Fixed a bug where the username specified in the -UserName parameter was not being used to create the credential in the store. The username for the logged on user was being used instead. Issue logged https://github.com/davotronic5000/PowerShell_Credential_Manager/issues/8


### v1.0 Initial Release
Implementing basic functionality
- Get-StoredCredential - Gets one or more credentials from the Windows Credential Manager.
- New-Stored Credential - Adds a new credential to the Windows Credential Manager.
- Remove-StoredCredential - Deletes a credential from the Windows Credential Manager.
- Get-StrongPassword - Randomly generates a new password.

## Credits

Written by Dave Garnar (@davotronic5000)
http://blog.davotronic5000.co.uk

Edited by Markus Szumovski (echalone)
https://github.com/echalone

## License


This software is licensed under the [The MIT License (MIT)](http://opensource.org/licenses/MIT).

	Copyright (C) 2016 Dave Garnar and 2022 Markus Szumovski

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
