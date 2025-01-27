Check Activation Status
=======================

A robust Windows Powershell script to display the licensing status of Microsoft Windows and Office.

Supported products
------------------

- Windows Vista and later / Windows Server 2008 and later.
- Office 2010 and later (MSI or C2R), installed on Windows XP and later.
- Office UWP apps on Windows 10/11.
- Windows and Office KMS Host (CSVLK), installed on Windows Server 2003 and later.

Features
--------

- Require Windows Powershell 2.0 at minimum
- Practical replacement for **slmgr.vbs** functions `/dli` `/dlv` `xpr`
- Shows the activation expiration date for supported products
- Shows the `ProductKeyChannel` for Windows Vista / 7 / 8 primary installed key (available for uplevel Windows by default)
- Shows the status of add-on licenses (Extended Security Updates, APPXLOB, OCUR..., etc)
- Shows the status of Automatic VM Activation for Windows Server 2012 and later
- Shows the status of Subscription Activation for Windows 11 24H2 and later
- Implement **vNextDiag.ps1** functions to detect Office vNext licenses (subscription or lifetime)
- Implement <a href="https://github.com/asdcorp/clic" target="_blank">Client Licensing Check</a> tool for Windows 8 and later

Unsupported
-----------

Status of Token-based or Active Directory (AD) Volume Licensing.

Parameters
----------

|Switch |Effect|
|-------|------|
| -IID  | Show Offline Installation ID |
| -Dlv  | Show IID, Rearm count, Trusted time, Product ID.. if available |
| -All  | Show status for all IDs, regardless installed keys |
| -Pass | Skip end prompt or clearing window buffer with All switch |

License
-------
The project is licensed under the terms of the MIT License.
