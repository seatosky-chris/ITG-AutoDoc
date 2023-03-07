# ITG AutoDoc

This is a collection of scripts for IT Glue that provide automatic documentation. All of these scripts (not including helper scripts) can be scheduled to run daily or weekly to keep the documentation up-to-date.

Note: Some of these scripts include a number of images that are used in the *At a Glance* section. These are hosted on a server that does not allow hotlinking. If you wish to use these you will need to re-host them.

### AD Groups
This script will document Active Directory Security Groups. It must be ran from the customer's AD server. For this to work they must be using a local Active Directory server. It will not work with Azure AD. If they have a large amount of AD Groups it can take a very long time to run. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. For each security group it will create a new asset. It will do its best to categorize the group and it will tag any parent/child groups as well as member users. The script will take care of adding all AD groups as well as keeping them updated. It will try to add all of the data it can but if necessary, you can manually edit things like the group type, group description, folder details, who to add (only manual), approver for access (only manual), and the group details. For the sync to work, the GUID must be correct in the ITG asset. If you do not want it to add new groups, you can change `$UpdateOnly` to `$true`. This script uses a dictionary which you must unzip from the `DictionaryAlphabetJSON.zip` file.

### Active Directory
This script will document the Active Directory setup. It must be ran from the customer's AD server. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It will get as much data as it can about the AD configuration and update the asset with this info. Values include: AD Full name, short name, level, AD servers, a forest and site summary, domain controllers, password requirements, domain admins, and user count. The script will overwrite any existing data.

### Bluebeam Licensing
This script will update existing Bluebeam license details by using the Bluebeam registration lookup website. It will query the site based on the existing serial and product keys. You must add an asset with this info to ITG first for it to keep the asset up-to-date. This script can be ran from any device. To set it up you must fill in the IT Glue API key, endpoint url, the customers ITG organization ID, and the ITG base url. Additionally, you must setup the primary email used for Bluebeam licensing (and optionally any other emails that may have been used). Optionally, you can also include an Application ID to auto-tag the licenses to the Bluebeam app, and a Overview Document ID, to keep a summary of Bluebeam licenses. The script will keep the license details up-to-date including: renewal date, seats available (total the license can have), seats free, seats used, and a list of devices that are using that license. It will tag those devices to the license as related items. If setup, it will also update a license overview that contains a table of all the Bluebeam licenses and how many free seats are available. 

### Datto Backups (BCDR)
This script will create and update a Backup asset for each Datto BCDR in your partner portal. This does not need to be setup on a customer server and can be ran from anywhere. This can be setup with a global ITG api key and a Datto Backups API key and be ran for all customers in one go. It will run through each BCDR's organization and try to match them to an ITG organization, if it cannot, you will be prompted to make a match manually. It will then get the BCDR's info and the protected devices from the API, update the Backup asset in ITG, and tag the protected devices to the Backup asset. You can get your Datto API key by logging into the Datto Backup Portal then navigating to Admin > Integrations. Enable the REST API and use the Public and Secret key's generated.

Note that this script cannot update the Local Retention Period or the IPMI IP address, those still need to be documented manually.

If you are running this from the Task Scheduler, be sure to set the Action's "Start In" value to the location that the script is running from. This is required for relative path references for the forms and json matching file.

### File Shares
This script can update Windows file shares in ITG. It must be setup on every server you want to document the shares on. There are 2 versions of this script:
1. If the customer has a single server, use the `File Shares.ps1` script. This will document the file shares on that server and pull AD GPO info.
2. If the customer has multiple servers, use the `File Shares - File Server.ps1` script on each of the file servers, and then the `File Shares - AD Server.ps1` script on the AD server. The File Server script will document all of the file shares on each file server and then the AD Server script will update each with AD GPO info. If the AD server has file shares on it, you will want to run a copy of each script on it. Note that the AD server needs to have read-access to the UNC path of each file share that is being documented.
 
To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It updates/creates all file shares in ITG with their associated permissions. It will tag AD security groups if using the `File Shares.ps1` or `File Shares - AD Server.ps1` script.

### Hyper-V
This script will document the Hyper-V setup on a server. It must be ran from the Hyper-V server itself. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It will get as much data as it can about the Hyper-V configuration and update the asset with this info. Values include: host name, host device, a table of all the VM's with their state, settings & resources, a table of network settings including switches, network adapters & replication settings, and a table of host settings. This script will overwrite any existing data. Additionally, it can update a Virtualizations/Cluster asset which contains an overview of the Hyper-V setup. For this to work, the title of the corresponding Virtualization's page must contain the name of that Hyper-V host or the name of the Cluster.

### Licensing Overview
This script will create a license overview that contains a table of all the licenses of a certain type including how many free seats are available. This same overview is built in to the Bluebeam Licensing script. This script can be ran from any device. To set it up you must fill in the IT Glue API key, endpoint url, the customers ITG organization ID, and the ITG base url. Additionally configure the `$LicenseNames` array to include the names of all licenses you want in this overview and a unique `$OverviewDocumentName` name. To create multiple overviews for different license types, create multiple instances of this script. 

### Meraki Licensing
This script will create and update a Licensing asset for that companies Meraki equipment. This does not need to be setup on a customer server and can be ran from anywhere. This can be setup with a global ITG api key and global Meraki API key and be ran for all customers in one go. It will run through each Meraki organization and try to match them to an ITG organization, if it cannot, you will be prompted to make a match manually. It will then get the license info and devices from Meraki, update the license asset in ITG, and tag the Meraki devices to the license asset.

If you are running this from the Task Scheduler, be sure to set the Action's "Start In" value to the location that the script is running from. This is required for relative path references for the forms and json matching file.

### Sophos Firewall Licensing
This script will create and update Firewall assets for Sophos Firewalls in the Sophos portal. This does not need to be setup on a customer server and can be ran from anywhere. This can be setup with a global ITG api key and global Sophos API key and be ran for all customers in one go. It will run through each Sophos organization and try to match them to an ITG organization, if it cannot, you will be prompted to make a match manually. It will then get the firewall info from Sophos, update/create the firewall asset in ITG, and tag the ITG configuration if it exists (on new firewall creations it will create the configuration).

If you are running this from the Task Scheduler, be sure to set the Action's "Start In" value to the location that the script is running from. This is required for relative path references for the forms and json matching file.

### O365 Groups
This script will document Email Groups in O365. It will add/update Microsoft 365 Groups, Distribution Lists, Mail-enabled Security groups, regular Security groups, and Shared Mailboxes. It requires unattended access to O365 with an SSL certificate, the same setup the User Audit script has. If they have a large amount of Email Groups it can take a long time to run. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. Additionally, the O365 unattended login details are required. For each email group it will create a new asset. It will categorize the group and it will tag all owners and members. The script will take care of adding all new groups as well as keeping them updated. It will try to add all of the data it can but if necessary, you can manually edit things like the group description, configuration details, who to add (only manual), approver for access, etc. For the sync to work, the ObjectID must be correct in the ITG asset. If you do not want it to add new groups, you can change `$UpdateOnly` to `$true`.

### Security Summary
This script will document a portion of the Security Summary page. This script should be ran from a companies main AD server, if possible. It will attempt to get the currently running Anti-Virus (on the device this script is running on), this does not work properly on servers though and will be offloaded to the Device Audit which can get this information from RMM. It will query ITG to get the type of Firewall being used and update the Firewall Manufacturer info. Lastly, if this script is ran on an AD server, it will get the Password Complexity information and will update that.

### Warranties
This script will update warranty information for devices in Autotask & ITG. It pulls all of the devices from Autotask and runs through each, using the serial number to get the Warranty. If a device does not have a serial number set, it will not be able to get warranty info for it.

This script is setup to be ran on Autotask and then changes will sync through to IT Glue, but it would be fairly easy to modify this to update IT Glue directly.

It will only work for devices from the following Manufacturers: Dell, Lenovo, Microsoft, & Toshiba. It can estimate warranty info for Apple devices but as this won't always be accurate, this has been disabled. HP devices may be a possibility in the future but their API is not working and a new one has been "coming soon" for quite some time. Warranty info will be updated in Autotask and then syncs through to IT Glue.

Additionally the script will set the "Warranty Start Date" and "Warranty Product Name" fields in Autotask. These do not sync through to IT Glue.

This is a modified version of Kelvin Tegelaar's [PowerShellWarrantyReports](https://github.com/KelvinTegelaar/PowerShellWarrantyReports) PowerShell module. It uses a modified version of the Autotask Warranty update procedure that can also update warranty start date and product name, and can be ran on only devices missing warranty info. This is useful because the Autotask API is quite slow and a full update takes a long time to run.

### Quick Delete Duplicate Groups
This is a simple helper script for mass deleting duplicate AD groups as there were a few issues with duplicates when creating the AD Groups autodoc script. This is not an Autodoc script and should not be scheduled. 