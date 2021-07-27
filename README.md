# ITG AutoDoc

This is a collection of scripts for IT Glue that provide automatic documentation. All of these scripts (not including helper scripts) can be scheduled to run daily or weekly to keep the documentation up-to-date.

### AD Groups
This script will document Active Directory Security Groups. It must be ran from the customer's AD server. If they have a large amount of AD Groups it can take a very long time to run. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. For each security group it will create a new asset. It will do its best to categorize the group and it will tag any parent/child groups as well as member users. If you do not want it to add new groups, you can change `$UpdateOnly` to `$true`. This script uses a dictionary which you must unzip from the `DictionaryAlphabetJSON.zip` file.

### Active Directory
This script will document the Active Directory setup. It must be ran from the customer's AD server. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It will get as much data as it can about the AD configuration and update the asset with this info. Values include: AD Full name, short name, level, AD servers, a forest and site summary, domain controllers, password requirements, domain admins, and user count. The script will overwrite any existing data.

### Bluebeam Licensing
This script will update existing Bluebeam license details by using the Bluebeam registration lookup website. It will query the site based on the existing serial and product keys. You must add an asset with this info to ITG first for it to keep the asset up-to-date. This script can be ran from any device. To set it up you must fill in the IT Glue API key, endpoint url, the customers ITG organization ID, and the ITG base url. Additionally, you must setup the primary email used for Bluebeam licensing (and optionally any other emails that may have been used). Optionally, you can also include an Application ID to auto-tag the licenses to the Bluebeam app, and a Overview Document ID, to keep a summary of Bluebeam licenses. The script will keep the license details up-to-date including: renewal date, seats available (total the license can have), seats free, seats used, and a list of devices that are using that license. It will tag those devices to the license as related items. If setup, it will also update a license overview that contains a table of all the Bluebeam licenses and how many free seats are available. 

### File Shares
A WIP, this script can update file shares in ITG. It must be ran from the server where the file shares are. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It updates/creates all file shares in ITG with their associated permissions. It will tag AD security groups where possible.

### Hyper-V
This script will document the Hyper-V setup on a server. It must be ran from the Hyper-V server itself. To set it up you must fill in the IT Glue API key, endpoint url, and the customers ITG organization ID. It will get as much data as it can about the Hyper-V configuration and update the asset with this info. Values include: host name, host device, a table of all the VM's with their state, settings & resources, a table of network settings including switches, network adapters & replication settings, and a table of host settings. This script will overwrite any existing data. 

### Licensing Overview
This script will create a license overview that contains a table of all the licenses of a certain type including how many free seats are available. This same overview is built in to the Bluebeam Licensing script. This script can be ran from any device. To set it up you must fill in the IT Glue API key, endpoint url, the customers ITG organization ID, and the ITG base url. Additionally configure the `$LicenseNames` array to include the names of all licenses you want in this overview and a unique `$OverviewDocumentName` name. To create multiple overviews for different license types, create multiple instances of this script. 

### Quick Delete Duplicate Groups
This is a simple helper script for mass deleting duplicate AD groups as there were a few issues with duplicates when creating the AD Groups autodoc script. This is not an Autodoc script and should not be scheduled. 