# pyWinAD
python wrapper for [automated AD join API](https://github.com/gjbsaiia/easyJoinAPI) for Windows VMs

## WinADClient() class
All methods for this lib run out of this class. The __init__ contructor takes three, optional, arguments:
* **creds**: The API credential you want all subsequent methods to run with. defaults to an unauthorized credential that the API doesn't recognize.
* **base_url**: The domain name for the API. Default doesn't need adjusted.
* **role**: Whether you're managing the VM from within the VM - 'internal', or you're managing the VM externally - 'external'. Defaults to 'External'.

### WinADClient Methods:

* **__post**: Takes arguments `func` = which php page (api service) you're requesting, `data` = the arguments the api call requires (must be in json payload format).</br>
Takes arguments, and makes request through python request library.

* **isExternal**: Simply returns boolean `True` if this instance is configured for external.

* **setAuth**: Takes argument `cred` = **encrypted** API credential.</br>
Updates the credential in `Authorization` header.

* **setDomain**: Takes argument `domain_name` = the domain name of your machine.</br>
Sets the domain_name stored in self.domain_name. Nothing on the machine itself is changed by this.

* **joinMachine**: Takes argument `ad_domain` = desired Active Directory domain</br>
Builds and sends API join request - will join and restart the machine through API. **Note:** domain name needs to satisfy naming convention. New names are set through `setDomain(<name>)`.

* **logToDns**: Takes argument `domain` = the domain name, `raw_addy` = the IP address you want associated with domain, `dnsCred` = temp API credential (defaults to `None`).</br>
Requests API to create a DNS record associated the given domain name to the given ip. The DNS logging API request requires a special DNS API credential, or an Admin API credential. If you set `dnsCred`, that credential is **only** used for the DNS logging API request. This method does not currently work. Waiting for Engineer to flesh this out.

* **setAPICred**: Takes argument `creds` = bare api credential.</br>
Encrypts credential, stores it in self.token, and then updates the `Authorization` header.

* **buildPayload**: Takes argument `data` = parameters needed for request in a dictionary.</br>
Structures request data into a format that the API can interpret.

* **recoverEncKey**: Removes encoding on globally stored encryption key. This method should really pull the key from Vault instead when Progressive gets Enterprise Vault. This would also allow for cool functionality where you can cycle encryption keys periodically by having this library and the API simply pull a Vault variable each time they encrypt/decrypt.

* **encrypt**: Takes parameter `bare_key` = bare API credentials.</br>
Encrypts API credentials using a key shared between this library and the API. Only authorized credentials that are encrypted with this common key and method can use the API - no bare keys are accepted.

#### Methods only able to be used by WinADClient - External

* **addAPICredential**: Takes argument `new_creds` = unauthorized, bare, API credential.</br>
Requests API to authorize a new API credential. You must be using an admin API credential for this to run.

* **changeEncryptionKey**: Takes argument `key` = base string to generate new key with (defaults to `None`).</br>
Unsupported until Progressive gets Vault. But it would generate a new encryption key, and update the vault variable. If `key` is unset, generates a random 30 char string as a seed.

#### Methods only able to be used by WinADClient - Internal

* **genDomain**: Generates new domain name using the machine's IP address. Follows this convention:</br>
Example ip: 10.0.0.1</br>
Generated domain: '10-0-0-1-us-e1'

* **runDomain**: Takes parameter `old_domain` = current domain set on the VM, `new_domain` = desired domain for the VM (defaults to self.domain_name). </br>
Runs powershell locally to set the machine name. This method will restart the machine.

* **updateMetadata**: Updates OpenStack metadata for instance to tag it's domain name and that it's a Windows OS.

* **changeDomain**: Takes optional parameter `dnsCred` = temporary API credential to be used for logToDns call.</br>
Magic method that handles all internal management. Ensures that methods are called in the right order so that runDomain is executed last, so reboot does not make the process kill itself.
