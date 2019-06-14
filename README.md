# Update All vTM Certificates

This script will update the Services Director Service SSL Certificate for 
a fleet of vTMs. 

# Pulse Secure Services Director

Pulse Secure Services Director is the management tool for Pulse Secure 
Virtual Traffic Manager (vTM), an advanced Application Delivery Controller.

See the [Pulse Secure vADC landing page](https://www.pulsesecure.net/vadc) 
for more details on the products and their capabilities.

This script requires Services Director version 19.1 or higher

# Install
Pulse Secure supports this script on Ubuntu 18.04 running python 3.

### First install pip3 and virtualenv
```
sudo apt install python3-pip
sudo apt install virtualenv
```

#### Then setup and use a virtualenv
```
virtualenv --no-site-packages VIRTUAL
source VIRTUAL/bin/activate
```

### Install the required packages to the virtualenv
```
pip3 install -r requirements.txt
```

# Run the tests
```
# From the directory update_all_vtm_certificates run
python3 -m unittest discover
```

# Run the script

##### First put the new service SSL certificate onto all of the vTMs
```
python3 update_all_vtm_certificates.py --new-sd-service-certificate new_cert.pem
--current-sd-service-certificate current_sd_cert.cert --sd-url https://10.62.168.200:8100
--sd-username admin --sd-password noop --new-private-key new_key.pem
```
##### Then update your SD Service SSL Certificate through the GUI

##### Then clear the current (now old) SD Service SSL Certificate from your vTMs
```
python3 update_all_vtm_certificates.py --new-sd-service-certificate new_cert.pem
--current-sd-service-certificate current_sd_cert.cert --sd-url https://10.62.168.200:8100
--sd-username admin --sd-password noop --new-private-key new_key.pem --remove-old-certificates
```

# Questions

If you have a Pulse Secure Services Director license with support entitlement, 
please contact the Pulse Secure support team with any questions.

# Further Information

Please see the knowledge base for 
detailed instructions on how to use this script

License
===
The files in this repository are licensed under the terms of 
[Apache License 2.0](./LICENSE). See the LICENSE file for details.
