import json
from OpenSSL import SSL, crypto, _util

class CSR(object):
    def __init__(self, csr_json):
        csr_dict = json.loads(csr_json)
        self.common_name = csr_dict['CSR']['CommonName']
        self.country_name = csr_dict['CSR']['CountryName']
        self.state_or_province_name = csr_dict['CSR']['StateOrProvinceName']
        self.locality_name = csr_dict['CSR']['LocalityName']
        self.organization_name = csr_dict['CSR']['OrganizationName']
        self.organizational_unit_name = csr_dict['CSR']['OrganizationalUnitName']
        self.private_key = None
        self.public_key = None
        self.csr = None

    def generate_csr(self):
        req = crypto.X509Req()
        req.get_subject().CN = self.common_name
        req.get_subject().countryName = self.country_name
        req.get_subject().stateOrProvinceName = self.state_or_province_name
        req.get_subject().localityName = self.locality_name
        req.get_subject().organizationName = self.organization_name
        req.get_subject().organizationalUnitName = self.organizational_unit_name

        key = self._generate_private_key()

        req.set_pubkey(key)
        req.sign(key, "sha1")

        self.csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        self.private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        self.public_key = self._extract_public_key(key)


    def _extract_public_key(self, pkey):
        bio = crypto._new_mem_buf()
        _util.lib.PEM_write_bio_PUBKEY(bio, pkey._pkey)
        return crypto._bio_to_string(bio)

    def _generate_private_key(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        return key







csr_json = '{ "CSR": { "CommonName": "test", "CountryName": "US", "StateOrProvinceName": "NY", "LocalityName": "local", "OrganizationName": "testcorp", "OrganizationalUnitName": "testOU"} }'

csr_obj = CSR(csr_json)

csr_obj.generate_csr()
print(csr_obj.csr)
print(csr_obj.public_key)
print(csr_obj.private_key)
