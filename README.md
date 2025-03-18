# DISSECT: Certificate Analysis

The **Certificate Analysis** component is part of the **DISSECT** project, aimed at analyzing the certificate chain of a given domain. It is designed to validate each SSL/TLS certificate in the chain, ensuring they meet the best security practices and do not pose any unwanted risks. The analysis consists in verifying whether the certificate chain for a given domain is in order, which inlcudes checking for certificate expiry status, hostname mismatches, usage of insecure cryptographic signatures, blacklisted certificates, and other potential security issues.

## Overview

The certificate analysis component focuses on validating each certificate in a given chain. To do so, there are several aspects being considered. The following list contains some of the most important aspects being analyzed:

- **Certificate Validation**: Check if the SSL/TLS certificate is valid and properly issued.
- **Expiration Monitoring**: Identify certificates nearing expiration.
- **Chain of Trust Analysis**: Verify that the certificate is correctly signed by a trusted certificate authority (CA).
- **Revocation Status**: Check if a certificate has been revoked via OCSP or CRL.
- **Configuration Assessment**: Ensure secure key lengths, signature algorithms, and compliance with best practices.
- **Hostname Mismatch**: Verify wether certificates contain any hostname mismatch.

## Installation

This component consists of a python package that can be imported locally by other python programs. Therefore, having `python` and `pip` installed are the two main pre-requisites to build and run this component. For privacy reasons, the component will not be publicy accessible. With this in mind, `pip` will be used to **install the package locally**:

```bash
pip install -e /path/to/package
```

## Usage (To be Improved)

After installing the package using pip, it should be available to use as any other python package. To import the package use the following line in your program:

```python
from cert-info import analyze
```

After importing the package, it can be used as follows:

```python
result = analyze("www.domain.com")
```

## Output (To be Done)

The `cert-info` package performs an assessment on the certificate chain of a given domain. All of the results are returned in a single object, as shown in the example below:

```python
from cert-info import scan

# Perform the analysis
result = analyze("www.domain.com")

# Print the result
print(result)

# Example output
...

```

## Contributing

Contributions are more than welcome and they are what makes the community great! Feel free to open issues, suggest features, or submit pull requests. Please check out the [contributions guide](/docs/CONTRIBUTING.md) for more information on how to do so.

## Documentation

Full documentation for `cert-info` can be accessed [here](). (TBD)

## Authors

- [Diogo Ribeiro](https://github.com/ribeiropdiogo)
- [João Marco Silva](https://github.com/jotamarco)

## License

cert-info is licensed using [GNU v3](/LICENSE)

