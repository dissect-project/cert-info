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

Contributions are more than welcome and they are what makes the community great! Feel free to open issues, suggest features, or submit pull requests. However, in order to maintain some order, the following set of conventions should be used:

- **Branches**: To contribute, please create a new branch locally using the structure `tag/name`, where `tag` consists of a descriptive tag of the contribution, and `name` consists in the name of the branch. Do not commit directly to the `main` branch. Some of the possible tags include:
    - **new**: new functionalities
    - **docs**: documentation
    - **enhancement**: enhancing some part of the code
    - **refactor**: major changes in the code, namely in the code structure
    - **bugfix**: fixing some bug in the code

- **Commits**: When adding commits to your branch, use descriptive commit messages, following the format:
    ```bash
    git commit -m "tag: brief commit description
    
    Here you can place a more detailed description of what is included in
    the commit, making sure to not exceed 72 characters per line. The tag 
    used above should be the same as the one used in the branch, and the
    brief commit description should be self-explanatory."
    ```

- **Testing**: To test the code, execute the `python -m unittest` command in the root of the repository. Make sure all tests pass successfully. To test using `pylint`, run `pylint src` at the root of the project and make sure the score is above `9.0`.

- **Pull Requests**: When opening a pull request, make sure to assign at least a reviewer so that all the code being merged has been validated by more than one person. When merging the pull request, make sure to **squash** all **commits** **before merging**.

## Documentation

Full documentation for `cert-info` can be accessed [here](). (TBD)

## Authors

- [Diogo Ribeiro](https://github.com/ribeiropdiogo)
- [João Marco Silva](https://github.com/jotamarco)

## License

cert-info is licensed using [GNU v3](/LICENSE)

