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
- **Pull Requests**: When opening a pull request, make sure to assign at least a reviewer so that all the code being merged has been validated by more than one person. When merging the pull request, make sure to **squash** all **commits** **before merging**.