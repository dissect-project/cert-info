"""
The File Manager is repsonsible for managing the files that are
used in the retrieval and validation of the certificate chain.
"""

import os

class FileManager:
    """
    File Manager class that provids methods for creating and deleting
    files and directories.
    """

    @staticmethod
    def create_dir(dirname: str) -> None:
        """
        Create a directory.

        Args:
            directory (str): The directory to be created.
        
        Returns:
            None
        """
        # Try to create the directory
        try:
            os.makedirs(dirname)
        except FileExistsError:
            # Pass if the directory already exists
            pass

    @staticmethod
    def remove_dir(dirname: str) -> None:
        """
        Remove a directory.

        Args:
            directory (str): The directory to be removed.
        
        Returns:
            None
        """
        # Try to remove the directory
        try:
            os.rmdir(dirname)
        except FileNotFoundError:
            # Pass if the directory does not exist
            pass

    @staticmethod
    def remove_files(dirname: str) -> None:
        """
        Remove files in a given directory.

        Args:
            dirname (str): The directory to be cleaned.
        
        Returns:
            None
        """
        # Try to remove the files
        try:
            for file in os.listdir(dirname):
                os.remove(os.path.join(dirname, file))
        except FileNotFoundError:
            # Pass if the directory does not exist
            pass

    @staticmethod
    def write_to_file(filename: str, content: str) -> None:
        """
        Write the specified content to the given file.

        Args:
            filename (str): The file to write to.
            content (str): The content to write.
        
        Returns:
            None
        """
        # Check if the object is binary or text and open the file in the appropriate mode
        mode = 'wb' if isinstance(content, bytes) else 'w'
        # Try to write to the file
        try:
            with open(filename, mode) as file:
                file.write(content)
        except FileNotFoundError:
            # Pass if the file does not exist
            pass
