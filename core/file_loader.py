import os 

class FileLoader:
    """ Responsible for safely loading files and reading them as bytes."""

    def __init__(self):
        self.file_path = None;
        self.file_data = None;

    def load_file(self, file_path: str) -> bytes:
        """
        Load a file from disk and return its content as bytes .
        :param file_path: path to the file
        :return :File acontent in bytes
        :raises: Exception if file is invalid or cannot be read
        """

        #check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        #check if it is a file(not a folder)
        if not os.path.isfile(file_path):
            raise ValueError("The selected path is not a file")
        
        #optional:limit file size (50MB)

        max_size = 50 * 1024 * 1024 #50MB
        file_size = os.path.getsize(file_path)

        if file_size > max_size:
            raise ValueError("File is too large (max 50Mb allowed)")
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # save internally
            self.file_path = file_path
            self.file_data = data

            return data
        except Exception as e:
            raise Exception(f"Error reading file:{str(e)}")
    def get_file_info(self) -> dict:
        """
        REturn basic information about the loaded file
        """

        if self.file_path is None:
            return {}
        
        return {
            "file_name": os.path.basename(self.file_path),
            "file_size": os.path.getsize(self.file_path),
            "file_path": self.file_path
        }
    def clear(self):
        """
        Reset loaded file data
        """
        self.file_path = None
        self.file_data = None