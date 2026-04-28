from core.file_loader import FileLoader

loader = FileLoader()

try:
    data = loader.load_file("hello.exe") 
    print("file laoded successfully!")
    print(f"File size: {len(data)} bytes")

    info = loader.get_file_info()
    print("file info:", info)

except Exception as e:
    print("Error:",e)