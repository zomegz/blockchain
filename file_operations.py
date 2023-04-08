import os
import shutil

def create_file(filename, content):
    try:
        with open(filename, 'w') as f:
            f.write(content)
        return f"File {filename} created successfully."
    except Exception as e:
        return f"Failed to create file {filename}. Error: {str(e)}"

def read_file(filename):
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"File {filename} content: {content}"
    except Exception as e:
        return f"Failed to read file {filename}. Error: {str(e)}"

def update_file(filename, content):
    try:
        with open(filename, 'w') as f:
            f.write(content)
        return f"File {filename} updated successfully."
    except Exception as e:
        return f"Failed to update file {filename}. Error: {str(e)}"

def delete_file(filename):
    try:
        os.remove(filename)
        return f"File {filename} deleted successfully."
    except Exception as e:
        return f"Failed to delete file {filename}. Error: {str(e)}"

def create_directory(directory_path):
    try:
        os.makedirs(directory_path)
        return f"Directory {directory_path} created successfully."
    except Exception as e:
        return f"Failed to create directory {directory_path}. Error: {str(e)}"

def list_directory(directory_path):
    try:
        contents = os.listdir(directory_path)
        return f"Contents of {directory_path}: {', '.join(contents)}"
    except Exception as e:
        return f"Failed to list contents of {directory_path}. Error: {str(e)}"

def delete_directory(directory_path):
    try:
        shutil.rmtree(directory_path)
        return f"Directory {directory_path} deleted successfully."
    except Exception as e:
        return f"Failed to delete directory {directory_path}. Error: {str(e)}"

