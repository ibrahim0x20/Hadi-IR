import pandas as pd
import sqlite3
from pathlib import Path
import sys
import chardet

def detect_file_encoding(file_path):
    """Detect the encoding of a file using chardet"""
    with open(file_path, 'rb') as file:
        raw_data = file.read()
        result = chardet.detect(raw_data)
        return result['encoding']

def create_signature_db():
    try:
        # Detect file encoding
        file_path = 'signed.csv'
        encoding = detect_file_encoding(file_path)
        print(f"Detected file encoding: {encoding}")

        # Read CSV file with detected encoding
        df = pd.read_csv(file_path, encoding=encoding, on_bad_lines='warn')
        
        # Clean the data
        # Replace any problematic characters in string columns
        string_columns = df.select_dtypes(include=['object']).columns
        for col in string_columns:
            df[col] = df[col].astype(str).apply(lambda x: x.encode('ascii', 'replace').decode('ascii'))
        
        # Create SQLite connection
        conn = sqlite3.connect('signature.db')
        
        # Create table with MD5 as primary key
        create_table_sql = '''
        CREATE TABLE IF NOT EXISTS signed (
            MD5 TEXT PRIMARY KEY,
            Path TEXT,
            Verified TEXT,
            Date TEXT,
            Publisher TEXT,
            Company TEXT,
            Description TEXT,
            Product TEXT,
            Product_Version TEXT,
            File_Version TEXT,
            Machine_Type TEXT,
            SHA1 TEXT,
            PESHA1 TEXT,
            PESHA256 TEXT,
            SHA256 TEXT,
            IMP TEXT
        )
        '''
        
        conn.execute(create_table_sql)
        
        # Write the dataframe to SQLite
        # If a record with the same MD5 exists, it will be replaced
        df.to_sql('signed', conn, if_exists='replace', index=False)
        
        # Create index on commonly searched fields
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sha1 ON signed(SHA1)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sha256 ON signed(SHA256)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_path ON signed(Path)')
        
        # Print some statistics
        cursor = conn.cursor()
        row_count = cursor.execute('SELECT COUNT(*) FROM signed').fetchone()[0]
        print(f"Successfully imported {row_count} records to signature.db")
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
    except FileNotFoundError:
        print("Error: signed.csv file not found")
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print("Error: The CSV file is empty")
        sys.exit(1)
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Try running the script with explicit encoding:")
        print("python script.py -e cp1252")  # Common Windows encoding
        sys.exit(1)

if __name__ == "__main__":
    create_signature_db()