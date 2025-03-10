import sqlite3
import sys
import argparse

def execute_query(database_path, query):
    try:
        # Establish connection to the database
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()
        
        # Execute the query
        cursor.execute(query)
        
        # If it's a SELECT query, fetch and print results
        if query.strip().upper().startswith('SELECT') or query.strip().upper().startswith('PRAGMA'):
            results = cursor.fetchall()
            if results:
                # Print column names if available
                column_names = [description[0] for description in cursor.description]
                print("Columns:", column_names)
                
                # Print each row
                for row in results:
                    print(row)
            else:
                print("No results returned.")
        else:
            # For non-SELECT queries, commit changes
            conn.commit()
            print(f"Query executed successfully. Rows affected: {cursor.rowcount}")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        if 'conn' in locals():
            conn.close()
            print("Database connection closed.")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Execute a SQLite query on a specified database')
    parser.add_argument('database', help='Path to the SQLite database file')
    parser.add_argument('query', help='SQL query to execute')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute the query
    execute_query(args.database, args.query)

if __name__ == "__main__":
    # Check if arguments are provided
    if len(sys.argv) < 3:
        print("Error: Please provide database path and query as arguments")
        print("Usage: python script.py database.db \"SELECT * FROM table_name\"")
        sys.exit(1)
    
    main()
