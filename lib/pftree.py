import pandas as pd
from datetime import datetime

# Load the PECmd output
pecmd_df = pd.read_csv('PECmd_Output.csv')

# Load the Timeline data
timeline_df = pd.read_csv('PECmd_Output_Timeline.csv', sep='\t', header=None, names=['Time', 'Path'])

# Filter for executables of interest
executables_of_interest = ['word.exe', 'cmd.exe']
filtered_df = pecmd_df[pecmd_df['ExecutableName'].isin(executables_of_interest)]


# Function to check if powershell.exe is in FilesLoaded and correlate times
def check_powershell_execution(row, timeline_df):
    if 'powershell.exe' in row['FilesLoaded']:
        # Get the LastRun time of the executable
        last_run_time = datetime.strptime(row['LastRun'], '%Y-%m-%d %H:%M:%S')

        # Get the execution time of powershell.exe from the timeline
        powershell_times = timeline_df[timeline_df['Path'].str.contains('powershell.exe', case=False, na=False)]

        for _, powershell_row in powershell_times.iterrows():
            powershell_time = datetime.strptime(powershell_row['Time'], '%Y-%m-%d %H:%M:%S')

            # Calculate the time delta
            time_delta = abs((last_run_time - powershell_time).total_seconds())

            # If the time delta is small (e.g., less than 10 seconds), print the details
            if time_delta < 10:
                print(f"Executable: {row['ExecutableName']}")
                print(f"LastRun: {last_run_time}")
                print(f"PowerShell Execution Time: {powershell_time}")
                print(f"Time Delta: {time_delta} seconds")
                print("---")


# Apply the function to each row in the filtered dataframe
filtered_df.apply(lambda row: check_powershell_execution(row, timeline_df), axis=1)