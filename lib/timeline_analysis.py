import pandas as pd
from datetime import datetime

def detect_frequent_executions(timeline_data, time_threshold=pd.Timedelta(minutes=5), min_group_size=7):
    """
    Detect executables running too frequently within a short period of time.

    Args:
        timeline_data (pd.DataFrame): The timeline data with 'ExecutableName' and 'RunTime'.
        time_threshold (pd.Timedelta): The maximum allowed time difference between executions.
        min_group_size (int): The minimum number of executions required to form a group.

    Returns:
        dict: A dictionary containing frequent executions grouped by executable.
    """
    # Convert the 'RunTime' column to datetime format
    timeline_data['RunTime'] = pd.to_datetime(timeline_data['RunTime'])

    # Sort the data by 'ExecutableName' and 'RunTime'
    timeline_data = timeline_data.sort_values(by=['ExecutableName', 'RunTime'])

    # Dictionary to store frequent executions
    frequent_executions = {}

    # Iterate through the timeline data and calculate time differences
    for executable, group in timeline_data.groupby('ExecutableName'):
        if len(group) < min_group_size:  # Skip if total entries are less than min group size
            continue

        # Calculate time differences between consecutive runs
        time_diffs = group['RunTime'].diff().shift(-1)

        # Find runs with time differences below the threshold
        frequent_runs = time_diffs[time_diffs < time_threshold]

        if not frequent_runs.empty:
            # Group consecutive frequent runs
            groups = []
            current_group = []
            for i in range(len(group) - 1):  # Iterate up to the second-to-last element
                if time_diffs.iloc[i] < time_threshold:
                    if not current_group:
                        current_group.append(group['RunTime'].iloc[i])
                    current_group.append(group['RunTime'].iloc[i + 1])
                else:
                    if len(current_group) >= min_group_size:
                        groups.append(current_group)
                    current_group = []

            # Add the last group if it exists and has enough entries
            if len(current_group) >= min_group_size:
                groups.append(current_group)

            if groups:  # Only add to frequent_executions if we found valid groups
                frequent_executions[executable] = {
                    'count': sum(len(g) for g in groups),
                    'groups': groups
                }

    return frequent_executions


def print_frequent_executions(frequent_executions):
    """
    Print the results of frequent executions.

    Args:
        frequent_executions (dict): A dictionary containing frequent executions grouped by executable.
    """
    if frequent_executions:
        print("Executables running too frequently (minimum 7 executions per group):")
        for executable, data in frequent_executions.items():
            print(f"\nExecutable: {executable}")
            print(f"Total number of frequent runs: {data['count']}")
            print("Groups of frequent executions:")
            for group_idx, times in enumerate(data['groups'], 1):
                print(f"\nGroup {group_idx} ({len(times)} executions):")
                for i in range(len(times)):
                    if i == 0:
                        print(f"  - {times[i]}: (first execution in group)")
                    else:
                        time_diff = times[i] - times[i - 1]
                        print(f"  - {times[i]}: {time_diff}")
    else:
        print("No executables found with groups of 7 or more frequent executions.")


def main():
    # Load the timeline data from the CSV file
    try:
        timeline_data = pd.read_csv("../Triage/PECmd_Output_Timeline.csv")
    except FileNotFoundError:
        print("Error: The file 'PECmd_Output_Timeline.csv' was not found.")
        return
    except pd.errors.EmptyDataError:
        print("Error: The file 'PECmd_Output_Timeline.csv' is empty.")
        return

    # Define thresholds
    time_threshold = pd.Timedelta(minutes=5)
    min_group_size = 7  # Minimum number of executions required for a group

    # Detect frequent executions
    frequent_executions = detect_frequent_executions(timeline_data, time_threshold, min_group_size)

    # Print the results
    print_frequent_executions(frequent_executions)


if __name__ == "__main__":
    main()