import csv

def save_results(results, output_file="reports/results.csv"):

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "classification"])

        for host, classification in results:
            writer.writerow([host, classification])
