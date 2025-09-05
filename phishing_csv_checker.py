import pandas as pd
import re

# Phishing detection logic
def is_phishing_url(url):
    """
    Detect if a URL is phishing or safe.
    """
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):  # Check if IP is in URL
        return 'Phishing'
    if len(url) > 75:  # Check if URL length is too long
        return 'Phishing'
    if "https" not in url[:5]:  # Check if HTTPS is missing
        return 'Phishing'
    return 'Safe'

# Read the CSV file
input_csv = "C:\Users\kirup\Desktop\2024\kp\phishinglinks.csv"  # Replace with the actual file path or name
output_csv = "classified_urls.csv"  # Output file to save results

# Load the CSV into a DataFrame
data = pd.read_csv(input_csv)

# Check if a 'URL' column exists
if 'URL' not in data.columns:
    raise ValueError("The CSV file must have a 'URL' column.")

# Apply the phishing detection logic to each URL
data['Result'] = data['URL'].apply(is_phishing_url)

# Save the results to a new CSV file
data.to_csv(output_csv, index=False)

print(f"Phishing detection completed. Results saved to {output_csv}.")
