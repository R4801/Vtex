import re
import pandas as pd
import requests
import json
import time,sys,hashlib

df=pd.read_excel('ioc.xlsx')

df = df.astype({
    "status": "string",
    "raw": "string",
    "flagged": "Int64",
    "type" : "string"
})
# writing type of ioc --------------------------------------------------->
def set_type(ioc):
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")  # Matches MD5/SHA1/SHA256
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"  # simple domain check (google.com, sub.example.org)
    )
    
    if ip_pattern.match(ioc):
        return "IP Address"
    elif hash_pattern.match(ioc):
        return "Hash"

    else:
        if ioc.startswith("http://") or ioc.startswith("https://"):
            return "URL"
        elif domain_pattern.match(ioc):
            return "URL"
        else:
            # Fallback if none matched
            return "Unknown"

df.loc[pd.isna(df['type']), 'type'] = df.loc[pd.isna(df['type']), 'ioc'].apply(set_type)
df.to_excel('ioc.xlsx', index=False) 
#-------------------------------------------------------------------<



#fetch intel----------------------------------------------->

#Virustotal params -->

apis=['your api here', 'and another one', 'and more']
api_index=0

def get_headers():
    return {
        "accept": "application/json",
        "x-apikey": apis[api_index]
    }

VT_IP= "https://www.virustotal.com/api/v3/ip_addresses/"
VT_File= "https://www.virustotal.com/api/v3/files/"
VT_URL= "https://www.virustotal.com/api/v3/urls/"

#---->

def intelfetch(ioc, ioc_type):
    global api_index

    if ioc_type == "IP Address":
        endpoint = VT_IP + ioc
    elif ioc_type == "Hash":
        endpoint = VT_File + ioc
    elif ioc_type == "URL":
        endpoint = VT_URL + hashlib.sha256(ioc.encode()).hexdigest() #base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    elif ioc_type == "Unknown":
        return "Unknown Type"
    else:
        return "Invalid Type"
    
    # --- Attempt control ---
    attempts = 0
    max_attempts = 4 * len(apis)  # 4 full cycles

    while attempts < max_attempts:
        try:
            response = requests.get(endpoint, headers=get_headers())

            if response.status_code == 200:
                print(endpoint)
                data = response.json()
                malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                raw_response = json.dumps(data)
                status = "Malicious" if malicious_count > 0 else "Clean"

                return malicious_count, raw_response, status

            elif response.status_code == 429:  # Rate limit
                print(f'API key {api_index} exhausted, switching...')
                api_index = (api_index + 1) % len(apis)
                attempts += 1

                # After first cycle → wait 10s before retrying
                if attempts == len(apis):
                    print('All keys used once, waiting 10s before second cycle...')
                    time.sleep(10)

                continue

            else:  # Any other HTTP error
                api_index = (api_index + 1) % len(apis)
                attempts += 1
                return pd.NA, f"Error {response.status_code} - {response.reason}", f"Retry-After: {response.headers.get('Retry-After')}"

        except Exception as e:
            return pd.NA, f"Exception: {e}", f"Exception: {e}"

    # --- If we reach here, all keys failed after 2 cycles ---
    print("All API keys exhausted after 2 cycles. Stopping program.")
    sys.exit(1)  # terminate program



batch_size = 10
count = 0  # counter for batch

mask = pd.isna(df['flagged']) | pd.isna(df['raw']) | pd.isna(df['status'])

for idx, row in df.loc[mask].iterrows():
    flagged, raw, status = intelfetch(row['ioc'], row['type'])
    df.at[idx, 'flagged'] = flagged
    df.at[idx, 'raw'] = raw
    df.at[idx, 'status'] = status

    count += 1
    if count % batch_size == 0:
        # Write intermediate results to Excel
        df.to_excel("ioc.xlsx", index=False)
        print(f"Saved {count} rows so far...")


# Write the last batch if it didn't hit the batch_size multiple
if count % batch_size != 0:
    df.to_excel("ioc.xlsx", index=False)
    print(f"Saved final {count % batch_size} rows")