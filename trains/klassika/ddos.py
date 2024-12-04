import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the URL for the registration endpoint
url = "http://172.30.13.15:4242/register"

# Function to send a registration request
def register_user(i):
    # Define the payload with username and password
    payload = {
        "username": "asd" * 1000 + str(i),  # Username
        "password": "asd" * 1000 + str(i)   # Password
    }

    # Send a POST request
    response = requests.post(url, data=payload)

    # Return the status code and response text
    return response.status_code, response.text

# Number of users to register
num_users = 10000

# Using ThreadPoolExecutor to manage threads
with ThreadPoolExecutor(max_workers=20) as executor:
    # Create a list to hold future results
    futures = {executor.submit(register_user, i): i for i in range(num_users)}

    for future in as_completed(futures):
        user_id = futures[future]
        try:
            status_code, response_text = future.result()
            if status_code == 302:
                print(f"User  {user_id}: Redirected to:", response_text)
            elif status_code == 200:
                print(f"User  {user_id}: Registration successful:", response_text)
            else:
                print(f"User  {user_id}: Failed to register. Status code:", status_code)
                print(f"User  {user_id}: Response text:", response_text)
        except Exception as e:
            print(f"User  {user_id}: Exception occurred: {e}")