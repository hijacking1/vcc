import os
import requests
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_fixed
import base64

links = "sub.txt"

with open(links, "r", encoding="utf-8") as file:
    try:
        links = [line.strip() for line in file]
    except Exception as e:
        print(f"{e} \n")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))

def get(url,session, i):
    try:
        res = session.get(url, timeout=30)
        res.raise_for_status()
        os.makedirs("source", exist_ok=True)
        output = f"source/{i}.txt"
        with open(output, "w", encoding="utf-8") as file:
            res_str = res.text
            if (is_base64(res_str)):
                file.write(decode_base64(res_str))
            else:
                file.write(res_str)
    except Exception as e:
        print(e)

session = requests.Session()

def get_source():
    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            for i, url in enumerate(links, start=1):
                if url != "":
                    #print(f"URL : {url}")
                    executor.submit(get, url, session, i)
        except Exception as e:
            print(e)

def decode_base64(s: str) -> str:
    decoded = ""
    try:
        padding = 4 - len(s) % 4
        if padding != 4:
            padded_data = s + "=" * padding
        else:
            padded_data = s
        decoded = base64.urlsafe_b64decode(padded_data).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decode get_source -> decode_base64: {str(e)}")
    return decoded
    
def is_base64(s: str) -> bool:
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False
    
if __name__ == "__main__":
    get_source()
