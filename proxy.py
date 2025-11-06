import requests
import time

while True:
    time.sleep(2)
    try:
        test_url = "http://pubproxy.com/api/proxy?level=elite"
        response = requests.get(test_url, timeout=5)
        proxy = response.json().get("data")[0].get("ipPort") 
        protocol = ['http','https','socks4','socks5']
        for p in protocol:
            prox = {p:f"{p}://{proxy}"}
            try:
                req = requests.get('https://google.com',proxies=prox,timeout=4)
                if req.status_code == 200:
                    print(f"Working proxies: {prox[p]}")
                    with open("proxy.txt", "a") as f:
                        f.write(prox[p]+ "\n")
            except:
                pass
    except:
        print("No proxy available.")
        break